#!/usr/bin/env python

import copy
import os
from lark import Lark, Tree, Transformer
import yaml
from netaddr import IPNetwork
from time import perf_counter
import logging
import arculusfireio.utils.yaml

# CheatSheet: https://github.com/lark-parser/lark/blob/master/docs/_static/lark_cheatsheet.pdf
# commons: https://github.com/lark-parser/lark/blob/master/lark/grammars/common.lark
# JSON parser example: https://github.com/lark-parser/lark/blob/master/docs/json_tutorial.md

logger = logging.getLogger("root")

def generate_rule():
    rule = {
        "action": "allow",
        "from": [],
        "to": [],
        "dports": [],
        "protocols": [],
        "direction": None,
        "line": 0
    }
    return rule


# for each rule found by transform_rules(), create a new
# firewall rule dict and fill it with all parsed values
def transform_rule(rule):
    new_rule = generate_rule()
    logger.debug("Transforming rules:{} into Python structure".format(rule.line))
    new_rule["line"] = rule.line
    for element in rule.children:
        if isinstance(element, Tree):
            if element.data == "source_host":
                new_rule["from"].append(element.children[0].value)
            elif element.data == "target_host":
                new_rule["to"].append(element.children[0].value)
            elif element.data == "destport":
                new_rule["dports"].append(element.children[0].value)
            elif element.data == "protocol":
                new_rule["protocols"].append(element.children[0].value)
    return new_rule


# traverse the rule tree (as returned by the Lark parser)
# and return a list of rule dictionaries
def transform_rules(rules):
    transformed_rules = []
    logger.debug("Traversing the parser tree")
    if rules.data == "rules":
        logger.debug("Found 'rules' parent object")
        for rule in rules.children:
            if rule.data == "rule":
                transformed_rules.append(transform_rule(rule))
    return transformed_rules


# generic helper to read plaintext file back as string
def read_plaintext(name):
    logging.debug("Reading plaintext file '{}'".format(name))
    with open(name, "r") as reader:
        data = reader.read()
    return data


# helper to write out firewall rules as YAML file
def write_rules(firewall, rules_local, rules_forwarding, path):
    if not os.path.exists("{}/rules".format(path)):
        os.makedirs("{}/rules".format(path))
    with open("{}/rules/{}.yml".format(path, firewall["name"]), "w") as file:
        data = {
            "firewall": firewall,
            "rules_local": rules_local,
            "rules_forwarding": rules_forwarding
        }
        yaml.dump(data, file)


# recursively resolves nested definitions (`include` parameter)
# TODO: will cause an endless recursion if two definitions
#       include each other
def resolve_definition(term, definitions):
    for definition in definitions["net-objects"]:
        data = []
        if definition["name"] == term:
            if "include" in definition:
                logging.debug("Recursing into nested definition '{}' in '{}'".format(definition["include"], term))
                data = data + resolve_definition(definition["include"], definitions)
            data = data + definition["nets"]
            return data
    raise Exception("Could not resolve definition '{}'".format(term))


# check all rules for definitions (e.g. "mycorp-networks") and
# replace with the data from definitions.yml
def replace_definitions(rules, definitions):
    for rule in rules:
        nets = []
        for src in rule["from"]:
            nets = nets + resolve_definition(src, definitions)
        rule["from"] = nets
        nets = []
        for dst in rule["to"]:
            nets = nets + resolve_definition(dst, definitions)
        rule["to"] = nets
    return rules


def any_ip_affects_local_firewall(local_ips, ips):
    for ip in ips:
        for local_ip in local_ips:
            if not ip == "0.0.0.0/0" and IPNetwork(local_ip) in IPNetwork(ip):
                return True
    return False


def any_ip_affects_forwarding_firewall(firewall, ips):
    for ip in ips:
        check = ip_affects_forwarding_firewall(firewall, ip)
        if check:
            return True
    return False


def ip_affects_forwarding_firewall(firewall, ip):
    for int in firewall["forwarding_interfaces"]:
        for net in int["nets"]:
            if IPNetwork(ip) in IPNetwork(net):
                logging.debug("{}: {} is part of/equal to {}".format(firewall["name"], ip, net))
                return True
            else:
                logging.debug("{}: {} is NOT part of/equal to {}".format(firewall["name"], ip, net))
    return False


def strip_foreign_ips(firewall, rule, direction):
    if direction == "in":
        net_count_before = len(rule["to"])
        rule["to"][:] = [net for net in rule["to"] if ip_affects_forwarding_firewall(firewall, net)]
        net_count_after = len(rule["to"])
    elif direction == "out":
        net_count_before = len(rule["from"])
        rule["from"][:] = [net for net in rule["from"] if ip_affects_forwarding_firewall(firewall, net)]
        net_count_after = len(rule["from"])
    logging.debug("{}: Found {} and removed {} non-local IPs/networks from rule".format(firewall["name"], net_count_before, net_count_before - net_count_after))


def get_local_rules(firewall, rules):
    rules_local = []
    local_ips = []
    for int in firewall["local_interfaces"]:
        for net in int["nets"]:
            local_ips.append(net)

    for rule in rules:
        logger.debug("")
        logger.debug("{}/local: CHECKING NEXT RULE IN LIST".format(firewall["name"]))
        logger.debug(rule)
        if any_ip_affects_local_firewall(local_ips, rule["from"]):
            logger.debug("{}/local: Rule matches OUTBOUND direction".format(firewall["name"]))
            accepted_rule = copy.deepcopy(rule)
            accepted_rule["direction"] = "out"
            accepted_rule["from"] = local_ips
            rules_local.append(accepted_rule)
            continue
        elif any_ip_affects_local_firewall(local_ips, rule["to"]):
            logger.debug("{}/local: Rule matches INBOUND direction".format(firewall["name"]))
            accepted_rule = copy.deepcopy(rule)
            accepted_rule["direction"] = "in"
            accepted_rule["to"] = local_ips
            rules_local.append(accepted_rule)
            continue

    return rules_local


def get_forwarding_rules(firewall, rules):
    if firewall["type"] != "forward":
        return []

    forwarding_nets = []
    for int in firewall["forwarding_interfaces"]:
        for net in int["nets"]:
            forwarding_nets.append(net)

    rules_forwarding = []
    for rule in rules:
        logger.debug("")
        logger.debug("{}/forwarding: CHECKING NEXT RULE IN LIST".format(firewall["name"]))
        logger.debug(rule)
        if any_ip_affects_forwarding_firewall(firewall, rule["from"]):
            logger.debug("{}/forwarding: Rule matches OUTBOUND direction".format(firewall["name"]))
            accepted_rule = copy.deepcopy(rule)
            accepted_rule["direction"] = "out"
            strip_foreign_ips(firewall, accepted_rule, accepted_rule["direction"])
            rules_forwarding.append(accepted_rule)
            continue
        if any_ip_affects_forwarding_firewall(firewall, rule["to"]):
            logger.debug("{}/forwarding: Rule matches INBOUND direction".format(firewall["name"]))
            accepted_rule = copy.deepcopy(rule)
            accepted_rule["direction"] = "in"
            strip_foreign_ips(firewall, accepted_rule, accepted_rule["direction"])
            rules_forwarding.append(accepted_rule)
            continue
    return rules_forwarding


# flatten out rules and check if they affect the current firewall
# also populate "direction" to indicate traffic flow (in/out)
# also strips all non-relevant ips/networks from the rule (e.g. not local to the current firewall)
def prepare_firewall(firewall, rules):
    logger.info("Finding all rules affecting {}".format(firewall["name"]))

    rules_forwarding = get_forwarding_rules(firewall, rules)
    rules_local = get_local_rules(firewall, rules)

    logger.info("{}: Found {} local and {} forwarding rule(s) affecting this firewall".format( firewall["name"], len(rules_local), len(rules_forwarding)))
    return rules_local, rules_forwarding


def get_firewall(firewall, firewalls):
    for fw in firewalls:
        if fw["name"] == firewall:
            return fw
    raise Exception("Firewall '{}' not found".format(firewall))


def parse_rules(config):
    grammar = read_plaintext("grammar/arculus-fire-grammar-0.1")
    rules = read_plaintext("examples/rules")

    init_parser_start = perf_counter()
    parser = Lark(grammar, start="rules", parser="lalr", propagate_positions=True)
    init_parser_finish = perf_counter()

    init_parser_in_ms = round((init_parser_finish - init_parser_start) * 1000, 4)
    logger.debug("Initialising parser and grammar took {}ms".format(init_parser_in_ms))

    # parse our rules file (returns a Lark Tree type)
    parser_start = perf_counter()
    rules_parsed = parser.parse(rules)
    parser_finish = perf_counter()
    
    parsetime_in_ms = round((parser_finish - parser_start) * 1000, 4)
    logger.debug("Parsing all rules took {}ms".format(parsetime_in_ms))

    # transform the Tree into a list of dicts, suitable for processing
    transformer_start = perf_counter()
    rules_transformed = transform_rules(rules_parsed)
    transformer_finish = perf_counter()

    transformtime_in_ms = round((transformer_finish - transformer_start) * 1000, 4)
    logger.debug("Transforming parser tree into Python data structure took {}ms".format(transformtime_in_ms))

    logging.debug("Parsed {} rules from the rule file".format(len(rules_transformed)))
    
    definitions = arculusfireio.utils.yaml.read(config["general"]["net_definitions"])
    # replace all definitions (e.g. source/target hosts) with their real values
    # this should probably happen as a "Transformer" type of thing:
    # Lark is able to transform/replace stuff while it is parsing so we
    # don't have to look at everything twice
    rules_transformed = replace_definitions(rules_transformed, definitions)

    return rules_transformed