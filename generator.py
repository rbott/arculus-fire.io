#!/usr/bin/env python

import logging
from time import perf_counter

from generators.dumb_iptables_generator import DumbIptablesGenerator
from generators.dumb_nftables_generator import DumbNftablesGenerator

import utils.config
import utils.yaml

if __name__ == "__main__":
    logger = logging.getLogger("root")

    timer_start = perf_counter()

    config = utils.config.read_config()
    utils.config.set_loglevel(config)

    definitions = utils.yaml.read(config["general"]["net_definitions"])
    firewalls = utils.yaml.read(config["general"]["firewall_definitions"])
    local_networks = [ d for d in definitions["net-objects"] if d["name"] == "mycorp-networks" ][0]["nets"]

    for firewall in firewalls["firewalls"]:
        fw_name = firewall["name"]
        rules = utils.yaml.read("{}/rules/{}.yml".format(config["general"]["workdir"],fw_name))
        if rules["firewall"]["target"] == "iptables":
            firewall_generator = DumbIptablesGenerator(fw_name, rules, local_networks, config["general"]["workdir"])
        elif rules["firewall"]["target"] == "nftables":
            firewall_generator = DumbNftablesGenerator(fw_name, rules, local_networks, config["general"]["workdir"])
        else:
            raise Exception("Unknown firewall target type: '{}'".format(rules["firewall"]["target"]))
        firewall_generator.generate()
        firewall_generator.write_to_file()

    timer_finish = perf_counter()
    runtime_in_ms = round((timer_finish - timer_start) * 1000, 4)

    logger.debug("Script ran for {}ms".format(runtime_in_ms))