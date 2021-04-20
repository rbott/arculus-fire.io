#!/usr/bin/env python

from socket import IPV6_CHECKSUM
from netaddr.ip import IPAddress
from arculusfireio.generators.firewall_generator import FirewallGenerator
from hashlib import sha1
from netaddr import IPNetwork
from arculusfireio.constants import ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX
import logging

logger = logging.getLogger("root")

# This implements a simple iptables output generator.
# Its output is to be consumed through ip(6)tables-restore.
#
# It only provides a very simple traffic abstraction to 
# (slightly) reduce the rule processing overhead:
# It generates one IN and one OUT chain per firewall interface
# and sorts traffic into these chains by matching the
# interface name, direction and source or destination prefixes.

class DumbIptablesGenerator(FirewallGenerator):
    def __init__(self, name, rules, local_networks, workdir):
        self.iptables_chains = []
        self.iptables_chain_rules = {}
        self.iptables_rules = []
        self.ip6tables_chains = []
        self.ip6tables_chain_rules = {}
        self.ip6tables_rules = []
        super().__init__(name, rules, local_networks, workdir)
    

    def lookup_chain(self, src, dst, direction):
        if direction == "in":
            ip_prefix = IPNetwork(dst)
            prefix = "TO-"
        else:
            ip_prefix = IPNetwork(src)
            prefix = "FROM-"

        for interface in self.firewall["local_interfaces"] + self.firewall["forwarding_interfaces"]:
            for net in interface["nets"]:
                if ip_prefix in IPNetwork(net):
                    return "{}{}".format(prefix, self.generate_interface_hash(interface))
        return "FORWARD"


    def generate_chain(self, ip_version, identifier):
        if ARCULUS_IP_VERSION_FOUR == ip_version:
            self.iptables_chains.append(identifier)
        elif ARCULUS_IP_VERSION_SIX == ip_version:
            self.ip6tables_chains.append(identifier)


    def generate_state_match(self):
        return "-m state --state NEW"


    def generate_comment(self, comment):
        return "-m comment --comment \"{}\"".format(comment)


    def generate_interface_hash(self, interface):
        interface_identifier = "{}_{}".format(interface["name"], "_".join(interface["nets"])).encode("utf-8")
        return sha1(interface_identifier).hexdigest()[:16]


    def generate_interfaces(self):
        for interface in self.firewall["local_interfaces"]:
            identifier = self.generate_interface_hash(interface)
            for ip_version in [ ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX]:
                self.generate_chain(ip_version, "TO-" + identifier)
                self.generate_chain(ip_version, "FROM-" + identifier)
            for net_str in interface["nets"]:
                net = IPNetwork(net_str)
                if net.version == 4:
                    self.iptables_rules.append("-A INPUT -d {} -i {} -j TO-{}".format(net_str, interface["name"], identifier))
                    self.iptables_rules.append("-A OUTPUT -s {} -o {} -j FROM-{}".format(net_str, interface["name"], identifier))
                elif net.version == 6:
                    self.ip6tables_rules.append("-A INPUT -d {} -i {} -j TO-{}".format(net_str, interface["name"], identifier))
                    self.ip6tables_rules.append("-A OUTPUT -s {} -o {} -j FROM-{}".format(net_str, interface["name"], identifier))

        for interface in self.firewall["forwarding_interfaces"]:
            identifier = self.generate_interface_hash(interface)
            for ip_version in [ ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX]:
                self.generate_chain(ip_version, "TO-" + identifier)
                self.generate_chain(ip_version, "FROM-" + identifier)
            for net_str in interface["nets"]:
                net = IPNetwork(net_str)
                if net.version == 4:
                    self.iptables_rules.append("-A FORWARD -s {} -i {} -j FROM-{}".format(net, interface["name"], identifier))
                    self.iptables_rules.append("-A FORWARD -d {} -o {} -j TO-{}".format(net, interface["name"], identifier))
                elif net.version == 6:
                    self.ip6tables_rules.append("-A FORWARD -s {} -i {} -j FROM-{}".format(net, interface["name"], identifier))
                    self.ip6tables_rules.append("-A FORWARD -d {} -o {} -j TO-{}".format(net, interface["name"], identifier))


    def split_by_ip_version(self, ips):
        split_ips = {
            ARCULUS_IP_VERSION_FOUR: [],
            ARCULUS_IP_VERSION_SIX: []
        }
        for ip_str in ips:
            ip = IPNetwork(ip_str)
            if ip.version == 4:
                split_ips[ARCULUS_IP_VERSION_FOUR].append(ip_str)
            elif ip.version == 6:
                split_ips[ARCULUS_IP_VERSION_SIX].append(ip_str)
            else:
                raise Exception("Invalid IP address, could neither parse as IPv4 nor as IPv6: '{}'".format(ip_str))
        return split_ips


    def generate_filter_rules(self):
        for rule in self.rules_local:
            if not rule["protocols"]:
                rule["protocols"] = [ "all" ]

            sources = self.split_by_ip_version(rule["from"])
            dests = self.split_by_ip_version(rule["to"])

            for ip_version in [ ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX ]:
                for src in sources[ip_version]:
                    for dst in dests[ip_version]:
                        for protocol in rule["protocols"]:
                            chain = self.lookup_chain(src, dst, rule["direction"])
                            comment = "source: line {}".format(rule["line"])
                            current_rule = "-A {} {} {} -s {} -d {} -p {}".format(
                                chain, self.generate_state_match(), self.generate_comment(comment), src, dst, protocol)
                            if protocol == "tcp" or protocol == "udp" or protocol == "sctp" or protocol == "all":
                                if rule["dports"]:
                                    current_rule += " -m multiport --dports {}".format(",".join(rule["dports"]))
                            current_rule += " -j ACCEPT\n"
                            self.output[ip_version] += current_rule

            for ip_version in [ ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX ]:
                for rule in self.rules_forwarding:
                    if not rule["protocols"]:
                        rule["protocols"] = [ "all" ]

                    sources = self.split_by_ip_version(rule["from"])
                    dests = self.split_by_ip_version(rule["to"])

                    for src in sources[ip_version]:
                        for dst in dests[ip_version]:
                            for protocol in rule["protocols"]:
                                chain = self.lookup_chain(src, dst, rule["direction"])
                                comment = "source: line {}".format(rule["line"])
                                current_rule = "-A {} {} {} -s {} -d {} -p {}".format(
                                    chain, self.generate_state_match(), self.generate_comment(comment), src, dst, protocol)
                                if protocol == "tcp" or protocol == "udp" or protocol == "sctp" or protocol == "all":
                                    if rule["dports"]:
                                        current_rule += " -m multiport --dports {}".format(",".join(rule["dports"]))
                                current_rule += " -j ACCEPT\n"
                                self.output[ip_version] += current_rule


    def generate_filter_header(self):
        for ip_version in [ ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX ]:
            self.output[ip_version] += "*filter\n"
            # initialise all known chains
            if self.firewall["type"] == "forward":
                self.output[ip_version] += ":FORWARD DROP [0:0]\n"
            self.output[ip_version] += ":INPUT DROP [0:0]\n"
            self.output[ip_version] += ":BYEBYE - [0:0]\n"
            self.output[ip_version] += ":BYEBYE_INT_TO_INT - [0:0]\n"
            self.output[ip_version] += ":BYEBYE_INT_TO_EXT - [0:0]\n"
            self.output[ip_version] += ":BYEBYE_EXT_TO_INT - [0:0]\n"
            for chain in self.iptables_chains:
                self.output[ip_version] += ":{} - [0:0]\n".format(chain)

            # first rule: accept all related/established connections
            if self.firewall["type"] == "forward":
                self.output[ip_version] += "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                self.output[ip_version] += "-A FORWARD -p icmp -j ACCEPT\n"

            self.output[ip_version] += "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
            self.output[ip_version] += "-A INPUT -p icmp -j ACCEPT\n"
            self.output[ip_version] += "-A INPUT -i lo -j ACCEPT\n"

        # sort traffic into chains by interface
        for rule in self.iptables_rules:
            self.output[ARCULUS_IP_VERSION_FOUR] += "{}\n".format(rule)
        for rule in self.ip6tables_rules:
            self.output[ARCULUS_IP_VERSION_SIX] += "{}\n".format(rule)


    def generate_filter_footer(self):
        for chain in self.iptables_chains:
            self.output[ARCULUS_IP_VERSION_FOUR] += "-A {} -j BYEBYE\n".format(chain)
        for chain in self.ip6tables_chains:
            self.output[ARCULUS_IP_VERSION_SIX] += "-A {} -j BYEBYE\n".format(chain)
        
        local_networks = self.split_by_ip_version(self.local_networks)

        for ip_version in [ ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX ]:
            # match local-to-local traffic
            for local_source_network in local_networks[ip_version]:
                for local_destination_network in local_networks[ip_version]:
                    self.output[ip_version] += "-A BYEBYE -s {} -d {} -j BYEBYE_INT_TO_INT\n".format(local_source_network, local_destination_network)
        
            # match local-to-external traffic
            for local_source_network in local_networks[ip_version]:
                self.output[ip_version] += "-A BYEBYE -s {} -j BYEBYE_INT_TO_EXT\n".format(local_source_network)

            # match external-to-local traffic
            for local_destination_network in local_networks[ip_version]:
                self.output[ip_version] += "-A BYEBYE -d {} -j BYEBYE_EXT_TO_INT\n".format(local_destination_network)
        
            # log and reject local-to-local traffic
            self.output[ip_version] += "-A BYEBYE_INT_TO_INT -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"INT-TO-INT\"\n"
            self.output[ip_version] += "-A BYEBYE_INT_TO_INT -p tcp -j REJECT --reject-with tcp-reset\n"
            self.output[ip_version] += "-A BYEBYE_INT_TO_INT -j REJECT\n"

            # log and reject local-to-external traffic
            self.output[ip_version] += "-A BYEBYE_INT_TO_EXT -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"INT-TO-EXT\"\n"
            self.output[ip_version] += "-A BYEBYE_INT_TO_EXT -p tcp -j REJECT --reject-with tcp-reset\n"
            self.output[ip_version] += "-A BYEBYE_INT_TO_EXT -j REJECT\n"

            # log and silently drop external-to-local traffic
            self.output[ip_version] += "-A BYEBYE_EXT_TO_INT -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"INT-TO-EXT\"\n"
            self.output[ip_version] += "-A BYEBYE_EXT_TO_INT -j DROP\n"


            # fall-back log + silent drop if anything went wrong above
            if self.firewall["type"] == "forward":
                self.output[ip_version] += "-A FORWARD -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"DEFAULT-DROP\"\n"
            self.output[ip_version] += "COMMIT\n"


    def generate(self):
        self.generate_interfaces()
        self.generate_filter_header()
        self.generate_filter_rules()
        self.generate_filter_footer()
        if not self.iptables_rules:
            logger.debug("No IPv4 rules detected")
            self.output[ARCULUS_IP_VERSION_FOUR] = ""
        if not self.ip6tables_rules:
            logger.debug("No IPv6 rules detected")
            self.output[ARCULUS_IP_VERSION_SIX] = ""