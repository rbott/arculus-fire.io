#!/usr/bin/env python

from arculusfireio.generators.firewall_generator import FirewallGenerator
from hashlib import sha1
from netaddr import IPNetwork

# This implements a simple iptables output generator.
# Its output is to be consumed through iptables-restore.
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


    def generate_chain(self, identifier):
        self.iptables_chains.append(identifier)


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
            self.generate_chain("TO-" + identifier)
            self.generate_chain("FROM-" + identifier)
            for net in interface["nets"]:
                self.iptables_rules.append("-A INPUT -d {} -i {} -j TO-{}".format(net, interface["name"], identifier))
                self.iptables_rules.append("-A OUTPUT -s {} -o {} -j FROM-{}".format(net, interface["name"], identifier))

        for interface in self.firewall["forwarding_interfaces"]:
            identifier = self.generate_interface_hash(interface)
            self.generate_chain("TO-" + identifier)
            self.generate_chain("FROM-" + identifier)
            for net in interface["nets"]:
                self.iptables_rules.append("-A FORWARD -s {} -i {} -j FROM-{}".format(net, interface["name"], identifier))
                self.iptables_rules.append("-A FORWARD -d {} -o {} -j TO-{}".format(net, interface["name"], identifier))


    def generate_filter_rules(self):
        for rule in self.rules_local:
            if not rule["protocols"]:
                rule["protocols"] = [ "all" ]

            for src in rule["from"]:
                for dst in rule["to"]:
                    for protocol in rule["protocols"]:
                        chain = self.lookup_chain(src, dst, rule["direction"])
                        comment = "source: line {}".format(rule["line"])
                        current_rule = "-A {} {} {} -s {} -d {} -p {}".format(
                            chain, self.generate_state_match(), self.generate_comment(comment), src, dst, protocol)
                        if protocol == "tcp" or protocol == "udp" or protocol == "sctp" or protocol == "all":
                            if rule["dports"]:
                                current_rule += " -m multiport --dports {}".format(",".join(rule["dports"]))
                        current_rule += " -j ACCEPT\n"
                        self.output += current_rule
                        
        for rule in self.rules_forwarding:
            if not rule["protocols"]:
                rule["protocols"] = [ "all" ]

            for src in rule["from"]:
                for dst in rule["to"]:
                    for protocol in rule["protocols"]:
                        chain = self.lookup_chain(src, dst, rule["direction"])
                        comment = "source: line {}".format(rule["line"])
                        current_rule = "-A {} {} {} -s {} -d {} -p {}".format(
                            chain, self.generate_state_match(), self.generate_comment(comment), src, dst, protocol)
                        if protocol == "tcp" or protocol == "udp" or protocol == "sctp" or protocol == "all":
                            if rule["dports"]:
                                current_rule += " -m multiport --dports {}".format(",".join(rule["dports"]))
                        current_rule += " -j ACCEPT\n"
                        self.output += current_rule


    def generate_filter_header(self):
        self.output += "*filter\n"
        # initialise all known chains
        if self.firewall["type"] == "forward":
            self.output += ":FORWARD DROP [0:0]\n"
        self.output += ":INPUT DROP [0:0]\n"
        self.output += ":BYEBYE - [0:0]\n"
        self.output += ":BYEBYE_INT_TO_INT - [0:0]\n"
        self.output += ":BYEBYE_INT_TO_EXT - [0:0]\n"
        self.output += ":BYEBYE_EXT_TO_INT - [0:0]\n"
        for chain in self.iptables_chains:
            self.output += ":{} - [0:0]\n".format(chain)

        # first rule: accept all related/established connections
        if self.firewall["type"] == "forward":
            self.output += "-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
            self.output += "-A FORWARD -p icmp -j ACCEPT\n"

        self.output += "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
        self.output += "-A INPUT -p icmp -j ACCEPT\n"
        self.output += "-A INPUT -i lo -j ACCEPT\n"

        # sort traffic into chains by interface
        for rule in self.iptables_rules:
            self.output += "{}\n".format(rule)


    def generate_filter_footer(self):
        for chain in self.iptables_chains:
            self.output += "-A {} -j BYEBYE\n".format(chain)
        
        # match local-to-local traffic
        for local_source_network in self.local_networks:
            for local_destination_network in self.local_networks:
                self.output += "-A BYEBYE -s {} -d {} -j BYEBYE_INT_TO_INT\n".format(local_source_network, local_destination_network)
        
        # match local-to-external traffic
        for local_source_network in self.local_networks:
            self.output += "-A BYEBYE -s {} -j BYEBYE_INT_TO_EXT\n".format(local_source_network)

        # match external-to-local traffic
        for local_destination_network in self.local_networks:
            self.output += "-A BYEBYE -d {} -j BYEBYE_EXT_TO_INT\n".format(local_destination_network)
        
        # log and reject local-to-local traffic
        self.output += "-A BYEBYE_INT_TO_INT -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"INT-TO-INT\"\n"
        self.output += "-A BYEBYE_INT_TO_INT -p tcp -j REJECT --reject-with tcp-reset\n"
        self.output += "-A BYEBYE_INT_TO_INT -j REJECT\n"

        # log and reject local-to-external traffic
        self.output += "-A BYEBYE_INT_TO_EXT -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"INT-TO-EXT\"\n"
        self.output += "-A BYEBYE_INT_TO_EXT -p tcp -j REJECT --reject-with tcp-reset\n"
        self.output += "-A BYEBYE_INT_TO_EXT -j REJECT\n"

        # log and silently drop external-to-local traffic
        self.output += "-A BYEBYE_EXT_TO_INT -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"INT-TO-EXT\"\n"
        self.output += "-A BYEBYE_EXT_TO_INT -j DROP\n"


        # fall-back log + silent drop if anything went wrong above
        if self.firewall["type"] == "forward":
            self.output += "-A FORWARD -m limit --limit 3 --limit-burst 15 -j NFLOG --nflog-prefix \"DEFAULT-DROP\"\n"
        self.output += "COMMIT\n"


    def generate(self):
        self.generate_interfaces()
        self.generate_filter_header()
        self.generate_filter_rules()
        self.generate_filter_footer()