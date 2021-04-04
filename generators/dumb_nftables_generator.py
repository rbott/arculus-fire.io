#!/usr/bin/env python

from generators.firewall_generator import FirewallGenerator

# This implements a simple nftables output generator.
# It can be imported through `nft -f $file` or syntax-checked
# through `nft -cf $file`.
#
# The only abstraction it provides is grouping source/destination
# addresses together in a single rule. Other than that it is
# a dumb flat list of rules.

# quick nftables reference: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
# information related to nft scripting: https://wiki.nftables.org/wiki-nftables/index.php/Scripting

class DumbNftablesGenerator(FirewallGenerator):

    # GENERIC FUNCTIONS

    def generate_filter_header(self):
        self.output += "#!/usr/sbin/nft -f\n\n"
        self.output += "flush ruleset\n\n"
        self.output += "define LOCAL_NETWORKS = {{{}}}\n\n".format(",".join(self.local_networks))
        self.output += "add table filter\n"

        if self.firewall["type"] == "forward":
            # initialise base forward table
            self.output += "add chain filter forward { type filter hook forward priority 0; policy drop; }\n"
            # first rule: accept all related/established connections
            self.output += "add rule filter forward ct state established,related counter accept\n"
            # second rule: ICMP is good.
            self.output += "add rule filter forward ip protocol icmp counter accept\n\n"

        # initialise base input table
        self.output += "add chain filter input { type filter hook input priority 0; policy drop; }\n"
        # first rule: accept all related/established connections
        self.output += "add rule filter input ct state established,related counter accept\n"
        # second rule: ICMP is good.
        self.output += "add rule filter input ip protocol icmp counter accept\n\n"

        # accept localhost traffic 
        self.output += "add rule filter input iif lo accept\n"
        self.output += "add rule filter input iif != lo ip daddr 127.0.0.1/8 counter drop\n\n"


    def generate_filter_footer(self):
        filters = [ "input" ]
        if self.firewall["type"] == "forward":
            filters.append("forward")
        
        # add logging / dropping rules
        self.output += "\n"
        for filter_name in filters:
            self.output += "add rule filter {} limit rate 3/second burst 15 packets ip saddr $LOCAL_NETWORKS ip daddr $LOCAL_NETWORKS log prefix \"INT-TO-INT\" group 0 continue\n".format(filter_name)
            self.output += "add rule filter {} ip saddr $LOCAL_NETWORKS ip daddr $LOCAL_NETWORKS counter reject\n\n".format(filter_name)

            self.output += "add rule filter {} limit rate 3/second burst 15 packets ip saddr $LOCAL_NETWORKS ip daddr != $LOCAL_NETWORKS log prefix \"INT-TO-EXT\" group 0 continue\n".format(filter_name)
            self.output += "add rule filter {} ip saddr $LOCAL_NETWORKS ip daddr != $LOCAL_NETWORKS counter reject\n\n".format(filter_name)

            self.output += "add rule filter {} limit rate 3/second burst 15 packets ip saddr != $LOCAL_NETWORKS ip daddr $LOCAL_NETWORKS log prefix \"EXT-TO-INT\" group 0 continue\n".format(filter_name)
            self.output += "add rule filter {} ip saddr != $LOCAL_NETWORKS ip daddr $LOCAL_NETWORKS counter drop\n\n".format(filter_name)


    def generate_forwarding_filter_rules(self):
        for rule in self.rules_forwarding:
            if not rule["protocols"]:
                raise NotImplementedError("DumbNftablesGenerator: rules without a protocol are not supported")

            for protocol in rule["protocols"]:
                current_rule = "add rule filter forward ip protocol {} ip saddr {{{}}} ip daddr {{{}}}".format(
                    protocol, ",".join(rule["from"]), ",".join(rule["to"]))
                if (protocol == "tcp" or protocol == "udp" or protocol == "sctp") and rule["dports"]:
                    current_rule += " {} dport {{{}}}".format(protocol, ",".join(rule["dports"])).replace(":","-")
                current_rule += " counter accept comment \"source: line {}\"\n".format(rule["line"])
                self.output += current_rule


    def generate_local_filter_rules(self):
        for rule in self.rules_local:
            if not rule["protocols"]:
                raise NotImplementedError("DumbNftablesGenerator: rules without a protocol are not supported")

            # WARNING: this generator currently only generates inbound rules - outbound traffic is unrestricted!
            if rule["direction"] != "in":
                continue

            for protocol in rule["protocols"]:
                current_rule = "add rule filter input ip protocol {} ip saddr {{{}}} ip daddr {{{}}}".format(
                    protocol, ",".join(rule["from"]), ",".join(rule["to"]))
                if (protocol == "tcp" or protocol == "udp" or protocol == "sctp") and rule["dports"]:
                    current_rule += " {} dport {{{}}}".format(protocol, ",".join(rule["dports"])).replace(":","-")
                current_rule += " counter accept comment \"source: line {}\"\n".format(rule["line"])
                self.output += current_rule


    def generate(self):
            self.generate_filter_header()
            self.generate_local_filter_rules()
            self.generate_forwarding_filter_rules()
            self.generate_filter_footer()