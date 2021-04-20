#!/usr/bin/env python

from arculusfireio.constants import ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX
from arculusfireio.generators.firewall_generator import FirewallGenerator
import arculusfireio.constants
from netaddr import IPNetwork

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

    def split_by_ip_version(self, ips):
        split_ips = {
            arculusfireio.constants.ARCULUS_IP_VERSION_FOUR: [],
            arculusfireio.constants.ARCULUS_IP_VERSION_SIX: []
        }
        for ip_str in ips:
            ip = IPNetwork(ip_str)
            if ip.version == 4:
                split_ips[arculusfireio.constants.ARCULUS_IP_VERSION_FOUR].append(ip_str)
            elif ip.version == 6:
                split_ips[arculusfireio.constants.ARCULUS_IP_VERSION_SIX].append(ip_str)
            else:
                raise Exception("Invalid IP address, could neither parse as IPv4 nor as IPv6: '{}'".format(ip_str))
        return split_ips

    # GENERIC FUNCTIONS

    def generate_filter_header(self):
        self.output[ARCULUS_IP_VERSION_FOUR] += "#!/usr/sbin/nft -f\n\n"
        self.output[ARCULUS_IP_VERSION_FOUR]+= "flush ruleset\n\n"
        local_networks = self.split_by_ip_version(self.local_networks)
        self.output[ARCULUS_IP_VERSION_FOUR]+= "define LOCAL_NETWORKS_IPV4 = {{{}}}\n\n".format(",".join(local_networks[ARCULUS_IP_VERSION_FOUR]))
        self.output[ARCULUS_IP_VERSION_FOUR]+= "define LOCAL_NETWORKS_IPV6 = {{{}}}\n\n".format(",".join(local_networks[ARCULUS_IP_VERSION_SIX]))
        self.output[ARCULUS_IP_VERSION_FOUR]+= "add table filter\n"

        if self.firewall["type"] == "forward":
            # initialise base forward table
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add chain filter forward { type filter hook forward priority 0; policy drop; }\n"
            # first rule: accept all related/established connections
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter forward ct state established,related counter accept\n"
            # second rule: ICMP is good.
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter forward ip protocol icmp counter accept\n\n"

        # initialise base input table
        self.output[ARCULUS_IP_VERSION_FOUR]+= "add chain filter input { type filter hook input priority 0; policy drop; }\n"
        # first rule: accept all related/established connections
        self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter input ct state established,related counter accept\n"
        # second rule: ICMP is good.
        self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter input ip protocol icmp counter accept\n\n"

        # accept localhost traffic 
        self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter input iif lo accept\n"
        self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter input iif != lo ip daddr 127.0.0.1/8 counter drop\n\n"


    def generate_filter_footer(self):
        filters = [ "input" ]
        if self.firewall["type"] == "forward":
            filters.append("forward")
        
        # add logging / dropping rules
        self.output[ARCULUS_IP_VERSION_FOUR]+= "\n"
        for filter_name in filters:
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} limit rate 3/second burst 15 packets ip saddr $LOCAL_NETWORKS_IPV4 ip daddr $LOCAL_NETWORKS_IPV4 log prefix \"INT-TO-INT\" group 0 continue\n".format(filter_name)
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} ip saddr $LOCAL_NETWORKS_IPV4 ip daddr $LOCAL_NETWORKS_IPV4 counter reject\n\n".format(filter_name)

            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} limit rate 3/second burst 15 packets ip saddr $LOCAL_NETWORKS_IPV4 ip daddr != $LOCAL_NETWORKS_IPV4 log prefix \"INT-TO-EXT\" group 0 continue\n".format(filter_name)
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} ip saddr $LOCAL_NETWORKS_IPV4 ip daddr != $LOCAL_NETWORKS_IPV4 counter reject\n\n".format(filter_name)

            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} limit rate 3/second burst 15 packets ip saddr != $LOCAL_NETWORKS_IPV4 ip daddr $LOCAL_NETWORKS_IPV4 log prefix \"EXT-TO-INT\" group 0 continue\n".format(filter_name)
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} ip saddr != $LOCAL_NETWORKS_IPV4 ip daddr $LOCAL_NETWORKS_IPV4 counter drop\n\n".format(filter_name)

            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} limit rate 3/second burst 15 packets ip6 saddr $LOCAL_NETWORKS_IPV6 ip6 daddr $LOCAL_NETWORKS_IPV6 log prefix \"INT-TO-INT\" group 0 continue\n".format(filter_name)
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} ip6 saddr $LOCAL_NETWORKS_IPV6 ip6 daddr $LOCAL_NETWORKS_IPV6 counter reject\n\n".format(filter_name)

            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} limit rate 3/second burst 15 packets ip6 saddr $LOCAL_NETWORKS_IPV6 ip6 daddr != $LOCAL_NETWORKS_IPV6 log prefix \"INT-TO-EXT\" group 0 continue\n".format(filter_name)
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} ip6 saddr $LOCAL_NETWORKS_IPV6 ip6 daddr != $LOCAL_NETWORKS_IPV6 counter reject\n\n".format(filter_name)

            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} limit rate 3/second burst 15 packets ip6 saddr != $LOCAL_NETWORKS_IPV6 ip6 daddr $LOCAL_NETWORKS_IPV6 log prefix \"EXT-TO-INT\" group 0 continue\n".format(filter_name)
            self.output[ARCULUS_IP_VERSION_FOUR]+= "add rule inet filter {} ip6 saddr != $LOCAL_NETWORKS_IPV6 ip6 daddr $LOCAL_NETWORKS_IPV6 counter drop\n\n".format(filter_name)


    def generate_forwarding_filter_rules(self):
        for rule in self.rules_forwarding:
            if not rule["protocols"]:
                raise NotImplementedError("DumbNftablesGenerator: rules without a protocol are not supported")

            for protocol in rule["protocols"]:
                src = self.split_by_ip_version(rule["from"])
                dests = self.split_by_ip_version(rule["to"])
                ip_prot_name = {
                    ARCULUS_IP_VERSION_FOUR: "ip",
                    ARCULUS_IP_VERSION_SIX: "ip6"
                }
                for ip_version in [ARCULUS_IP_VERSION_FOUR, ARCULUS_IP_VERSION_SIX]:
                    current_rule = "add rule inet filter forward {} protocol {} {} saddr {{{}}} {} daddr {{{}}}".format(
                        ip_prot_name[ip_version], protocol, ip_prot_name[ip_version], ",".join(src[ip_version]), ip_prot_name[ip_version], ",".join(dests[ip_version]))
                    if (protocol == "tcp" or protocol == "udp" or protocol == "sctp") and rule["dports"]:
                        current_rule += " {} dport {{{}}}".format(protocol, ",".join(rule["dports"])).replace(":","-")
                    current_rule += " counter accept comment \"source: line {}\"\n".format(rule["line"])
                    self.output[ARCULUS_IP_VERSION_FOUR]+= current_rule


    def generate_local_filter_rules(self):
        for rule in self.rules_local:
            if not rule["protocols"]:
                raise NotImplementedError("DumbNftablesGenerator: rules without a protocol are not supported")

            # WARNING: this generator currently only generates inbound rules - outbound traffic is unrestricted!
            if rule["direction"] != "in":
                continue

            for protocol in rule["protocols"]:
                current_rule = "add rule inet filter input ip protocol {} ip saddr {{{}}} ip daddr {{{}}}".format(
                    protocol, ",".join(rule["from"]), ",".join(rule["to"]))
                if (protocol == "tcp" or protocol == "udp" or protocol == "sctp") and rule["dports"]:
                    current_rule += " {} dport {{{}}}".format(protocol, ",".join(rule["dports"])).replace(":","-")
                current_rule += " counter accept comment \"source: line {}\"\n".format(rule["line"])
                self.output[ARCULUS_IP_VERSION_FOUR]+= current_rule


    def generate(self):
            self.generate_filter_header()
            self.generate_local_filter_rules()
            self.generate_forwarding_filter_rules()
            self.generate_filter_footer()