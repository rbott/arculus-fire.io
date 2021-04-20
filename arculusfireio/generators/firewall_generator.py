#!/usr/bin/env python

import os
import arculusfireio.constants 

class FirewallGenerator:
     def __init__(self, name, rules, local_networks, workdir):
         self.output = {
             arculusfireio.constants.ARCULUS_IP_VERSION_FOUR: "",
             arculusfireio.constants.ARCULUS_IP_VERSION_SIX: ""
         }
         self.name = name
         self.rules_local = rules["rules_local"]
         self.rules_forwarding = rules["rules_forwarding"]
         self.firewall = rules["firewall"]
         self.local_networks = local_networks
         self.workdir = workdir


     def write_to_file(self):
        if not os.path.exists('{}/firewalls'.format(self.workdir)):
            os.makedirs('{}/firewalls'.format(self.workdir))
        
        with open('{}/firewalls/{}.ipv4'.format(self.workdir, self.name), 'w') as file:
            file.write(self.output[arculusfireio.constants.ARCULUS_IP_VERSION_FOUR])
        with open('{}/firewalls/{}.ipv6'.format(self.workdir, self.name), 'w') as file:
            file.write(self.output[arculusfireio.constants.ARCULUS_IP_VERSION_SIX])

