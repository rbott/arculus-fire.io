#!/usr/bin/env python

import os 

class FirewallGenerator:
     def __init__(self, name, rules, local_networks, workdir):
         self.output = ""
         self.name = name
         self.rules_local = rules["rules_local"]
         self.rules_forwarding = rules["rules_forwarding"]
         self.firewall = rules["firewall"]
         self.local_networks = local_networks
         self.workdir = workdir


     def write_to_file(self):
        if not os.path.exists('{}/firewalls'.format(self.workdir)):
            os.makedirs('{}/firewalls'.format(self.workdir))
        
        with open('{}/firewalls/{}'.format(self.workdir, self.name), 'w') as file:
            file.write(self.output)

