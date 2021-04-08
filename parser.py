#!/usr/bin/env python

import logging
from time import perf_counter
import arculusfireio.utils.config
import arculusfireio.utils.yaml
import arculusfireio.parser

if __name__ == "__main__":
    logger = logging.getLogger("root")

    timer_start = perf_counter()

    config = arculusfireio.utils.config.read_config()
    arculusfireio.utils.config.set_loglevel(config)

    firewalls = arculusfireio.utils.yaml.read(config["general"]["firewall_definitions"])

    # parse the `rules` file
    rules = arculusfireio.parser.parse_rules(config)
    
    # prepare data for each configured firewall (written out to `generated_rules/$name`)
    for firewall in firewalls["firewalls"]:
        fw = firewall["name"]
        firewall = arculusfireio.parser.get_firewall(fw, firewalls["firewalls"])
        rules_local, rules_forwarding = arculusfireio.parser.prepare_firewall(firewall, rules)
        arculusfireio.parser.write_rules(firewall, rules_local, rules_forwarding, config["general"]["workdir"])
    
    timer_finish = perf_counter()
    runtime_in_ms = round((timer_finish - timer_start) * 1000, 4)

    logger.debug("Script ran for {}ms".format(runtime_in_ms))

