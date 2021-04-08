#!/usr/bin/env python

import logging
import yaml

# generic helper to read and parse YAML file
def read(name):
    logging.debug("Reading/Parsing YAML file '{}'".format(name))
    with open(name, 'r') as reader:
        yaml_data = yaml.load(reader, Loader=yaml.FullLoader)
    return yaml_data