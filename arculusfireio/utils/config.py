#!/usr/bin/env python

import configparser
import logging

def read_config():
    config = configparser.ConfigParser()
    config.read('arculus-fire.io.conf')
    return config

def set_loglevel(config):
    logformat = "%(message)s"

    loglevel_string = str.lower(config["general"]["loglevel"])
    if loglevel_string == "debug":
        logformat = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
        loglevel=logging.DEBUG
    elif loglevel_string == "info":
        loglevel=logging.INFO
    else:
        loglevel=logging.WARNING

    logging.basicConfig(format=logformat, level=loglevel)