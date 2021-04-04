#!/usr/bin/env python

import configparser

def read_config():
    config = configparser.ConfigParser()
    config.read('arculus-fire.io.conf')
    return config