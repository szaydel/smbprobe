#!/usr/bin/env python3
import pprint
import yaml


def parse_config(filename):
    with open(filename, "rb") as input:
        try:
            conf_dict = yaml.full_load(input)
            return conf_dict, None
        except yaml.parser.ParserError as err:
            return None, err

data, err = parse_config("test.yml")
if err is not None:
    raise err

pprint.pprint(data, indent=2)