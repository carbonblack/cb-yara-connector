# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import hashlib
import os
import sys
from typing import List, Optional

import yara

from . import globals
from .loggers import logger


def generate_yara_rule_map_hash(yara_rule_path: str, return_list: bool = False) -> Optional[List[str]]:
    """
    Create a list of hashes for each yara rule.

    :param yara_rule_path: the path to where the yara rules are stored.
    :param return_list: if True; return the list locally instead of saving to globals
    """
    temp_list = []
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
            fullpath = os.path.join(yara_rule_path, fn)
            if not os.path.isfile(fullpath):
                continue
            with open(os.path.join(yara_rule_path, fn), "rb") as fp:
                data = fp.read()
                md5 = hashlib.md5()
                md5.update(data)
                temp_list.append(str(md5.hexdigest()))

    temp_list.sort()

    if not return_list:
        globals.g_yara_rule_map_hash_list = temp_list
        return None
    else:
        return temp_list


def validate_yara_rules():
    """ RULE VALIDATION MODE OF OPERATION """
    logger.info(f"Validating yara rules in directory: {globals.g_yara_rules_dir}")
    yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
    try:
        yara.compile(filepaths=yara_rule_map)
        logger.info("All yara rules compiled successfully")
    except Exception as err:
        logger.error(f"There were errors compiling yara rules: {err}")
        sys.exit(2)
    sys.exit()

def generate_rule_map(yara_rule_path: str) -> dict:
    """
    Create a dictionary keyed by filename containing file paths
    :param yara_rule_path: location of yara rules
    :return: dict of paths keyed by namespace
    """
    rule_map = {}
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
            fullpath = os.path.join(yara_rule_path, fn)
            if not os.path.isfile(fullpath):
                continue

            last_dot = fn.rfind(".")
            if last_dot != -1:
                namespace = fn[:last_dot]
            else:
                namespace = fn
            rule_map[namespace] = fullpath

    return rule_map
