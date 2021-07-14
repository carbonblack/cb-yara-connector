# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.
import hashlib
import os
import sys

import yara

from .loggers import logger


def validate_yara_rules(yara_rules_dir: str):
    logger.info(f"Validating yara rules in directory: {yara_rules_dir}")
    yara_rule_map = generate_rule_map(yara_rules_dir)
    try:
        yara.compile(filepaths=yara_rule_map)
        logger.info("All yara rules compiled successfully")
    except Exception as err:
        logger.error(f"There were errors compiling yara rules: {err}")
        sys.exit(2)
    sys.exit()


def generate_rule_map(yara_rule_path: str):
    rule_map = {}
    md5sum = hashlib.md5()
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

            md5sum.update(open(fullpath).read().encode("utf-8"))

    return rule_map, md5sum.hexdigest()
