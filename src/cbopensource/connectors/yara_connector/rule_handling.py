# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import hashlib
import os
from typing import List, Optional

from . import globals


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
