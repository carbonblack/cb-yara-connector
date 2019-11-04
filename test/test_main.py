# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import os
from unittest import TestCase

import globals
from main import generate_yara_rule_map_hash

TESTS = os.path.abspath(os.path.dirname(__file__))


class TestMain(TestCase):

    def test_01_generate_yara_rule_map_hash(self):
        globals.g_yara_rule_map_hash_list = []
        generate_yara_rule_map_hash(os.path.join(TESTS, "rules"))
        self.assertEqual(1, len(globals.g_yara_rule_map_hash_list))
        self.assertEqual("191cc0ea3f9ef90ed1850a3650cd38ed", globals.g_yara_rule_map_hash_list[0])
