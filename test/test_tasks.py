# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import os
from unittest import TestCase

from tasks import generate_rule_map, generate_yara_rule_map_hash

TESTS = os.path.abspath(os.path.dirname(__file__))


class TestTasks(TestCase):

    def test_01a_generate_yara_rule_map(self):
        the_dict = generate_rule_map(os.path.join(TESTS, "rules"))
        self.assertEqual(1, len(the_dict))
        self.assertTrue("test" in the_dict)
        self.assertTrue(the_dict["test"].endswith("test/rules/test.yara"))

    def test_01b_generate_yara_rule_map_hash(self):
        the_list = generate_yara_rule_map_hash(os.path.join(TESTS, "rules"))
        self.assertEqual(1, len(the_list))
        self.assertEqual("191cc0ea3f9ef90ed1850a3650cd38ed", the_list[0])
