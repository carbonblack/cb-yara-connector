import os
from unittest import TestCase

import globals
from main import generate_yara_rule_map_hash, verify_config

TESTS = os.path.abspath(os.path.dirname(__file__))


class TestMain(TestCase):

    def test_generate_yara_rule_map_hash(self):
        globals.g_yara_rule_map_hash_list = []
        generate_yara_rule_map_hash(os.path.join(TESTS, "rules"))
        self.assertEqual(1, len(globals.g_yara_rule_map_hash_list))
        self.assertEqual("191cc0ea3f9ef90ed1850a3650cd38ed", globals.g_yara_rule_map_hash_list[0])

    def test_validate_config(self):
        globals.output_file = None
        ok = verify_config(os.path.join(TESTS, "config", "sample.conf"), "Sample.conf")
        self.assertTrue(ok)
        self.assertEqual("Sample.conf", globals.output_file)

    def test_validate_config_missing_worker(self):
        globals.g_remote = None
        ok = verify_config(os.path.join(TESTS, "config", "no_worker.conf"), "Sample.conf")
        self.assertTrue(ok)
        self.assertFalse(globals.g_remote)
