import os
from unittest import TestCase

from exceptions import CbInvalidConfig
from tasks import generate_rule_map, generate_yara_rule_map_hash, verify_config

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

    def test_02a_missing_config(self):
        """
        Ensure a missing config file is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "no-such-config.conf"))
        assert "does not exist!" in "{0}".format(err.exception.args[0])

    def test_03a_config_missing_header(self):
        """
        Ensure we detect a configuration file with no section header.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "missing_header.conf"))
        assert "File contains no section headers" in "{0}".format(err.exception.args[0])

    def test_03b_config_invalid_header(self):
        """
        Ensure we detect a configuration file with no "[general]" section header.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "invalid_header.conf"))
        assert "does not have a 'general' section" in "{0}".format(err.exception.args[0])

    def test_04a_config_local_worker_missing_server_url(self):
        """
        Ensure that local worker config with missing server url is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_url.conf"))
        assert "is 'local' and missing 'cb_server_url'" in "{0}".format(err.exception.args[0])

        # defined as "cb_server_url="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_url2.conf"))
        assert "is 'local' and missing 'cb_server_url'" in "{0}".format(err.exception.args[0])

    def test_04b_config_local_worker_missing_server_token(self):
        """
        Ensure that local worker config with missing server token is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_token.conf"))
        assert "is 'local' and missing 'cb_server_token'" in "{0}".format(err.exception.args[0])

        # defined as "cb_server_token="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_token2.conf"))
        assert "is 'local' and missing 'cb_server_token'" in "{0}".format(err.exception.args[0])

    def test_05_config_remote_worker_missing_broker_url(self):
        """
        Ensure that remote worker config with missing broker url is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "remote_worker_no_broker_url.conf"))
        assert "is 'remote' and missing 'broker_url'" in "{0}".format(err.exception.args[0])

        # defined as "broker_url="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "remote_worker_no_broker_url2.conf"))
        assert "is 'remote' and missing 'broker_url'" in "{0}".format(err.exception.args[0])

    def test_06a_config_missing_yara_rules_dir(self):
        """
        Ensure that config with missing yara rules directory is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "no_rules_dir.conf"))
        assert "has no 'yara_rules_dir' definition" in "{0}".format(err.exception.args[0])

        # defined as "yara_rules_dir="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "no_rules_dir2.conf"))
        assert "has no 'yara_rules_dir' definition" in "{0}".format(err.exception.args[0])

    def test_06b_config_yara_rules_dir_not_exists(self):
        """
        Ensure that config with yara rules directory that does not exist is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "missing_rules_dir.conf"))
        assert "does not exist" in "{0}".format(err.exception.args[0])

    def test_06c_config_yara_rules_dir_not_directory(self):
        """
        Ensure that config with yara rules directory that is not a directory is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_rules_dir.conf"))
        assert "is not a directory" in "{0}".format(err.exception.args[0])
