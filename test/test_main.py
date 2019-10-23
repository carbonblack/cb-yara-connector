import os
from unittest import TestCase

import globals
from main import CbInvalidConfig, generate_yara_rule_map_hash, verify_config

TESTS = os.path.abspath(os.path.dirname(__file__))


class TestMain(TestCase):

    def test_01_generate_yara_rule_map_hash(self):
        globals.g_yara_rule_map_hash_list = []
        generate_yara_rule_map_hash(os.path.join(TESTS, "rules"))
        self.assertEqual(1, len(globals.g_yara_rule_map_hash_list))
        self.assertEqual("191cc0ea3f9ef90ed1850a3650cd38ed", globals.g_yara_rule_map_hash_list[0])

    def test_02a_validate_config(self):
        # valid local
        globals.output_file = None
        globals.g_remote = None
        verify_config(os.path.join(TESTS, "config", "valid.conf"))
        self.assertTrue(globals.output_file.endswith("valid.conf.json"))
        self.assertFalse(globals.g_remote)

        # valid remote
        globals.g_remote = None
        verify_config(os.path.join(TESTS, "config", "valid2.conf"), "sample.json")
        self.assertTrue(globals.output_file.endswith("sample.json"))
        self.assertTrue(globals.g_remote)

    def test_02b_missing_config(self):
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
        assert "Config file does not have a 'general' section" in "{0}".format(err.exception.args[0])

    def test_04a_config_missing_worker(self):
        """
        Ensure that config lacking worker information defaults to local.
        """
        # not defined in file
        globals.g_remote = None
        verify_config(os.path.join(TESTS, "config", "missing_worker.conf"))
        self.assertFalse(globals.g_remote)

        # defined as "worker_type="
        globals.g_remote = None
        verify_config(os.path.join(TESTS, "config", "missing_worker2.conf"))
        self.assertFalse(globals.g_remote)

    def test_04b_config_bogus_worker(self):
        """
        Ensure that config with bogus worker is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_worker.conf"))
        assert "Invalid worker_type" in "{0}".format(err.exception.args[0])

    def test_05a_config_local_worker_missing_server_url(self):
        """
        Ensure that local worker config with missing server url is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_url.conf"))
        assert "Local worker configuration missing 'cb_server_url'" in "{0}".format(err.exception.args[0])

        # defined as "cb_server_url="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_url2.conf"))
        assert "Local worker configuration missing 'cb_server_url'" in "{0}".format(err.exception.args[0])

    def test_05b_config_local_worker_missing_server_token(self):
        """
        Ensure that local worker config with missing server token is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_token.conf"))
        assert "Local worker configuration missing 'cb_server_token'" in "{0}".format(err.exception.args[0])

        # defined as "cb_server_token="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "local_worker_no_server_token2.conf"))
        assert "Local worker configuration missing 'cb_server_token'" in "{0}".format(err.exception.args[0])

    def test_06_config_remote_worker_missing_server_token(self):
        """
        Ensure that remote worker config with missing broker url is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "remote_worker_no_broker_url.conf"))
        assert "Remote worker configuration missing 'broker_url'" in "{0}".format(err.exception.args[0])

        # defined as "broker_url="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "remote_worker_no_broker_url2.conf"))
        assert "Remote worker configuration missing 'broker_url'" in "{0}".format(err.exception.args[0])

    def test_07a_config_missing_yara_rules_dir(self):
        """
        Ensure that config with missing yara rules directory is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "no_rules_dir.conf"))
        assert "You must specify a yara rules directory in your configuration" in "{0}".format(err.exception.args[0])

        # defined as "yara_rules_dir="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "no_rules_dir2.conf"))
        assert "You must specify a yara rules directory in your configuration" in "{0}".format(err.exception.args[0])

    def test_07b_config_yara_rules_dir_not_exists(self):
        """
        Ensure that config with yara rules directory that does not exist is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "missing_rules_dir.conf"))
        assert "does not exist" in "{0}".format(err.exception.args[0])

    def test_07c_config_yara_rules_dir_not_directory(self):
        """
        Ensure that config with yara rules directory that is not a directory is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_rules_dir.conf"))
        assert "is not actualy a directory" in "{0}".format(err.exception.args[0])

    def test_08a_config_missing_postgres_host(self):
        """
        Ensure that config with missing postgres_host uses defaults.
        """
        check = globals.g_postgres_host

        # undefined, use default in globals
        verify_config(os.path.join(TESTS, "config", "missing_postgres_host.conf"))
        self.assertEqual(check, globals.g_postgres_host)

        # defined as "postgres_host="
        verify_config(os.path.join(TESTS, "config", "missing_postgres_host2.conf"))
        self.assertEqual(check, globals.g_postgres_host)

    # TODO: test_08b_config_invalid_postgres_host

    def test_09a_config_missing_postgres_username(self):
        """
        Ensure that config with missing postgres_username uses defaults.
        """
        check = globals.g_postgres_username

        # undefined, use default in globals
        verify_config(os.path.join(TESTS, "config", "missing_postgres_username.conf"))
        self.assertEqual(check, globals.g_postgres_username)

        # defined as "postgres_username="
        verify_config(os.path.join(TESTS, "config", "missing_postgres_username2.conf"))
        self.assertEqual(check, globals.g_postgres_username)

    # TODO: test_09b_config_invalid_postgres_username

    def test_10a_config_missing_postgres_password(self):
        """
        Ensure that config with missing postgres_password is detected.
        """
        # undefined
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "missing_postgres_password.conf"))
        assert "No 'postgres_password' defined in the configuration" in "{0}".format(err.exception.args[0])

        # defined as "postgres_password="
        with self.assertRaises(CbInvalidConfig) as err:
            verify_config(os.path.join(TESTS, "config", "missing_postgres_password2.conf"))
        assert "No 'postgres_password' defined in the configuration" in "{0}".format(err.exception.args[0])

    # TODO: test_10a_config_invalid_postgres_password

    def test_11a_config_missing_postgres_db(self):
        """
        Ensure that config with missing postgres_db is detected.
        """
        check = globals.g_postgres_db

        # undefined, use default in globals
        verify_config(os.path.join(TESTS, "config", "missing_postgres_db.conf"))
        self.assertEqual(check, globals.g_postgres_db)

        # defined as "postgres_db="
        verify_config(os.path.join(TESTS, "config", "missing_postgres_db2.conf"))
        self.assertEqual(check, globals.g_postgres_db)

    # TODO: test_11b_config_invalid_postgres_db

    def test_12a_config_missing_postgres_port(self):
        """
        Ensure that config with missing postgres_port is detected.
        """
        check = globals.g_postgres_port

        # undefined, use default in globals
        verify_config(os.path.join(TESTS, "config", "missing_postgres_port.conf"))
        self.assertEqual(check, globals.g_postgres_port)

        # defined as "postgres_port="
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "missing_postgres_port2.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_12b_config_bogus_postgres_port(self):
        """
        Ensure that config with bogus (non-int) postgres_port is detected.
        """
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_postgres_port.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    # TODO: test_12c_config_invalid_postgres_port

    def test_13a_config_missing_niceness(self):
        """
        Ensure that config with missing niceness is detected.
        """
        # defined as "niceness="
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "missing_niceness.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_13b_config_bogus_niceness(self):
        """
        Ensure that config with bogus (non-int) niceness is detected.
        """
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_niceness.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_14a_config_missing_concurrent_hashes(self):
        """
        Ensure that config with missing concurrent_hashes is detected.
        """
        # defined as "concurrent_hashes="
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "missing_concurrent_hashes.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_14b_config_bogus_concurrent_hashes(self):
        """
        Ensure that config with bogus (non-int) concurrent_hashes is detected.
        """
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_concurrent_hashes.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_15a_config_missing_disable_rescan(self):
        """
        Ensure that config with missing disable_rescan is detected.
        """
        globals.g_disable_rescan = None

        # defined as "disable_rescan="
        verify_config(os.path.join(TESTS, "config", "missing_disable_rescan.conf"))
        self.assertFalse(globals.g_disable_rescan)

    def test_15b_config_bogus_disable_rescan(self):
        """
        Ensure that config with bogus (non-bool) disable_rescan is detected.
        """
        globals.g_disable_rescan = None

        verify_config(os.path.join(TESTS, "config", "bogus_disable_rescan.conf"))
        self.assertTrue(globals.g_disable_rescan)

    def test_16a_config_missing_num_days_binaries(self):
        """
        Ensure that config with missing num_days_binaries is detected.
        """
        # defined as "num_days_binaries="
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "missing_num_days_binaries.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_16b_config_bogus_num_days_binaries(self):
        """
        Ensure that config with bogus (non-int) num_days_binaries is detected.
        """
        with self.assertRaises(ValueError) as err:
            verify_config(os.path.join(TESTS, "config", "bogus_num_days_binaries.conf"))
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])
