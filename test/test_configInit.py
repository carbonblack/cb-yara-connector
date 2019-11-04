# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import os
from unittest import TestCase

import globals
from config_handling import ConfigurationInit
from exceptions import CbInvalidConfig

TESTS = os.path.abspath(os.path.dirname(__file__))


class TestConfigurationInit(TestCase):

    def setUp(self):
        globals.g_config = {}
        globals.g_output_file = './yara_feed.json'
        globals.g_remote = False
        globals.g_cb_server_url = 'https://127.0.0.1'
        globals.g_cb_server_token = ''
        globals.g_broker_url = ''
        globals.g_yara_rules_dir = './yara_rules'
        globals.g_yara_rule_map = {}
        globals.g_yara_rule_map_hash_list = []
        globals.g_postgres_host = '127.0.0.1'
        globals.g_postgres_username = 'cb'
        globals.g_postgres_password = ''
        globals.g_postgres_port = 5002
        globals.g_postgres_db = 'cb'
        globals.g_max_hashes = 8
        globals.g_num_binaries_not_available = 0
        globals.g_num_binaries_analyzed = 0
        globals.g_disable_rescan = True
        globals.g_num_days_binaries = 365
        globals.g_vacuum_interval = -1
        globals.g_vacuum_script = './scripts/vacuumscript.sh'
        globals.g_feed_database_dir = "./feed_db"

    def test_01_missing_config(self):
        """
        Ensure a missing config file is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "no-such-config.conf"))
        assert "does not exist!" in "{0}".format(err.exception.args[0])

    # ----- Full validation (main)

    def test_02_validate_config(self):
        # valid local
        globals.g_output_file = None
        globals.g_remote = None
        ConfigurationInit(os.path.join(TESTS, "config", "valid.conf"), "sample.json")
        self.assertTrue(globals.g_output_file.endswith("sample.json"))
        self.assertFalse(globals.g_remote)

        # valid remote
        globals.g_remote = None
        ConfigurationInit(os.path.join(TESTS, "config", "valid2.conf"), "sample2.json")
        self.assertTrue(globals.g_output_file.endswith("sample2.json"))
        self.assertTrue(globals.g_remote)

    def test_03a_config_missing_header(self):
        """
        Ensure we detect a configuration file with no section header.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "missing_header.conf"), "sample.json")
        assert "File contains no section headers" in "{0}".format(err.exception.args[0])

    def test_03b_config_invalid_header(self):
        """
        Ensure we detect a configuration file with no "[general]" section header.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "invalid_header.conf"), "sample.json")
        assert "does not have a 'general' section" in "{0}".format(err.exception.args[0])

    def test_04a_config_missing_worker(self):
        """
        Ensure that config lacking worker information defaults to local.
        """
        # not defined in file
        globals.g_remote = None
        ConfigurationInit(os.path.join(TESTS, "config", "missing_worker.conf"), "sample.json")
        self.assertFalse(globals.g_remote)

        # defined as "worker_type="
        globals.g_remote = None
        ConfigurationInit(os.path.join(TESTS, "config", "missing_worker2.conf"), "sample.json")
        self.assertFalse(globals.g_remote)

    def test_04b_config_bogus_worker(self):
        """
        Ensure that config with bogus worker is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_worker.conf"), "sample.json")
        assert "invalid 'worker_type'" in "{0}".format(err.exception.args[0])

    def test_05a_config_local_worker_missing_server_url(self):
        """
        Ensure that local worker config with missing server url is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "local_worker_no_server_url.conf"), "sample.json")
        assert "has no 'cb_server_url' definition" in "{0}".format(err.exception.args[0])

        # defined as "cb_server_url="
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "local_worker_no_server_url2.conf"), "sample.json")
        assert "has no 'cb_server_url' definition" in "{0}".format(err.exception.args[0])

    def test_05b_config_local_worker_missing_server_token(self):
        """
        Ensure that local worker config with missing server token is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "local_worker_no_server_token.conf"), "sample.json")
        assert "has no 'cb_server_token' definition" in "{0}".format(err.exception.args[0])

        # defined as "cb_server_token="
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "local_worker_no_server_token2.conf"), "sample.json")
        assert "has no 'cb_server_token' definition" in "{0}".format(err.exception.args[0])

    def test_06_config_remote_worker_missing_broker_url(self):
        """
        Ensure that remote worker config with missing broker url is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "remote_worker_no_broker_url.conf"), "sample.json")
        assert "has no 'broker_url' definition" in "{0}".format(err.exception.args[0])

        # defined as "broker_url="
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "remote_worker_no_broker_url2.conf"), "sample.json")
        assert "has no 'broker_url' definition" in "{0}".format(err.exception.args[0])

    def test_07a_config_missing_yara_rules_dir(self):
        """
        Ensure that config with missing yara rules directory is detected.
        """
        # not defined in file
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "no_rules_dir.conf"), "sample.json")
        assert "has no 'yara_rules_dir' definition" in "{0}".format(err.exception.args[0])

        # defined as "yara_rules_dir="
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "no_rules_dir2.conf"), "sample.json")
        assert "has no 'yara_rules_dir' definition" in "{0}".format(err.exception.args[0])

    def test_07b_config_yara_rules_dir_not_exists(self):
        """
        Ensure that config with yara rules directory that does not exist is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "missing_rules_dir.conf"), "sample.json")
        assert "does not exist" in "{0}".format(err.exception.args[0])

    def test_07c_config_yara_rules_dir_not_directory(self):
        """
        Ensure that config with yara rules directory that is not a directory is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_rules_dir.conf"), "sample.json")
        assert "is not a directory" in "{0}".format(err.exception.args[0])

    def test_08a_config_missing_postgres_host(self):
        """
        Ensure that config with missing postgres_host uses defaults.
        """
        check = globals.g_postgres_host

        # undefined, use default in globals
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_host.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_host)

        # defined as "postgres_host="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_host2.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_host)

    # TODO: test_08b_config_invalid_postgres_host

    def test_09a_config_missing_postgres_username(self):
        """
        Ensure that config with missing postgres_username uses defaults.
        """
        check = globals.g_postgres_username

        # undefined, use default in globals
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_username.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_username)

        # defined as "postgres_username="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_username2.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_username)

    # TODO: test_09b_config_invalid_postgres_username

    def test_10a_config_missing_postgres_password(self):
        """
        Ensure that config with missing postgres_password is detected.
        """
        # undefined
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_password.conf"), "sample.json")
        assert "has no 'postgres_password' definition" in "{0}".format(err.exception.args[0])

        # defined as "postgres_password="
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_password2.conf"), "sample.json")
        assert "has no 'postgres_password' definition" in "{0}".format(err.exception.args[0])

    # TODO: test_10a_config_invalid_postgres_password

    def test_11a_config_missing_postgres_db(self):
        """
        Ensure that config with missing postgres_db is detected.
        """
        check = globals.g_postgres_db

        # undefined, use default in globals
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_db.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_db)

        # defined as "postgres_db="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_db2.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_db)

    # TODO: test_11b_config_invalid_postgres_db

    def test_12a_config_missing_postgres_port(self):
        """
        Ensure that config with missing postgres_port is detected.
        """
        check = globals.g_postgres_port

        # undefined, use default in globals
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_port.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_port)

        # defined as "postgres_port="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_postgres_port2.conf"), "sample.json")
        self.assertEqual(check, globals.g_postgres_port)

    def test_12b_config_bogus_postgres_port(self):
        """
        Ensure that config with bogus (non-int) postgres_port is detected.
        """
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_postgres_port.conf"), "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    # TODO: test_12c_config_invalid_postgres_port

    def test_13a_config_missing_niceness(self):
        """
        Ensure that config with missing niceness is not a problem.
        """
        # defined as "niceness="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_niceness.conf"), "sample.json")

    def test_13b_config_bogus_niceness(self):
        """
        Ensure that config with bogus (non-int) niceness is detected.
        """
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_niceness.conf"), "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_14a_config_missing_concurrent_hashes(self):
        """
        Ensure that config with missing concurrent_hashes uses default.
        """
        check = globals.g_max_hashes

        # defined as "concurrent_hashes="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_concurrent_hashes.conf"), "sample.json")
        self.assertEqual(check, globals.g_max_hashes)

    def test_14b_config_bogus_concurrent_hashes(self):
        """
        Ensure that config with bogus (non-int) concurrent_hashes is detected.
        """
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_concurrent_hashes.conf"), "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_15a_config_missing_disable_rescan(self):
        """
        Ensure that config with missing disable_rescan is detected.
        """
        globals.g_disable_rescan = None

        # defined as "disable_rescan="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_disable_rescan.conf"), "sample.json")
        self.assertFalse(globals.g_disable_rescan)

    def test_15b_config_bogus_disable_rescan(self):
        """
        Ensure that config with bogus (non-bool) disable_rescan is detected.
        """
        globals.g_disable_rescan = None

        # Not true, false, yes, no
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_disable_rescan.conf"), "sample.json")
        assert "is not a valid boolean value" in "{0}".format(err.exception.args[0])

    def test_16a_config_missing_num_days_binaries(self):
        """
        Ensure that config with missing num_days_binaries reverts to default
        """
        check = globals.g_num_days_binaries

        # defined as "num_days_binaries="
        ConfigurationInit(os.path.join(TESTS, "config", "missing_num_days_binaries.conf"), "sample.json")
        self.assertEqual(check, globals.g_num_days_binaries)

    def test_16b_config_bogus_num_days_binaries(self):
        """
        Ensure that config with bogus (non-int) num_days_binaries is detected.
        """
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_num_days_binaries.conf"), "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_17a_config_bogus_vacuum_interval(self):
        """
        Ensure that config with bogus (non-int) vacuum_interval is detected.
        """
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_vacuum_interval.conf"), "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_17b_config_negative_vacuum_interval(self):
        """
        Ensure that config with bogus (non-int) vacuum_interval is detected.
        """
        globals.g_vacuum_interval = None
        ConfigurationInit(os.path.join(TESTS, "config", "negative_vacuum_interval.conf"), "sample.json")
        self.assertEqual(0, globals.g_vacuum_interval)

    def test_18a_config_missing_vacuum_script(self):
        """
        Ensure that config with missing vacuum_script is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "no_such_vacuum_script.conf"), "sample.json")
        assert "does not exist" in "{0}".format(err.exception.args[0])

    def test_18b_config_bogus_vacuum_script_is_dir(self):
        """
        Ensure that config with vacuum_script as directory is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "vacuum_script_dir.conf"), "sample.json")
        assert "is a directory" in "{0}".format(err.exception.args[0])

    def test_19a_config_vacuum_script_enabled(self):
        """
        Ensure that config with vacuum_script and vacuum_interval is ready to go.
        """
        globals.g_vacuum_interval = None
        globals.g_vacuum_script = None
        ConfigurationInit(os.path.join(TESTS, "config", "vacuum_script_enabled.conf"), "sample.json")
        self.assertEqual(360, globals.g_vacuum_interval)
        self.assertTrue(globals.g_vacuum_script.endswith("/scripts/vacuumscript.sh"))

    def test_19a_config_vacuum_script_and_no_vacuum_interval(self):
        """
        Ensure that config with vacuum_script but vacuum_interval == 0 has it disabled.
        """
        globals.g_vacuum_interval = None
        globals.g_vacuum_script = None
        ConfigurationInit(os.path.join(TESTS, "config", "vacuum_script_no_interval.conf"), "sample.json")
        self.assertEqual(0, globals.g_vacuum_interval)
        self.assertIsNone(globals.g_vacuum_script)

    def test_20a_config_feed_database_dir_not_exists(self):
        """
        Ensure that config with feed database directory that does not exist will create that directory.
        """
        path = os.path.abspath("./no-such-directory")
        if os.path.exists(path):
            os.rmdir(path)
        try:
            ConfigurationInit(os.path.join(TESTS, "config", "missing_feed_database_dir.conf"), "sample.json")
            self.assertTrue(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.rmdir(path)

    def test_20b_config_feed_database_dir_not_directory(self):
        """
        Ensure that config with eed database directory that is not a directory is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "bogus_feed_database_dir.conf"), "sample.json")
        assert "is not a directory" in "{0}".format(err.exception.args[0])

    def test_21_config_malformed_parameter(self):
        """
        Ensure that config with malformed parameter is detected
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "malformed_param.conf"), "sample.json")
        assert "cannot be parsed" in "{0}".format(err.exception.args[0])

    # ----- Minimal validation (worker)

    def test_90_minimal_validation_effects(self):
        """
        Ensure that minimal caonfiguration does not set extra globals
        """
        globals.g_postgres_host = None
        ConfigurationInit(os.path.join(TESTS, "config", "valid.conf"))
        self.assertIsNone(globals.g_postgres_host)
