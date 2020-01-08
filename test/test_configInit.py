# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import os
from typing import List
from unittest import TestCase

import globals
from config_handling import ConfigurationInit
from exceptions import CbInvalidConfig

TESTS = os.path.abspath(os.path.dirname(__file__))

TESTCONF = os.path.join(TESTS, "conf-testing.conf")
BASE = """[general]
mode=master

cb_server_url=https://127.0.0.1:443
cb_server_token=abcdefghijklmnopqrstuvwxyz012345
broker_url=redis://

yara_rules_dir=./rules

postgres_host=localhost
postgres_username=cb
postgres_password=abcdefghijklmnop
postgres_db=cb
postgres_port=5002

niceness=1
concurrent_hashes=8
disable_rescan=False
num_days_binaries=365

utility_interval=360
utility_script=../scripts/vacuumscript.sh
utility_debug=false

feed_database_dir=./feed_db

worker_network_timeout=5
database_scanning_interval=360

celery_worker_kwargs={"autoscale":"4,4"}
"""


class TestConfigurationInit(TestCase):

    def setUp(self) -> None:
        """
        Reset globals and recreate a base configuration.
        :return:
        """
        globals.g_config = {}
        globals.g_output_file = ""
        globals.g_mode = ""
        globals.g_cb_server_url = ""
        globals.g_cb_server_token = ""
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
        globals.g_utility_interval = 0
        globals.g_utility_script = ""
        globals.g_utility_debug = False
        globals.g_feed_database_dir = "./feed_db"
        globals.g_worker_network_timeout = 5
        globals.g_scanning_interval = 360
        globals.g_celeryworkerkwargs = None

        with open(TESTCONF, "w") as fp:
            fp.write(BASE)

    def tearDown(self) -> None:
        """
        Cleanup after testing.
        """
        if os.path.exists(TESTCONF):
            os.remove(TESTCONF)

        if os.path.exists(globals.g_feed_database_dir):
            os.rmdir(globals.g_feed_database_dir)

    @staticmethod
    def mangle(header: str = None, add: List[str] = None, change: dict = None):
        """
        Mangle the base configuration file to produce the testing situation
        :param header: mangle header entry, if specified
        :param add: list of string entries to add to the end
        :param change: dictionary of changes, keyed by parameter; a value of None removes the line
        :return:
        """
        with open(TESTCONF, "r") as fp:
            original = fp.readlines()

        replace = []
        for line in original:
            if header is not None and line.strip().startswith("[") and line.strip().endswith("]"):
                line = header + "\n"
            if change is not None:
                for key, value in change.items():
                    if line.startswith(key):
                        if value is None:
                            line = None
                        else:
                            line = f"{key}={value}\n"
                        break
            if line is not None:
                replace.append(line)

        if add is not None:
            for item in add:
                replace.append(item + "\n")

        with open(TESTCONF, "w") as fp:
            fp.writelines(replace)

    # ----- Begin Tests ----------------------------------------------------------------------

    def test_00a_validate_config(self):
        """
        Ensure our base configuration is valid.
        """
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertTrue(globals.g_output_file.endswith("sample.json"))

    def test_00b_validate_config_worker(self):
        """
        Ensure our base configuration is valid for worker types.
        """
        ConfigurationInit(TESTCONF)
        self.assertEqual("", globals.g_output_file)

    def test_01a_missing_config(self):
        """
        Ensure a missing config file is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS, "config", "no-such-config.conf"))
        assert "does not exist!" in "{0}".format(err.exception.args[0])

    def test_01b_config_is_dir(self):
        """
        Ensure a config path leading to a directory is detected.
        """
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(os.path.join(TESTS))
        assert "is a directory!" in "{0}".format(err.exception.args[0])

    def test_02a_section_header_missing(self):
        """
        Ensure we detect a configuration file without a "[general]" section header.
        """
        self.mangle(change={"[general]": None})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "File contains no section headers" in "{0}".format(err.exception.args[0])

    def test_02b_section_header_invalid(self):
        """
        Ensure we detect a configuration file with a different section header than "[general]".
        """
        self.mangle(header="[foobar]")
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "does not have a 'general' section" in "{0}".format(err.exception.args[0])

    def test_03a_mode_missing(self):
        """
        Ensure we detect a configuration file without a 'mode' definition (defaults to "master")
        """
        self.mangle(change={"mode": None})
        ConfigurationInit(TESTCONF)
        self.assertEqual("master", globals.g_mode)

    def test_03b_mode_invalid(self):
        """
        Ensure we detect a configuration file with an invalid 'mode' definition.
        """
        self.mangle(change={"mode": "bogus"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "does not specify an allowed value: ['master', 'worker', 'master+worker']" in "{0}".format(
            err.exception.args[0])

    def test_03c_mode_duplicated(self):
        """
        Ensure we detect a configuration file with a duplicate 'mode' defintion (same logic applies
        to all parameter duplicates).
        """
        self.mangle(add=["mode=bogus"])
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "option 'mode' in section 'general' already exists" in "{0}".format(err.exception.args[0])

    # test_04 worker_type removed

    def test_05a_cb_server_url_missing_for_master(self):
        """
        Ensure that 'cb_server_url' is not required if mode==slave and worker_type==remote
        """
        self.mangle(change={"mode": "master", "cb_server_url": None})
        ConfigurationInit(TESTCONF)
        self.assertEqual("", globals.g_cb_server_url)

    def test_05b_cb_server_url_empty_for_master(self):
        """
        Ensure that 'cb_server_url' is not required if mode==slave and worker_type==remote
        """
        self.mangle(change={"mode": "master", "cb_server_url": ""})
        ConfigurationInit(TESTCONF)
        self.assertEqual("", globals.g_cb_server_url)

    def test_05c_cb_server_url_missing_for_worker(self):
        """
        Ensure that 'cb_server_url' is required and detected if mode=worker.
        """
        self.mangle(change={"mode": "worker", "cb_server_url": None})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "has no 'cb_server_url' definition" in "{0}".format(err.exception.args[0])

    def test_05d_cb_server_url_empty_for_worker(self):
        """
        Ensure that 'cb_server_url' is required and detected if mode=worker.
        """
        self.mangle(change={"mode": "worker", "cb_server_url": ""})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "has no 'cb_server_url' definition" in "{0}".format(err.exception.args[0])

    def test_05e_cb_server_url_missing_for_worker(self):
        """
        Ensure that 'cb_server_url' is required and detected.
        """
        self.mangle(change={"mode": "worker", "cb_server_url": None})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "has no 'cb_server_url' definition" in "{0}".format(err.exception.args[0])

    def test_05f_cb_server_url_empty_for_worker(self):
        """
        Ensure that 'cb_server_url' is required and detected.
        """
        self.mangle(change={"mode": "worker", "cb_server_url": ""})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "has no 'cb_server_url' definition" in "{0}".format(err.exception.args[0])

    def test_06a_broker_url_missing(self):
        """
        Ensure that  missing broker_url is detected.
        """
        self.mangle(change={"broker_url": None})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "has no 'broker_url' definition" in "{0}".format(err.exception.args[0])

    def test_06b_broker_url_empty(self):
        """
        Ensure that empty broker_url is detected.
        """
        self.mangle(change={"broker_url": ""})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF)
        assert "has no 'broker_url' definition" in "{0}".format(err.exception.args[0])

    def test_07a_yara_rules_dir_missing(self):
        """
        Ensure that config with missing yara rules directory is detected.
        """
        self.mangle(change={"yara_rules_dir": None})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "has no 'yara_rules_dir' definition" in "{0}".format(err.exception.args[0])

    def test_07b_yara_rules_dir_empty(self):
        """
        Ensure that config with empty yara rules directory is detected.
        """
        self.mangle(change={"yara_rules_dir": ""})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "has no 'yara_rules_dir' definition" in "{0}".format(err.exception.args[0])

    def test_07c_yara_rules_dir_not_exists(self):
        """
        Ensure that config with yara rules directory that does not exist is detected.
        """
        self.mangle(change={"yara_rules_dir": "no-such-dir"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "does not exist" in "{0}".format(err.exception.args[0])

    def test_07d_yara_rules_dir_not_directory(self):
        """
        Ensure that config with yara rules directory that is not a directory is detected.
        """
        self.mangle(change={"yara_rules_dir": TESTCONF})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "is not a directory" in "{0}".format(err.exception.args[0])

    # ----- extended config, requires output_file with value ------------------------------

    def test_08a_postgres_host_missing(self):
        """
        Ensure that config with missing postgres_host uses defaults.
        """
        check = globals.g_postgres_host

        self.mangle(change={"postgres_host": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_host)

    def test_08b_postgres_host_empty(self):
        """
        Ensure that config with empty postgres_host uses defaults.
        """
        check = globals.g_postgres_host

        self.mangle(change={"postgres_host": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_host)

    def test_09a_postgres_username_missing(self):
        """
        Ensure that config with missing postgres_username uses defaults.
        """
        check = globals.g_postgres_username

        self.mangle(change={"postgres_host": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_username)

    def test_09b_postgres_username_empty(self):
        """
        Ensure that config with empty postgres_username uses defaults.
        """
        check = globals.g_postgres_username

        self.mangle(change={"postgres_host": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_username)

    def test_10a_postgres_password_missing(self):
        """
        Ensure that config with missing postgres_password is detected.
        """
        self.mangle(change={"postgres_password": None})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "has no 'postgres_password' definition" in "{0}".format(err.exception.args[0])

    def test_10b_postgres_password_empty(self):
        """
        Ensure that config with empty postgres_password is detected.
        """
        self.mangle(change={"postgres_password": ""})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "has no 'postgres_password' definition" in "{0}".format(err.exception.args[0])

    def test_11a_postgres_db_missing(self):
        """
        Ensure that config with missing postgres_db is detected.
        """
        check = globals.g_postgres_db

        self.mangle(change={"postgres_db": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_db)

    def test_11b_postgres_db_empty(self):
        """
        Ensure that config with empty postgres_db is detected.
        """
        check = globals.g_postgres_db

        self.mangle(change={"postgres_db": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_db)

    def test_12a_postgres_port_missing(self):
        """
        Ensure that config with missing postgres_port is detected.
        """
        check = globals.g_postgres_port

        self.mangle(change={"postgres_port": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_port)

    def test_12b_postgres_port_empty(self):
        """
        Ensure that config with empty postgres_port is detected.
        """
        check = globals.g_postgres_port

        self.mangle(change={"postgres_port": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_postgres_port)

    def test_12c_postgres_port_bogus(self):
        """
        Ensure that config with bogus (non-int) postgres_port is detected.
        """
        self.mangle(change={"postgres_port": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_13a_niceness_missing(self):
        """
        Ensure that config with missing niceness is not a problem.
        """
        self.mangle(change={"niceness": None})
        ConfigurationInit(TESTCONF, "sample.json")

    def test_13b_niceness_empty(self):
        """
        Ensure that config with missing niceness is not a problem.
        """
        self.mangle(change={"niceness": ""})
        ConfigurationInit(TESTCONF, "sample.json")

    def test_13c_niceness_bogus(self):
        """
        Ensure that config with bogus (non-int) niceness is detected.
        """
        self.mangle(change={"niceness": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_13d_niceness_negative(self):
        """
        Ensure that config with bogus (non-int) niceness is detected.
        """
        self.mangle(change={"niceness": "-1"})
        with self.assertRaises(Exception) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "'niceness' must be greater or equal to 0" in "{0}".format(err.exception.args[0])

    def test_14a_concurrent_hashes_missing(self):
        """
        Ensure that config with missing concurrent_hashes uses default.
        """
        check = globals.g_max_hashes

        self.mangle(change={"concurrent_hashes": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_max_hashes)

    def test_14b_concurrent_hashes_empty(self):
        """
        Ensure that config with missing concurrent_hashes uses default.
        """
        check = globals.g_max_hashes

        self.mangle(change={"concurrent_hashes": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_max_hashes)

    def test_14c_concurrent_hashes_bogus(self):
        """
        Ensure that config with bogus (non-int) concurrent_hashes is detected.
        """
        self.mangle(change={"concurrent_hashes": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_15a_disable_rescan_missing(self):
        """
        Ensure that config with missing disable_rescan is replaced with default
        """
        check = globals.g_disable_rescan

        self.mangle(change={"disable_rescan": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_disable_rescan)

    def test_15b_disable_rescan_empty(self):
        """
        Ensure that config with missing disable_rescan is replaced with default
        """
        check = globals.g_disable_rescan

        self.mangle(change={"disable_rescan": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_disable_rescan)

    def test_15c_disable_rescan_bogus(self):
        """
        Ensure that config with bogus (non-bool) disable_rescan is detected.
        """
        self.mangle(change={"disable_rescan": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "is not a valid boolean value" in "{0}".format(err.exception.args[0])

    def test_16a_num_days_binaries_missing(self):
        """
        Ensure that config with missing num_days_binaries reverts to default
        """
        check = globals.g_num_days_binaries

        self.mangle(change={"num_days_binaries": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_num_days_binaries)

    def test_16b_num_days_binaries_empty(self):
        """
        Ensure that config with empty num_days_binaries reverts to default
        """
        check = globals.g_num_days_binaries

        self.mangle(change={"num_days_binaries": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_num_days_binaries)

    def test_16c_num_days_binaries_bogus(self):
        """
        Ensure that config with bogus (non-int) num_days_binaries is detected.
        """
        self.mangle(change={"num_days_binaries": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_17a_utility_interval_missing(self):
        """
        Ensure that missing utility_interval uses the default.
        """
        check = globals.g_utility_interval

        self.mangle(change={"utility_interval": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_utility_interval)

    def test_17b_utility_interval_empty(self):
        """
        Ensure that empty utility_interval uses the default.
        """
        check = globals.g_utility_interval

        self.mangle(change={"utility_interval": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_utility_interval)

    def test_17c_utility_interval_bogus(self):
        """
        Ensure that config with bogus (non-int) utility_interval is detected.
        """
        self.mangle(change={"utility_interval": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_17d_utility_interval_negative(self):
        """
        Ensure that config with negative utility_interval is detected.
        """
        self.mangle(change={"utility_interval": "-10"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "'utility_interval' must be greater or equal to 0" in "{0}".format(err.exception.args[0])

    def test_18a_utility_script_not_exist(self):
        """
        Ensure that config with non-existing utility_script is detected.
        """
        self.mangle(change={"utility_script": "no-such-script.sh", "utility_interval": "10"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "does not exist" in "{0}".format(err.exception.args[0])

    def test_18b_utility_script_is_dir(self):
        """
        Ensure that config with utility_script as directory is detected.
        """
        self.mangle(change={"utility_script": TESTS, "utility_interval": "10"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "is a directory" in "{0}".format(err.exception.args[0])

    def test_18c_utility_script_missing(self):
        """
        Ensure that config with missing utility_script with positive interval is nullified.
        """
        self.mangle(change={"utility_script": None, "utility_interval": "10"})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(0, globals.g_utility_interval)
        self.assertEqual("", globals.g_utility_script)

    def test_18d_utility_script_empty(self):
        """
        Ensure that config with empty utility_script with positive interval is nullified.
        """
        self.mangle(change={"utility_script": "", "utility_interval": "10"})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(0, globals.g_utility_interval)
        self.assertEqual("", globals.g_utility_script)

    def test_19a_utility_script_enabled(self):
        """
        Ensure that config with utility_script and utility_interval is ready to go.
        """
        self.mangle(change={"utility_script": "../scripts/vacuumscript.sh", "utility_interval": "10"})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(10, globals.g_utility_interval)
        self.assertTrue(globals.g_utility_script.endswith("/scripts/vacuumscript.sh"))

    def test_19b_utility_script_and_no_utility_interval(self):
        """
        Ensure that config with utility_script but utility_interval == 0 has it disabled.
        """
        self.mangle(change={"utility_script": "../scripts/vacuumscript.sh", "utility_interval": "0"})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(0, globals.g_utility_interval)
        self.assertEqual("", globals.g_utility_script)

    def test_20a_feed_database_dir_not_exists(self):
        """
        Ensure that config with feed database directory that does not exist will create that directory.
        """
        path = os.path.abspath("./no-such-feed-directory")
        if os.path.exists(path):
            os.rmdir(path)
        try:
            self.mangle(change={"feed_database_dir": path})
            ConfigurationInit(TESTCONF, "sample.json")
            self.assertTrue(os.path.exists(path))
        finally:
            if os.path.exists(path):
                os.rmdir(path)

    def test_20b_feed_database_dir_not_directory(self):
        """
        Ensure that config with feed database directory that is not a directory is detected.
        """
        self.mangle(change={"feed_database_dir": TESTCONF})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "is not a directory" in "{0}".format(err.exception.args[0])

    def test_21_config_malformed_parameter(self):
        """
        Ensure that config with malformed parameter is detected
        """
        self.mangle(change={"utility_interval": "1%"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "cannot be parsed" in "{0}".format(err.exception.args[0])

    def test_22a_worker_network_timeout_missing(self):
        """
        Ensure that config with missing worker_network_timeout reverts to default
        """
        check = globals.g_worker_network_timeout

        self.mangle(change={"worker_network_timeout": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_worker_network_timeout)

    def test_22b_worker_network_timeout_empty(self):
        """
        Ensure that config with empty worker_network_timeout reverts to default
        """
        check = globals.g_worker_network_timeout

        self.mangle(change={"worker_network_timeout": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_worker_network_timeout)

    def test_22c_worker_network_timeout_bogus(self):
        """
        Ensure that config with bogus (non-int) worker_network_timeout is detected.
        """
        self.mangle(change={"worker_network_timeout": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_23a_utility_debug_missing(self):
        """
        Ensure that config with missing utility_debug is always false.
        """
        self.mangle(change={"utility_debug": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertFalse(globals.g_utility_debug)

    def test_23b_utility_debug_empty(self):
        """
        Ensure that config with empty utility_debug is always false.
        """
        self.mangle(change={"utility_debug": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertFalse(globals.g_utility_debug)

    def test_23c_utility_debug_bogus(self):
        """
        Ensure that config with bogus (non-bool) utility_debug is detected.
        """
        self.mangle(change={"utility_debug": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "is not a valid boolean value" in "{0}".format(err.exception.args[0])

    def test_23d_utility_debug_empty_global_changed(self):
        """
        Ensure that config with empty utility_debug is always false, even if the globals are altered!
        """
        globals.g_utility_debug = True

        self.mangle(change={"utility_debug": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertFalse(globals.g_utility_debug)

    def test_24a_database_scanning_interval_missing(self):
        """
        Ensure that config with missing database_scanning_interval reverts to default
        """
        check = globals.g_scanning_interval

        self.mangle(change={"database_scanning_interval": None})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_scanning_interval)

    def test_24b_database_scanning_interval_empty(self):
        """
        Ensure that config with empty database_scanning_interval reverts to default
        """
        check = globals.g_scanning_interval

        self.mangle(change={"database_scanning_interval": ""})
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(check, globals.g_scanning_interval)

    def test_24c_database_scanning_interval_bogus(self):
        """
        Ensure that config with bogus (non-int) database_scanning_interval is detected.
        """
        self.mangle(change={"database_scanning_interval": "BOGUS"})
        with self.assertRaises(ValueError) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid literal for int" in "{0}".format(err.exception.args[0])

    def test_24d_database_scanning_interval_below_minimum(self):
        """
        Ensure that config with missing database_scanning_interval reverts to default
        """
        self.mangle(change={"database_scanning_interval": "18"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "'database_scanning_interval' must be greater or equal to 360" in "{0}".format(err.exception.args[0])

    def test_25a_celery_worker_config(self):
        """
        Ensure that basic celery worker config is handled
        """
        ConfigurationInit(TESTCONF, "sample.json")
        self.assertEqual(1, len(globals.g_celeryworkerkwargs))
        self.assertTrue("autoscale" in globals.g_celeryworkerkwargs)
        self.assertEqual("4,4", globals.g_celeryworkerkwargs['autoscale'])

    def test_25b_celery_worker_config_bad_json(self):
        """
        Ensure that basic celery worker config is handled with bad json.
        """
        self.mangle(change={"celery_worker_kwargs": "{BOGUS}"})
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "invalid JSON" in err.exception.args[0]

    def test_25c_celery_worker_config_missing(self):
        """
        Ensure that basic celery worker config is handled when missing
        """
        self.mangle(change={"celery_worker_kwargs": None})
        self.assertEqual(None, globals.g_celeryworkerkwargs)

    # ----- Unknown configuration (typo detection)

    def test_80_unexpected_parameter(self):
        """
        Ensure that config with unexpected parameter (typo?) is flagged
        """
        self.mangle(add=["cb_server=https://localhost"])  # should be "cb_server_url"
        with self.assertRaises(CbInvalidConfig) as err:
            ConfigurationInit(TESTCONF, "sample.json")
        assert "has unknown parameters: ['cb_server']" in "{0}".format(err.exception.args[0])

    # ----- Minimal validation (worker)

    def test_90_minimal_validation_effects(self):
        """
        Ensure that minimal caonfiguration does not set extra globals
        """
        globals.g_postgres_host = None
        ConfigurationInit(TESTCONF)
        self.assertIsNone(globals.g_postgres_host)
