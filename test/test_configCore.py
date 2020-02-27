# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import os
import shutil
from typing import Union
from unittest import TestCase

from config_handling import ConfigurationInit
from exceptions import CbInvalidConfig

TESTS = os.path.abspath(os.path.dirname(__file__))
JUNK = os.path.join(TESTS, "test-artifacts")
TESTCONF = os.path.join(JUNK, "conf-testing.conf")


class TestConfigurationCore(TestCase):

    def setUp(self) -> None:
        """
        Reset globals and recreate a base configuration.
        :return:
        """
        if os.path.exists(JUNK):
            shutil.rmtree(JUNK)
        os.makedirs(JUNK)

    def tearDown(self) -> None:
        """
        Cleanup after testing.
        """
        if os.path.exists(JUNK):
            shutil.rmtree(JUNK)

    @staticmethod
    def config(value: Union[int, str, bool] = None) -> ConfigurationInit:
        """
        Create a test config file with the TESTME test param.
        :param value: value to be used; if None, it won't exist.
        """
        with open(TESTCONF, "w") as fp:
            fp.write("[general]\n")
            if value is not None:
                fp.write("TESTME={0}".format(value))

        return ConfigurationInit(TESTCONF, TESTING_ONLY=True)

    @staticmethod
    def makedir(name: str) -> str:
        """
        Make directory for testing.
        :param name: directory name to be created
        """
        real_path = os.path.join(JUNK, name)
        os.makedirs(real_path)
        return real_path

    @staticmethod
    def makefile(name: str) -> str:
        """
        Make file for testing.
        :param name: file name to be created
        """
        real_path = os.path.join(JUNK, name)
        with open(real_path, "w") as fp:
            fp.write("OK")
            fp.flush()
        return real_path

    # ----- Begin Tests ----------------------------------------------------------------------

    def test_01a_as_str_default(self):
        """
        Validate _as_str when no value specified (use default)
        """
        cfg = self.config()

        value = cfg._as_str("TESTME")
        self.assertEqual("", value)

    def test_01b_as_str_changed_default(self):
        """
        Validate _as_str when no value specified (use new default)
        """
        cfg = self.config()

        value = cfg._as_str("TESTME", default="changed")
        self.assertEqual("changed", value)

    def test_01c_as_str_value(self):
        """
        Validate _as_str when value specified.
        """
        cfg = self.config("ok")

        value = cfg._as_str("TESTME")
        self.assertEqual("ok", value)

    def test_01d_as_str_required(self):
        """
        Validate _as_str when no value specified but is required.
        """
        cfg = self.config()

        with self.assertRaises(CbInvalidConfig):
            cfg._as_str("TESTME", required=True)

    def test_01e_as_str_value_not_in_allowed(self):
        """
        Validate _as_str when value specified but not in allowed values.
        """
        cfg = self.config("okay")

        with self.assertRaises(CbInvalidConfig):
            cfg._as_str("TESTME", allowed=["allowed"])

    def test_01f_as_str_value_in_allowed(self):
        """
        Validate _as_str when value specified.
        """
        cfg = self.config("ok")

        value = cfg._as_str("TESTME", allowed=["okay", "ok"])
        self.assertEqual("ok", value)

    def test_02a_as_int_default(self):
        """
        Validate _as_int when no value specified (use default)
        """
        cfg = self.config()

        value = cfg._as_int("TESTME")
        self.assertEqual(-1, value)

    def test_02b_as_int_changed_default(self):
        """
        Validate _as_int when no value specified (use new default)
        """
        cfg = self.config()

        value = cfg._as_int("TESTME", default=10)
        self.assertEqual(10, value)

    def test_02c_as_int_value(self):
        """
        Validate _as_int when value specified.
        """
        cfg = self.config(20)

        value = cfg._as_int("TESTME")
        self.assertEqual(20, value)

    def test_02d_as_int_required(self):
        """
        Validate _as_int when no value specified but is required.
        """
        cfg = self.config()

        with self.assertRaises(CbInvalidConfig):
            cfg._as_int("TESTME", required=True)

    def test_02e_as_int_value_below_minimum(self):
        """
        Validate _as_int when value specified but is below the allowed minimum.
        """
        cfg = self.config(5)

        with self.assertRaises(CbInvalidConfig):
            cfg._as_int("TESTME", min_value=10)

    def test_02f_as_int_value_at_minimum(self):
        """
        Validate _as_int when value specified but is at the allowed minimum.
        """
        cfg = self.config(5)

        value = cfg._as_int("TESTME", min_value=5)
        self.assertEqual(5, value)

    def test_02g_as_int_value_above_minimum(self):
        """
        Validate _as_int when value specified but is above the allowed minimum.
        """
        cfg = self.config(10)

        value = cfg._as_int("TESTME", min_value=5)
        self.assertEqual(10, value)

    def test_03a_as_bool_default(self):
        """
        Validate _as_bool when no value specified (use default)
        """
        cfg = self.config()

        value = cfg._as_bool("TESTME")
        self.assertEqual(False, value)

    def test_03b_as_bool_changed_default(self):
        """
        Validate _as_bool when no value specified (use new default)
        """
        cfg = self.config()

        value = cfg._as_bool("TESTME", default=True)
        self.assertEqual(True, value)

    def test_03c_as_bool_value(self):
        """
        Validate _as_bool when value specified.
        """
        cfg = self.config(True)

        value = cfg._as_bool("TESTME")
        self.assertEqual(True, value)

    def test_03d_as_bool_required(self):
        """
        Validate _as_bool when no value specified but is required.
        """
        cfg = self.config()

        with self.assertRaises(CbInvalidConfig):
            cfg._as_bool("TESTME", required=True)

    def test_04a_as_path_default(self):
        """
        Validate _as_path when no value specified (use default)
        """
        cfg = self.config()

        value = cfg._as_path("TESTME")
        self.assertEqual("", value)

    def test_04b_as_path_changed_default(self):
        """
        Validate _as_path when no value specified (use new default)
        """
        cfg = self.config()

        value = cfg._as_path("TESTME", default="/tmp", check_exists=False)
        self.assertEqual("/tmp", value)

    def test_04c_as_path_required(self):
        """
        Validate _as_path when no value specified but is required.
        """
        cfg = self.config()

        with self.assertRaises(CbInvalidConfig):
            cfg._as_bool("TESTME", required=True)

    def test_04d_as_path_specified_not_exists(self):
        """
        Validate _as_path when supplied path does not exist
        """
        cfg = self.config("NOSUCH")

        with self.assertRaises(CbInvalidConfig):
            cfg._as_path("TESTME", check_exists=True)

    def test_04e_as_path_specified_check_exists_dir(self):
        """
        Validate _as_path when supplied path resolves to a directory and we expect a directory
        """
        path = self.makedir("CREATED-04e")
        cfg = self.config(path)

        value = cfg._as_path("TESTME", check_exists=True, expect_dir=True)
        self.assertEqual(path, value)

    def test_04f_as_path_specified_check_exists_dir_but_is_file(self):
        """
        Validate _as_path when supplied path resolves to a file and we expect a directory
        """
        path = self.makefile("CREATED-04f")
        cfg = self.config(path)

        with self.assertRaises(CbInvalidConfig):
            cfg._as_path("TESTME", check_exists=True, expect_dir=True)

    def test_04g_as_path_specified_check_exists_file(self):
        """
        Validate _as_path when supplied path resolves to a file and we expect a file.
        """
        path = self.makefile("CREATED-04g")
        cfg = self.config(path)

        value = cfg._as_path("TESTME", check_exists=True, expect_dir=False)
        self.assertEqual(path, value)

    def test_04h_as_path_specified_check_exists_file_but_is_dir(self):
        """
        Validate _as_path when supplied path resolves to a directory and we expect a directory
        """
        path = self.makedir("CREATED-04h")
        cfg = self.config(path)

        with self.assertRaises(CbInvalidConfig):
            cfg._as_path("TESTME", check_exists=True, expect_dir=False)

    def test_04i_as_path_specified_check_exists_create_if_needed_dir(self):
        """
        Validate _as_path when supplied path does not exist but we specify create_if_needed.
        """
        path = os.path.join(JUNK, "CREATED-04i")
        cfg = self.config(path)

        value = cfg._as_path("TESTME", check_exists=True, expect_dir=True, create_if_needed=True)
        self.assertEqual(path, value)

    def test_04j_as_path_specified_check_exists_create_if_needed_file(self):
        """
        Validate _as_path when supplied path does not exist but we can't create if need if we are expecting a file.
        """
        path = os.path.join(JUNK, "CREATED-04j")
        cfg = self.config(path)

        with self.assertRaises(CbInvalidConfig):
            cfg._as_path("TESTME", check_exists=True, expect_dir=False, create_if_needed=True)
