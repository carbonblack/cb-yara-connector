# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import configparser
import json
import logging
import os
import re
from typing import List, Optional

import globals
from celery_app import app
from exceptions import CbInvalidConfig

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

__all__ = ["ConfigurationInit"]

################################################################################
# Configuration reader/validator
################################################################################

# Known parameters -- flag others as potential typos!
KNOWN = [
    "broker_url",
    "cb_server_token",
    "cb_server_url",
    "celery_worker_kwargs",
    "concurrent_hashes",
    "database_scanning_interval",
    "disable_rescan",
    "feed_database_dir",
    "mode",
    "niceness",
    "num_days_binaries",
    "postgres_db",
    "postgres_host",
    "postgres_password",
    "postgres_port",
    "postgres_username",
    "utility_debug",  # developer use only!
    "utility_interval",
    "utility_script",
    "worker_network_timeout",
    "yara_rules_dir",
]


class ConfigurationInit(object):
    """
    Class to deal with all configuration loading and validation.
    """

    def __init__(self, config_file: str, output_file: str = None, **kwargs) -> None:
        """
        Validate the config file.
        :param config_file: The config file to validate
        :param output_file: the output file; if not specified assume we are a task worker (simplified validation)
        """
        self.abs_config = os.path.abspath(os.path.expanduser(config_file))
        self.source = f"Config file '{self.abs_config}'"

        config = configparser.ConfigParser()
        if not os.path.exists(self.abs_config):
            raise CbInvalidConfig(f"{self.source} does not exist!")
        if os.path.isdir(self.abs_config):
            raise CbInvalidConfig(f"{self.source} is a directory!")

        try:
            config.read(self.abs_config)
        except Exception as err:
            raise CbInvalidConfig(err)

        logger.debug(f"NOTE: using config file '{self.abs_config}'")
        if not config.has_section("general"):
            raise CbInvalidConfig(f"{self.source} does not have a 'general' section")
        self.the_config = config["general"]

        # if testing core methods, get out now
        if "TESTING_ONLY" in kwargs:
            return

        # warn about unknown parameters -- typos?
        extras = []
        try:
            for item in config.items("general"):
                if item[0] not in KNOWN:
                    extras.append(item[0])
            if len(extras) > 0:
                raise CbInvalidConfig(f"{self.source} has unknown parameters: {extras}")
        except configparser.InterpolationSyntaxError as err:
            raise CbInvalidConfig(f"{self.source} cannot be parsed: {err}")

        globals.g_mode = self._as_str("mode", required=False, default="master",
                                      allowed=["master", "worker", "master+worker"])

        # do the config checks
        self._worker_check()

        if globals.g_mode in ["master", "master+worker"]:
            self._master_check(output_file)

    def _worker_check(self) -> None:
        """
        Validate entries used by task workers as well as the main process.

        :raises CbInvalidConfig:
        """
        globals.g_yara_rules_dir = self._as_path("yara_rules_dir", required=True, check_exists=True, expect_dir=True)

        # we need the cb_server_api information whenever  required (ie, we are a worker)
        cb_req = "worker" in globals.g_mode or "master+worker" in globals.g_mode

        globals.g_cb_server_url = self._as_str("cb_server_url", required=cb_req)
        globals.g_cb_server_token = self._as_str("cb_server_token", required=cb_req)

        value = self._as_str("broker_url", required=True)
        app.conf.update(broker_url=value, result_backend=value)

        globals.g_worker_network_timeout = self._as_int("worker_network_timeout",
                                                        default=globals.g_worker_network_timeout)
        globals.g_celeryworkerkwargs = self._as_json("celery_worker_kwargs")

    def _master_check(self, output_file) -> None:
        """
        Validate entries used by the main process.

        :param output_file: output file location from command line
        :raises CbInvalidConfig:
        :raises ValueError:
        """
        use_fallback = True
        if os.path.isfile('/etc/cb/cb.conf'):
            logger.debug("Found local 'cb.conf', attempting to configure postgres from it...")
            try:
                with open('/etc/cb/cb.conf') as cbconffile:
                    for line in cbconffile.readlines():
                        if line.startswith("DatabaseURL="):
                            dbregex = r"DatabaseURL=postgresql\+psycopg2:\/\/(.+):(.+)@localhost:(\d+)/(.+)"
                            matches = re.match(dbregex, line)
                            globals.g_postgres_user = "cb"
                            globals.g_postgres_password = matches.group(2) if matches else "NONE"
                            globals.g_postgres_port = 5002
                            globals.g_postgres_db = "cb"
                            globals.g_postgres_host = "127.0.0.1"
                            break
                use_fallback = False  # we good!
            except Exception as err:
                logger.exception(f"Someting went wrong trying to parse /etc/cb/cb.conf for postgres details: {err}")

        if use_fallback:
            logger.debug("Falling back to config settings for postgres...")
            globals.g_postgres_host = self._as_str("postgres_host", default=globals.g_postgres_host)
            globals.g_postgres_username = self._as_str("postgres_username", default=globals.g_postgres_username)
            globals.g_postgres_password = self._as_str("postgres_password", required=True)
            globals.g_postgres_db = self._as_str("postgres_db", default=globals.g_postgres_username)
            globals.g_postgres_port = self._as_int("postgres_port", default=globals.g_postgres_port)

        value = self._as_str("niceness")
        if value != "":
            os.nice(self._as_int("niceness", min_value=0))

        globals.g_max_hashes = self._as_int("concurrent_hashes", default=globals.g_max_hashes)
        globals.g_disable_rescan = self._as_bool("disable_rescan", default=globals.g_disable_rescan)
        globals.g_num_days_binaries = self._as_int("num_days_binaries", default=globals.g_num_days_binaries,
                                                   min_value=1)

        globals.g_utility_interval = self._as_int("utility_interval", default=globals.g_utility_interval,
                                                  min_value=0)
        if globals.g_utility_interval > 0:
            if self._as_str("utility_script", default=globals.g_utility_script) == "":
                logger.warning(f"{self.source} 'utility_interval' supplied but no script defined -- feature disabled")
                globals.g_utility_interval = 0
                globals.g_utility_script = ""
            else:
                globals.g_utility_script = self._as_path("utility_script", required=True, expect_dir=False,
                                                         default=globals.g_utility_script)
                logger.warning(f"{self.source} utility script '{globals.g_utility_script}' is enabled; " +
                               "use this advanced feature at your own discretion!")
        else:
            if self._as_str("utility_script", required=False, default=globals.g_utility_script) != "":
                logger.debug(f"{self.source} has 'utility_script' defined, but it is disabled")
                globals.g_utility_script = ""

        # developer use only
        globals.g_utility_debug = self._as_bool("utility_debug", default=False)

        globals.g_feed_database_dir = self._as_path("feed_database_dir", required=True, expect_dir=True,
                                                    default=globals.g_feed_database_dir, create_if_needed=True)

        if output_file is not None and output_file != "":
            globals.g_output_file = os.path.abspath(os.path.expanduser(output_file))
        else:  # same location as feed db, called "feed.json"
            globals.g_output_file = os.path.join(os.path.dirname(globals.g_feed_database_dir), "feed.json")

        logger.debug(f"NOTE: output file will be '{globals.g_output_file}'")

        globals.g_scanning_interval = self._as_int('database_scanning_interval', default=globals.g_scanning_interval,
                                                   min_value=360)

    # ----- Type Handlers ------------------------------------------------------------

    def _as_str(self, param: str, required: bool = False, default: str = "", allowed: List[str] = None) -> str:
        """
        Get a string parameter from the configuration.

        NOTE: This is the base for all other parameter getting functions, so changes here will affect them as well!

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :param default: default value if not supplied
        :return: the string value, or default if not required and no exception
        :raises CbInvalidConfig:
        """
        try:
            value = self.the_config.get(param, default)
            value = "" if value is None else value.strip()
            if value == "":
                value = default  # patch for supplied empty string
        except Exception as err:
            raise CbInvalidConfig(f"{self.source} parameter '{param}' cannot be parsed: {err}")

        if required and value == "":
            raise CbInvalidConfig(f"{self.source} has no '{param}' definition")

        if allowed is not None and value not in allowed:
            raise CbInvalidConfig(f"{self.source} does not specify an allowed value: {allowed}")

        return value

    def _as_path(self, param: str, required: bool = False, check_exists: bool = True, expect_dir: bool = False,
                 default: str = "", create_if_needed: bool = False) -> str:
        """
        Get a string parameter from the configuration and treat it as a path, performing normalization
        to produce an absolute path.  a "~/" at the beginning will be treated as the current user's home
        directory.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :param default: If not required, default value if not supplied
        :param check_exists: if True, check for existance
        :param expect_dir: if exists and True, target must be a directory
        :param create_if_needed: if True and we expect a directory, create if it does not exist
        :return: the path value, or empty string if not required and no exception
        :raises CbInvalidConfig:
        """
        value = self._as_str(param, required=required, default=default)

        if value == "":  # not required and not specified
            return value
        else:
            value = os.path.abspath(os.path.expanduser(value))
            if check_exists:
                if os.path.exists(value):  # path exists
                    if expect_dir and not os.path.isdir(value):
                        raise CbInvalidConfig(f"{self.source} specified path '{param}' ({value}) is not a directory")
                    elif not expect_dir and os.path.isdir(value):
                        raise CbInvalidConfig(f"{self.source} specified path '{param}' ({value}) is a directory")
                else:  # does not exist
                    if create_if_needed and expect_dir:
                        try:
                            os.makedirs(value)
                        except Exception as err:
                            raise CbInvalidConfig(f"{self.source} unable to create '{value}' for '{param}': {err}")
                    else:
                        raise CbInvalidConfig(
                            f"{self.source} specified path parameter '{param}' ({value}) does not exist")
            return value

    def _as_int(self, param: str, required: bool = False, default: int = -1, min_value: int = None) -> int:
        """
        Get an integer configuration parameter from the configuration.  A parameter that cannot be converted
        to an int will return a ValueError.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :param default: If not required, default value if not supplied
        :param min_value: minumum value allowed
        :return: the integer value, or default if not required and no exception
        :raises CbInvalidConfig:
        :raises ValueError:
        """
        self._as_str(param, required=required)  # required check
        value = int(self._as_str(param, required=required, default=str(default)))
        if min_value is not None and value < min_value:
            raise CbInvalidConfig(f"{self.source} '{param}' must be greater or equal to {min_value}")
        return value

    # noinspection PySameParameterValue
    def _as_bool(self, param: str, required: bool = False, default: bool = False) -> Optional[bool]:
        """
        Get a boolean configuration parameter from the configuration.  A parameter not one of
        ["true", "yes", "false", "no"] will return a ValueError.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :return: the boolean value, or False if not required and no exception
        :raises CbInvalidConfig:
        :raises ValueError:
        """
        self._as_str(param, required=required)  # required check
        value = self._as_str(param, required=required, default=str(default))
        if value is not None and value.lower() not in ["true", "yes", "false", "no"]:
            raise ValueError(f"{self.source} parameter '{param}' is not a valid boolean value")
        if value is None and default is not None:
            logger.warning(f"{self.source} has no defined '{param}'; using default of '{default}'")
            return default
        else:
            return value if value is None else value.lower() in ["true", "yes"]

    # noinspection PySameParameterValue
    def _as_json(self, param: str, required: bool = False) -> Optional[dict]:
        """
        Get a single-line JSON string and convert to a python dict for use as a kwargs.
        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :return: dictionary converstion, or None if not required and not supplied
        """
        value = self._as_str(param, required=required)  # required check
        if value == "":
            return None

        try:
            return json.loads(value)
        except Exception as err:
            raise CbInvalidConfig(f"{self.source} '{param}' has invalid JSON: {err}")
