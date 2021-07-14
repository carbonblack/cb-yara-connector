# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import configparser
import json
import logging
import os
import re
from enum import Enum
from typing import List, Optional

from .exceptions import CbInvalidConfig

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

__all__ = ["YaraConnectorConfig"]

################################################################################
# Configuration reader/validator
#
# Note: As of version 2.1.2, some terminology changes have been made that
# affects one configuration parameter, and the values used for the "mode"
# parameter. Some previous terms are now deprecated, but are still honored
# at runtime for compatibility, so that existing configuration files will
# continue to work:
#
#   - the parameter 'worker_network_timeout' is now 'minion_network_timeout'
#   - for the 'mode' parameter, the values "master", "worker" and "master+worker"
#     are now "primary", "minion" and "primary+minion"
#
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
    "minion_network_timeout",
    "yara_rules_dir",
    "log_level",
    "results_backend",
    "celery_app_conf",
    "node_id",
    "module_store_location"
]

MODES = [
    "master", "primary",
    "worker", "minion",
    "master+worker", "primary+minion", "standalone"
]

ALLOWED_LOG_LEVELS = ["VERBOSE", "VERBOSE", 'info',"INFO", 'debug', "DEBUG", 'critical', "CRITICAL", 'warn', 'WARN', 'warning', 'WARNING', 'ERROR']


class YaraConnectorMode(Enum):
    STANDALONE = 1
    PRIMARY = 2
    MINION = 3

    @staticmethod
    def get_mode_from_string(mode_string: str):
        is_primary = False
        is_minion = False
        if 'minion' in mode_string or 'worker' in mode_string:
            is_minion = True
        if 'primary' in mode_string or 'master' in mode_string:
            is_primary = True
        if is_minion and is_primary:
            return YaraConnectorMode.STANDALONE
        elif is_minion:
            return YaraConnectorMode.MINION
        elif is_primary:
            return YaraConnectorMode.PRIMARY
        return YaraConnectorMode.STANDALONE


class YaraConnectorConfig(object):
    """
    Class to deal with all configuration loading and validation.
    """

    def __init__(self, config_file: str, output_file: str = None, load=True) -> None:
        """
        Validate the config file.
        :param config_file: The config file to validate
        :param output_file: the output file; if not specified assume we are a task minion (simplified validation)
        """
        self.abs_config = os.path.abspath(os.path.expanduser(config_file))
        self.source = f"Config file '{self.abs_config}'"
        self.output_file = ""
        self.yara_rule_map = {}
        self.yara_rule_map_hash_list = []

        # configuration
        self.mode = "standalone"

        self.cb_server_url = None
        self.cb_server_token = None
        self.broker_url = None

        self.yara_rules_dir = "./yara_rules"

        self.postgres_host = "127.0.0.1"
        self.postgres_db = "cb"
        self.postgres_username = "cb"
        self.postgres_password = ""
        self.postgres_port = 5002

        self.max_hashes = 8
        self.num_binaries_not_available = 0
        self.num_binaries_analyzed = 0
        self.disable_rescan = True
        self.num_days_binaries = 365

        self.feed_database_dir = "./feed_db"

        self.scanning_interval = 360

        self.utility_interval = 0
        self.utility_script = ""
        self.utility_debug = False  # dev use only, reduces interval from minutes to seconds!

        self.minion_network_timeout = 5

        self.celery_worker_kwargs = None

        self.log_level = "VERBOSE"
        self.operation_mode = YaraConnectorMode.STANDALONE

        self.output_file = output_file

        self.the_config = None
        self.results_backend = None
        self.node_id = None
        self.module_store_location = "/var/cb/data/modulestore"

        self.celery_app_conf = None


        if load:
            self.load_config()

    def load_config(self):

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

        self.mode = self._as_str("mode",
                                 required=False,
                                 default="standalone",
                                 allowed=MODES)

        self.log_level = self._as_str("log_level", required=False, default="INFO",
                                      allowed=ALLOWED_LOG_LEVELS).upper()
        self.operation_mode = YaraConnectorMode.get_mode_from_string(self.mode)

        # do the config checks

        standalone_or_primary = self.operation_mode in [YaraConnectorMode.STANDALONE, YaraConnectorMode.PRIMARY]
        self.node_id = self._as_int("node_id", False, default=0 if standalone_or_primary else -1)
        self.module_store_location = self._as_path("module_store_location", required=False, check_exists=standalone_or_primary, expect_dir=True , default=self.module_store_location)

        if self.operation_mode != YaraConnectorMode.STANDALONE:
            self.celery_app_conf = self._as_json("celery_app_conf", False)

        self._minion_check()

        if self.operation_mode in [YaraConnectorMode.PRIMARY, YaraConnectorMode.STANDALONE]:
            self._primary_check()

    def _minion_check(self) -> None:
        """
        Validate entries used by task minions as well as the main process.

        :raises CbInvalidConfig:
        """
        self.yara_rules_dir = self._as_path("yara_rules_dir", required=True, check_exists=True, expect_dir=True)

        # we need the cb_server_api information whenever required (ie, we are a minion)
        cb_req = False
        if self.operation_mode in [YaraConnectorMode.STANDALONE, YaraConnectorMode.MINION]:
            cb_req = True

        self.cb_server_url = self._as_str("cb_server_url", required=cb_req)
        self.cb_server_token = self._as_str("cb_server_token", required=cb_req)

        self.broker_url = self._as_str("broker_url", required=self.operation_mode != YaraConnectorMode.STANDALONE,
                                       default=None)
        self.results_backend = self._as_str("results_backend", required=False, default=self.broker_url)

        # newer terminology takes precedence
        self.minion_network_timeout = self._as_int("worker_network_timeout",
                                                   default=self.minion_network_timeout)
        self.minion_network_timeout = self._as_int("minion_network_timeout",
                                                   default=self.minion_network_timeout)

        # newer terminology takes precedence
        self.celery_worker_kwargs = self._as_json("celery_worker_kwargs")
        self.celery_worker_kwargs = self._as_json("celery_worker_kwargs")

    def _primary_check(self) -> None:
        """
        Validate entries used by the main process.

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
                            self.postgres_user = "cb"
                            self.postgres_password = matches.group(2) if matches else "NONE"
                            self.postgres_port = 5002
                            self.postgres_db = "cb"
                            self.postgres_host = "127.0.0.1"
                            break
                use_fallback = False  # we good!
            except Exception as err:
                logger.exception(f"Someting went wrong trying to parse /etc/cb/cb.conf for postgres details: {err}")

        if use_fallback:
            logger.debug("Falling back to config settings for postgres...")
            self.postgres_host = self._as_str("postgres_host", default=self.postgres_host)
            self.postgres_username = self._as_str("postgres_username", default=self.postgres_username)
            self.postgres_password = self._as_str("postgres_password", required=True)
            self.postgres_db = self._as_str("postgres_db", default=self.postgres_username)
            self.postgres_port = self._as_int("postgres_port", default=self.postgres_port)

        value = self._as_str("niceness")
        if value != "":
            os.nice(self._as_int("niceness", min_value=0))

        self.max_hashes = self._as_int("concurrent_hashes", default=self.max_hashes)
        self.disable_rescan = self._as_bool("disable_rescan", default=self.disable_rescan)
        self.num_days_binaries = self._as_int("num_days_binaries", default=self.num_days_binaries,
                                              min_value=1)

        self.utility_interval = self._as_int("utility_interval", default=self.utility_interval,
                                             min_value=0)
        if self.utility_interval > 0:
            if self._as_str("utility_script", default=self.utility_script) == "":
                logger.warning(f"{self.source} 'utility_interval' supplied but no script defined -- feature disabled")
                self.utility_interval = 0
                self.utility_script = ""
            else:
                self.utility_script = self._as_path("utility_script", required=True, expect_dir=False,
                                                    default=self.utility_script)
                logger.warning(f"{self.source} utility script '{self.utility_script}' is enabled; " +
                               "use this advanced feature at your own discretion!")
        else:
            if self._as_str("utility_script", required=False, default=self.utility_script) != "":
                logger.debug(f"{self.source} has 'utility_script' defined, but it is disabled")
                self.utility_script = ""

        # developer use only
        self.utility_debug = self._as_bool("utility_debug", default=False)

        self.feed_database_dir = self._as_path("feed_database_dir", required=True, expect_dir=True,
                                               default=self.feed_database_dir, create_if_needed=True)

        if self.output_file is not None and self.output_file != "":
            self.output_file = os.path.abspath(os.path.expanduser(self.output_file))
        else:  # same location as feed db, called "feed.json"
            self.output_file = os.path.join(os.path.dirname(self.feed_database_dir), "feed.json")

        logger.debug(f"NOTE: output file will be '{self.output_file}'")

        self.scanning_interval = self._as_int('database_scanning_interval', default=self.scanning_interval,
                                              min_value=360)

    # ----- Type Handlers ------------------------------------------------------------

    def _as_str(self,
                param: str,
                required: bool = False,
                default: str = "",
                allowed: List[str] = None) -> str:
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

        if required and (value == "" or value == None):
            raise CbInvalidConfig(f"{self.source} has no '{param}' definition")

        if allowed is not None and value not in allowed:
            raise CbInvalidConfig(f"{self.source} does not specify an allowed value: {allowed}")

        return value

    def _as_path(self,
                 param: str,
                 required: bool = False,
                 check_exists: bool = True,
                 expect_dir: bool = False,
                 default: str = "",
                 create_if_needed: bool = False) -> str:
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

    def _as_int(self,
                param: str,
                required: bool = False,
                default: int = -1,
                min_value: int = None) -> int:
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
    def _as_bool(self,
                 param: str,
                 required: bool = False,
                 default: bool = False) -> Optional[bool]:
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
    def _as_json(self,
                 param: str,
                 required: bool = False) -> Optional[dict]:
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
