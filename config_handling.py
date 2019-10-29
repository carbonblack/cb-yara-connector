# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import configparser
import logging
import os
from typing import Optional

from celery import Celery

import globals
from exceptions import CbInvalidConfig
from utilities import placehold

logger = logging.getLogger(__name__)

__all__ = ["ConfigurationInit", "app"]

################################################################################
# Celery app
################################################################################

app = Celery()
# noinspection PyUnusedName
app.conf.task_serializer = "pickle"
# noinspection PyUnusedName
app.conf.result_serializer = "pickle"
# noinspection PyUnusedName
app.conf.accept_content = {"pickle"}


################################################################################
# Configuration reader/validator
################################################################################

class ConfigurationInit(object):
    """
    Class to deal with all configuration loading and validation.
    """

    def __init__(self, config_file: str, output_file: str = None) -> None:
        """
        Validate the config file.
        :param config_file: The config file to validate
        :param output_file: the output file; if not specified assume we are a task worker (simplified validation)
        """
        self.abs_config = os.path.abspath(os.path.expanduser(placehold(config_file)))
        self.source = f"Config file '{self.abs_config}'"

        config = configparser.ConfigParser()
        if not os.path.exists(config_file):
            raise CbInvalidConfig(f"{self.source} does not exist!")

        try:
            config.read(config_file)
        except Exception as err:
            raise CbInvalidConfig(err)

        logger.debug(f"NOTE: using config file '{self.abs_config}'")
        if not config.has_section("general"):
            raise CbInvalidConfig(f"{self.source} does not have a 'general' section")
        self.the_config = config["general"]

        self._worker_check()

        if output_file is not None:
            globals.g_output_file = os.path.abspath(os.path.expanduser(placehold(output_file)))
            logger.debug(f"NOTE: output file will be '{globals.g_output_file}'")
            self._extended_check()

    def _worker_check(self) -> None:
        """
        Validate entries used by task workers as well as the main process.

        :raises CbInvalidConfig:
        """
        value = self._as_str("worker_type", default="local")
        if value == "local":
            globals.g_remote = False
        elif value == "remote":
            globals.g_remote = True
        else:
            raise CbInvalidConfig(f"{self.source} has an invalid 'worker_type' ({value})")

        globals.g_yara_rules_dir = self._as_path("yara_rules_dir", required=True, exists=True, is_dir=True)

        # local/remote configuration data
        if not globals.g_remote:
            globals.g_cb_server_url = self._as_str("cb_server_url", required=True)
            globals.g_cb_server_token = self._as_str("cb_server_token", required=True)
        else:
            value = self._as_str("broker_url", required=True)
            app.conf.update(broker_url=value, result_backend=value)

    def _extended_check(self) -> None:
        """
        Validate entries used by the main process.

        :raises CbInvalidConfig:
        :raises ValueError:
        """

        # TODO: validate url & token with test call (if local)
        # TODO: validate broker with test call (if remote)

        globals.g_postgres_host = self._as_str("postgres_host", default=globals.g_postgres_host)
        globals.g_postgres_username = self._as_str("postgres_username", default=globals.g_postgres_username)
        globals.g_postgres_password = self._as_str("postgres_password", required=True)
        globals.g_postgres_db = self._as_str("postgres_db", default=globals.g_postgres_username)
        globals.g_postgres_port = self._as_int("postgres_port", default=globals.g_postgres_port)

        # TODO: validate postgres connection with supplied information?

        value = self._as_int("niceness")
        if value:
            os.nice(value)

        globals.g_max_hashes = self._as_int("concurrent_hashes", default=globals.g_max_hashes)
        globals.g_disable_rescan = self._as_bool("disable_rescan", default=globals.g_disable_rescan)
        globals.g_num_days_binaries = self._as_int("num_days_binaries", default=globals.g_num_days_binaries,
                                                   min_value=1)

        globals.g_vacuum_seconds = self._as_int("vacuum_seconds", default=globals.g_vacuum_seconds, min_value=0)
        if globals.g_vacuum_seconds > 0:
            globals.g_vacuum_script = self._as_path("vacuum_script", required=True, is_dir=False,
                                                    default=globals.g_vacuum_script)
            logger.warning(f"Vacuum Script '{globals.g_vacuum_script}' is enabled; " +
                           "use this advanced feature at your own discretion!")
        else:
            if self._as_path("vacuum_script", required=False, default=globals.g_vacuum_script):
                logger.debug(f"{self.source} has 'vacuum_script' defined, but it is disabled")

        globals.g_feed_database_dir = self._as_path("feed_database_dir", required=True, is_dir=True,
                                                    default=globals.g_feed_database_dir)

    # ----- Type Handlers

    def _as_str(self, param: str, required: bool = False, default: str = None) -> Optional[str]:
        """
        Get a string parameter from the configuration.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :param default: If not required, default value if not supplied
        :return: the string value, or None/default if not required and no exception
        :raises CbInvalidConfig:
        """
        value = self.the_config.get(param, None)
        if value is not None:
            value = value.strip()
        if (value is None or value == "") and default is not None:
            value = default
            logger.warning(f"{self.source} has no defined '{param}'; using default of '{default}'")
        if required and (value is None or value == ""):
            raise CbInvalidConfig(f"{self.source} has no '{param}' definition")
        return value

    def _as_path(self, param: str, required: bool = False, exists: bool = True, is_dir: bool = False,
                 default: str = None) -> Optional[str]:
        """
        Get an string parameter from the configuration and treat it as a path, performing normalization
        to produce an absolute path.  a "~" at the beginning will be treated as the current user's home
        directory; the placeholder "{YARA}" will be treated as the location of your yara package directory.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :param exists: if True and required, check for existance as well
        :param is_dir: if exists and True, source must be a directory
        :param default: If not required, default value if not supplied
        :return: the integer value, or None if not required and no exception
        :raises CbInvalidConfig:
        """
        value = self._as_str(param, required, default=default)
        if value is None:
            return value

        value = os.path.abspath(os.path.expanduser(placehold(value)))
        if exists:
            if not os.path.exists(value):
                raise CbInvalidConfig(f"{self.source} specified path parameter '{param}' ({value}) does not exist")
            if is_dir:
                if not os.path.isdir(value):
                    raise CbInvalidConfig(f"{self.source} specified path '{param}' ({value}) is not a directory")
            else:
                if os.path.isdir(value):
                    raise CbInvalidConfig(f"{self.source} specified path '{param}' ({value}) is a directory")

        return value

    def _as_int(self, param: str, required: bool = False, default: int = None, min_value: int = -1) -> Optional[int]:
        """
        Get an integer configuration parameter from the configuration.  A parameter that cannot be converted
        to an int will return a ValueError.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :param default: If not required, default value if not supplied
        :param min_value: minumum value allowed
        :return: the integer value, or None/default if not required and no exception
        :raises CbInvalidConfig:
        :raises ValueError:
        """
        value = self._as_str(param, required)
        use_default = default if default is None else max(default, min_value)
        if (value is None or value == "") and use_default is not None:
            logger.warning(f"{self.source} has no defined '{param}'; using default of '{use_default}'")
            return use_default
        else:
            return None if (value is None or value == "") else max(int(value), min_value)

    # noinspection PySameParameterValue
    def _as_bool(self, param: str, required: bool = False, default: bool = None) -> Optional[bool]:
        """
        Get a boolean configuration parameter from the configuration.  A parameter not one of
        ["true", "yes", "false", "no"] will return a ValueError.

        :param param: Name of the configuration parameter
        :param required: True if this must be specified in the configuration
        :return: the boolean value, or None if not required and no exception
        :raises CbInvalidConfig:
        :raises ValueError:
        """
        value = self._as_str(param, required)
        if value is not None and value.lower() not in ["true", "yes", "false", "no", ""]:
            raise ValueError(f"{self.source} parameter '{param}' is not a valid boolean value")
        if value is None and default is not None:
            logger.warning(f"{self.source} has no defined '{param}'; using default of '{default}'")
            return default
        else:
            return value if value is None else value.lower() in ["true", "yes"]
