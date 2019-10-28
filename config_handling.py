# coding: utf-8
# Copyright © 2018-2019 VMware, Inc. All Rights Reserved.

import configparser
import logging
import os

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
        abs_config = os.path.abspath(os.path.expanduser(placehold(config_file)))
        header = f"Config file '{abs_config}'"

        config = configparser.ConfigParser()
        if not os.path.exists(config_file):
            raise CbInvalidConfig(f"{header} does not exist!")

        try:
            config.read(config_file)
        except Exception as err:
            raise CbInvalidConfig(err)

        logger.debug(f"NOTE: using config file '{abs_config}'")
        if not config.has_section("general"):
            raise CbInvalidConfig(f"{header} does not have a 'general' section")

        if output_file is not None:
            globals.g_output_file = os.path.abspath(os.path.expanduser(placehold(output_file)))
            logger.debug(f"NOTE: output file will be '{globals.g_output_file}'")

        the_config = config["general"]
        if "worker_type" in the_config:
            if (
                    the_config["worker_type"] == "local"
                    or the_config["worker_type"].strip() == ""
            ):
                globals.g_remote = False  # 'local' or empty definition
            elif the_config["worker_type"] == "remote":
                globals.g_remote = True  # 'remote'
            else:  # anything else
                raise CbInvalidConfig(
                    f"{header} has an invalid 'worker_type' ({the_config['worker_type']})"
                )
        else:
            globals.g_remote = False
            logger.warning(f"{header} does not specify 'worker_type', assuming local")

        if "yara_rules_dir" in the_config and the_config["yara_rules_dir"].strip() != "":
            check = os.path.abspath(os.path.expanduser(placehold(the_config["yara_rules_dir"])))
            if os.path.exists(check):
                if os.path.isdir(check):
                    globals.g_yara_rules_dir = check
                else:
                    raise CbInvalidConfig(
                        f"{header} specified 'yara_rules_dir' ({check}) is not a directory"
                    )
            else:
                raise CbInvalidConfig(
                    f"{header} specified 'yara_rules_dir' ({check}) does not exist"
                )
        else:
            raise CbInvalidConfig(f"{header} has no 'yara_rules_dir' definition")

        # local/remote configuration data
        if not globals.g_remote:
            if "cb_server_url" in the_config and the_config["cb_server_url"].strip() != "":
                globals.g_cb_server_url = the_config["cb_server_url"]
            else:
                raise CbInvalidConfig(f"{header} is 'local' and missing 'cb_server_url'")
            if (
                    "cb_server_token" in the_config
                    and the_config["cb_server_token"].strip() != ""
            ):
                globals.g_cb_server_token = the_config["cb_server_token"]
            else:
                raise CbInvalidConfig(f"{header} is 'local' and missing 'cb_server_token'")
        else:
            if "broker_url" in the_config and the_config["broker_url"].strip() != "":
                app.conf.update(
                    broker_url=the_config["broker_url"],
                    result_backend=the_config["broker_url"],
                )
            else:
                raise CbInvalidConfig(f"{header} is 'remote' and missing 'broker_url'")

        # done with minimal task worker validation
        if output_file is None:
            return

        # TODO: validate url & token with test call (if local)
        # TODO: validate broker with test call (if remote)

        # NOTE: postgres_host has a default value in globals; use and warn if not defined
        if "postgres_host" in the_config and the_config["postgres_host"].strip() != "":
            globals.g_postgres_host = the_config["postgres_host"]
        else:
            logger.warning(
                f"{header} has no defined 'postgres_host'; using default of '{globals.g_postgres_host}'"
            )

        # NOTE: postgres_username has a default value in globals; use and warn if not defined
        if "postgres_username" in the_config and the_config["postgres_username"].strip() != "":
            globals.g_postgres_username = the_config["postgres_username"]
        else:
            logger.warning(
                f"{header} has no defined 'postgres_username'; using default of '{globals.g_postgres_username}'")

        if "postgres_password" in the_config and the_config["postgres_password"].strip() != "":
            globals.g_postgres_password = the_config["postgres_password"]
        else:
            raise CbInvalidConfig(f"{header} has no 'postgres_password' defined")

        # NOTE: postgres_db has a default value in globals; use and warn if not defined
        if "postgres_db" in the_config and the_config["postgres_db"].strip() != "":
            globals.g_postgres_db = the_config["postgres_db"]
        else:
            logger.warning(f"{header} has no defined 'postgres_db'; using default of '{globals.g_postgres_db}'")

        # NOTE: postgres_port has a default value in globals; use and warn if not defined
        if "postgres_port" in the_config:
            globals.g_postgres_port = int(the_config["postgres_port"])
        else:
            logger.warning(f"{header} has no defined 'postgres_port'; using default of '{globals.g_postgres_port}'")

        # TODO: validate postgres connection with supplied information?

        if "niceness" in the_config:
            os.nice(int(the_config["niceness"]))

        if "concurrent_hashes" in the_config:
            globals.g_max_hashes = int(the_config["concurrent_hashes"])
            logger.debug("Consurrent Hashes: {0}".format(globals.g_max_hashes))

        if "disable_rescan" in the_config:
            globals.g_disable_rescan = bool(the_config["disable_rescan"])
            logger.debug("Disable Rescan: {0}".format(globals.g_disable_rescan))

        if "num_days_binaries" in the_config:
            globals.g_num_days_binaries = max(int(the_config["num_days_binaries"]), 1)
            logger.debug(
                "Number of days for binaries: {0}".format(globals.g_num_days_binaries)
            )

        if "vacuum_seconds" in the_config:
            globals.g_vacuum_seconds = max(int(the_config["vacuum_seconds"]), 0)

            if "vacuum_script" in the_config and the_config["vacuum_script"].strip() != "":
                check = os.path.abspath(os.path.expanduser(placehold(the_config["vacuum_script"])))
            else:
                check = os.path.abspath(os.path.expanduser(placehold(globals.g_vacuum_script)))

            if globals.g_vacuum_seconds > 0:
                if os.path.exists(check):
                    if os.path.isdir(check):
                        raise CbInvalidConfig(f"{header} specified 'vacuum_script' ({check}) is a directory")
                else:
                    raise CbInvalidConfig(f"{header} specified 'vacuum_script' ({check}) does not exist")
                globals.g_vacuum_script = check
                logger.warning(f"Vacuum Script '{check}' is enabled; use this advanced feature at your own discretion!")
            else:
                logger.debug(f"{header} has 'vacuum_script' defined, but it is disabled")

        if "feed_database_dir" in the_config and the_config["feed_database_dir"].strip() != "":
            check = os.path.abspath(os.path.expanduser(placehold(the_config["feed_database_dir"])))
            if os.path.exists(check):
                if not os.path.isdir(check):
                    raise CbInvalidConfig(f"{header} specified 'feed_database_dir' ({check}) is not a directory")
                else:
                    globals.g_feed_database_dir = check
            else:
                raise CbInvalidConfig(f"{header} specified 'feed_database_dir' ({check}) does not exist")
        else:
            # we assume the default is correct, sanitize
            globals.g_feed_database_dir = os.path.abspath(os.path.expanduser(placehold(globals.g_feed_database_dir)))
