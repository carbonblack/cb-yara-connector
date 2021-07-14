# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import argparse
import logging
# noinspection PyUnresolvedReferences
import mmap  # NEEDED FOR RPM BUILD
import sys

from .config_handling import YaraConnectorConfig
from .loggers import logger, handle_logging
from .rule_handling import validate_yara_rules
from .yaraconnector import YaraConnector


# noinspection PyPackageRequirements
# noinspection PyPackageRequirements


################################################################################
# Main entrypoint
################################################################################


def handle_arguments():
    """
    Setup the main program options.

    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description="Yara Agent for Yara Connector")

    # Controls config file (ini)
    parser.add_argument(
        "--config-file", default="yaraconnector.conf", help="location of the config file", required=True,
    )
    # Controls log file location+name
    parser.add_argument(
        "--log-file", default="cb-yara-connector.log", help="file location for log output"
    )
    # Controls the output feed location+name
    parser.add_argument(
        "--output-file", default=None, help="file location for feed file"
    )
    # Controls the working directory
    parser.add_argument(
        "--working-dir", default=".", help="working directory"
    )
    # Controls the pid File
    parser.add_argument(
        "--pid-file", default="", help="pid file location - if not supplied, will not write a pid file"
    )

    group = parser.add_mutually_exclusive_group()
    # Controls if we run in daemon mode
    group.add_argument(
        "--daemon", action='store_true', help="run in daemon mode (run as a service)"
    )
    # Validates the rules
    group.add_argument(
        "--validate-yara-rules", action="store_true", help="only validate the yara rules, then exit"
    )

    parser.add_argument("--debug", action="store_true", help="enabled debug level logging")

    return parser.parse_args()


def run():
    """
    Main execution function.  Script will exit with a non-zero value based on the following:
        1: Configuration problem
        2: Yara rule validation problem
        3: User interrupt
        4: Unexpected Yara scan exception
    """
    args = handle_arguments()

    # check for extended logging
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Verify the configuration file and load up important global variables
    try:
        config = YaraConnectorConfig(args.config_file, args.output_file)
        # check for additional log file
        if args.log_file:
            handle_logging(args.log_file, config.log_level)
    except Exception as err:
        logger.error(f"Unable to continue due to a configuration problem: {err}")
        sys.exit(1)

    if args.validate_yara_rules:
        validate_yara_rules()
    else:
        yara_connector = YaraConnector(args, config=config)
        exit_rc = 0
        try:
            yara_connector.run()
        except KeyboardInterrupt:
            logger.info("\n\n##### Interrupted by user!\n")
            exit_rc = 3
        except Exception as err:
            logger.error(f"There were errors executing Yara rules: {err}")
            exit_rc = 4
        finally:
            yara_connector.exit(5.0)
        sys.exit(exit_rc)
