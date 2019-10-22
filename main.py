import argparse
import configparser
import hashlib
import json
import logging
import logging.handlers
import os
import time
import traceback
from datetime import datetime, timedelta
from typing import List, Optional

import humanfriendly
import psycopg2
# noinspection PyPackageRequirements
import yara
from celery import group
from peewee import SqliteDatabase

import globals
import singleton
from binary_database import BinaryDetonationResult, db
from feed import CbFeed, CbFeedInfo, CbReport
from tasks import analyze_binary, app, generate_rule_map, update_yara_rules_remote

logging_format = '%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s'
logging.basicConfig(format=logging_format)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger('celery.app.trace')
celery_logger.setLevel(logging.ERROR)


def generate_feed_from_db() -> None:
    """
    Creates a feed based on specific database information.
    :return:
    """
    query = BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0)

    reports = []
    for binary in query:
        fields = {'iocs': {'md5': [binary.md5]},
                  'score': binary.score,
                  'timestamp': int(time.mktime(time.gmtime())),
                  'link': '',
                  'id': 'binary_{0}'.format(binary.md5),
                  'title': binary.last_success_msg,
                  'description': binary.last_success_msg
                  }
        reports.append(CbReport(**fields))

    feedinfo = {'name': 'yara',
                'display_name': "Yara",
                'provider_url': "http://plusvic.github.io/yara/",
                'summary': "Scan binaries collected by Carbon Black with Yara.",
                'tech_data': "There are no requirements to share any data with Carbon Black to use this feed.",
                'icon': 'yara-logo.png',
                'category': "Connectors",
                }
    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)

    logger.debug("Writing out feed '{0}' to disk".format(feedinfo.data['name']))
    with open(globals.output_file, 'w') as fp:
        fp.write(feed.dump())


# noinspection DuplicatedCode
def generate_yara_rule_map_hash(yara_rule_path: str) -> None:
    """
    Create a list of hashes for each yara rule.

    :param yara_rule_path: the path to where the yara rules are stored.
    :return:
    """
    temp_list = []
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
            fullpath = os.path.join(yara_rule_path, fn)
            if not os.path.isfile(fullpath):
                continue
            with open(os.path.join(yara_rule_path, fn), 'rb') as fp:
                data = fp.read()
                # NOTE: Original logic resulted in a cumulative hash for each file (linking them)
                md5 = hashlib.md5()
                md5.update(data)
                temp_list.append(str(md5.hexdigest()))

    # FUTURE: Would this be better served as a map keyed by md5, with the value being the rule text, as for the
    #  following method?
    globals.g_yara_rule_map_hash_list = temp_list
    globals.g_yara_rule_map_hash_list.sort()


def generate_rule_map_remote(yara_rule_path) -> None:
    """
    Get remote rules and store into an internal map keyed by file name.
    :param yara_rule_path: path to wheer thr rules are stored
    :return:
    """
    ret_dict = {}
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
            fullpath = os.path.join(yara_rule_path, fn)
            if not os.path.isfile(fullpath):
                continue
            with open(os.path.join(yara_rule_path, fn), 'rb') as fp:
                ret_dict[fn] = fp.read()

    result = update_yara_rules_remote.delay(ret_dict)
    globals.g_yara_rule_map = ret_dict
    while not result.ready():
        time.sleep(.1)


def analyze_binaries(md5_hashes: List[str], local: bool) -> Optional:
    """
    Analyze binaries.

    TODO: determine return typing!

    :param md5_hashes: list of  hashes to check.
    :param local: True if local
    :return: None if there is a problem; results otherwise
    """
    if local:
        try:
            results = []
            for md5_hash in md5_hashes:
                results.append(analyze_binary(md5_hash))
        except Exception as err:
            logger.error("{0}".format(err))
            time.sleep(5)
            return None
        else:
            return results
    else:
        try:
            scan_group = []
            for md5_hash in md5_hashes:
                scan_group.append(analyze_binary.s(md5_hash))
            job = group(scan_group)

            result = job.apply_async()

            start = time.time()
            while not result.ready():
                if time.time() - start >= 120:  # 2 minute timeout
                    break
                else:
                    time.sleep(.1)
        except Exception as err:
            logger.error("Error when analyzing: {0}".format(err))
            logger.error(traceback.format_exc())
            time.sleep(5)
            return None
        else:
            if result.successful():
                return result.get(timeout=30)
            else:
                return None


def save_results(analysis_results: List) -> None:
    """
    Save the current analysis results.

    TODO: figure out typing!

    :param analysis_results:
    :return:
    """
    for analysis_result in analysis_results:
        if analysis_result.binary_not_available:
            globals.g_num_binaries_not_available += 1
            continue

        bdr, created = BinaryDetonationResult.get_or_create(md5=analysis_result.md5)

        try:
            bdr.md5 = analysis_result.md5
            bdr.last_scan_date = datetime.now()
            bdr.score = analysis_result.score
            bdr.last_error_msg = analysis_result.last_error_msg
            bdr.last_success_msg = analysis_result.short_result
            bdr.misc = json.dumps(globals.g_yara_rule_map_hash_list)
            bdr.save()
            globals.g_num_binaries_analyzed += 1
        except Exception as err:
            logger.error("Error saving to database: {0}".format(err))
            logger.error(traceback.format_exc())
        else:
            if analysis_result.score > 0:
                generate_feed_from_db()


def perform(yara_rule_dir):
    if globals.g_remote:
        logger.info("Uploading yara rules to workers...")
        generate_rule_map_remote(yara_rule_dir)

    num_total_binaries = 0
    num_binaries_skipped = 0
    num_binaries_queued = 0
    md5_hashes = []

    start_time = time.time()

    logger.info("Connecting to Postgres database...")
    try:
        conn = psycopg2.connect(host=globals.g_postgres_host,
                                database=globals.g_postgres_db,
                                user=globals.g_postgres_username,
                                password=globals.g_postgres_password,
                                port=globals.g_postgres_port)
        cur = conn.cursor(name="yara_agent")

        start_date_binaries = datetime.now() - timedelta(days=globals.g_num_days_binaries)
        # noinspection SqlDialectInspection,SqlNoDataSourceInspection
        cur.execute("SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND timestamp >= '{0}' "
                    "ORDER BY timestamp DESC".format(start_date_binaries))
    except Exception as err:
        logger.error("Failed to connect to Postgres database: {0}".format(err))
        logger.error(traceback.format_exc())
        return

    logger.info("Enumerating modulestore...")
    while True:
        rows = cur.fetchmany()
        if len(rows) == 0:
            break

        for row in rows:
            num_total_binaries += 1
            md5_hash = row[0].hex()

            #
            # Check if query returns any rows
            #
            query = BinaryDetonationResult.select().where(BinaryDetonationResult.md5 == md5_hash)
            if query.exists():
                try:
                    bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == md5_hash)
                    scanned_hash_list = json.loads(bdr.misc)
                    if globals.g_disable_rescan and bdr.misc:
                        continue

                    if scanned_hash_list == globals.g_yara_rule_map_hash_list:
                        num_binaries_skipped += 1
                        #
                        # If it is the same then we don't need to scan again
                        #
                        continue
                except Exception as e:
                    logger.error("Unable to decode yara rule map hash from database: {0}".format(e))

            num_binaries_queued += 1
            md5_hashes.append(md5_hash)

            if len(md5_hashes) >= globals.MAX_HASHES:
                analysis_results = analyze_binaries(md5_hashes, local=(not globals.g_remote))
                if analysis_results:
                    for analysis_result in analysis_results:
                        logger.debug((f"Analysis result is {analysis_result.md5} {analysis_result.binary_not_available}"
                                      f" {analysis_result.long_result} {analysis_result.last_error_msg}"))
                        if analysis_result.last_error_msg:
                            logger.error(analysis_result.last_error_msg)
                    save_results(analysis_results)
                else:
                    pass
                md5_hashes = []

        # throw us a bone every 1000 binaries processed
        if num_total_binaries % 1000 == 0:
            _rule_logging(start_time, num_binaries_skipped, num_total_binaries)

    conn.close()

    analysis_results = analyze_binaries(md5_hashes, local=(not globals.g_remote))
    if analysis_results:
        for analysis_result in analysis_results:
            logger.debug((f"Analysis result is {analysis_result.md5} {analysis_result.binary_not_available}"
                          f" {analysis_result.long_result} {analysis_result.last_error_msg}"))
            if analysis_result.last_error_msg:
                logger.error(analysis_result.last_error_msg)
        save_results(analysis_results)

    _rule_logging(start_time, num_binaries_skipped, num_total_binaries)
    generate_feed_from_db()


def _rule_logging(start_time: float, num_binaries_skipped: int, num_total_binaries: int) -> None:
    """
    Simple method to log yara work.
    :param start_time: start time for the work
    :param num_binaries_skipped:
    :param num_total_binaries:
    :return:
    """
    elapsed_time = time.time() - start_time
    logger.info("elapsed time: {0}".format(humanfriendly.format_timespan(elapsed_time)))
    logger.debug("   number binaries scanned: {0}".format(globals.g_num_binaries_analyzed))
    logger.debug("   number binaries already scanned: {0}".format(num_binaries_skipped))
    logger.debug("   number binaries unavailable: {0}".format(globals.g_num_binaries_not_available))
    logger.info("total binaries from db: {0}".format(num_total_binaries))
    logger.debug("   binaries per second: {0}:".format(round(num_total_binaries / elapsed_time, 2)))
    logger.info("num binaries score greater than zero: {0}".format(
        len(BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0))))
    logger.info("")


def verify_config(config_file: str, output_file: str) -> bool:
    """
    Validate the config file.
    :param config_file: The config file to validate
    :param output_file:
    :return: True if configuration file is good
    """
    config = configparser.ConfigParser()
    config.read(config_file)

    globals.output_file = output_file

    if not config.has_section('general'):
        logger.error("Config file does not have a 'general' section")
        return False

    if 'worker_type' in config['general']:
        if config['general']['worker_type'] == 'local':
            globals.g_remote = False
        elif config['general']['worker_type'] == 'remote':
            globals.g_remote = True
            if 'broker_url' in config['general']:
                app.conf.update(
                    broker_url=config['general']['broker_url'],
                    result_backend=config['general']['broker_url'])
        else:
            logger.error("invalid worker_type specified.  Must be \'local\' or \'remote\'")
            return False
    else:
        globals.g_remote = False
        logger.warning("Config file does not specify 'worker_type', assuming local")

    if 'yara_rules_dir' in config['general']:
        globals.g_yara_rules_dir = config['general']['yara_rules_dir']

    if 'postgres_host' in config['general']:
        globals.g_postgres_host = config['general']['postgres_host']

    if 'postgres_username' in config['general']:
        globals.g_postgres_username = config['general']['postgres_username']

    if 'postgres_password' in config['general']:
        globals.g_postgres_password = config['general']['postgres_password']

    if 'postgres_db' in config['general']:
        globals.g_postgres_db = config['general']['postgres_db']

    if 'cb_server_url' in config['general']:
        globals.g_cb_server_url = config['general']['cb_server_url']

    if 'cb_server_token' in config['general']:
        globals.g_cb_server_token = config['general']['cb_server_token']

    if 'niceness' in config['general']:
        os.nice(int(config['general']['niceness']))

    if 'concurrent_hashes' in config['general']:
        globals.MAX_HASHES = int(config['general']['concurrent_hashes'])

    if 'disable_rescan' in config['general']:
        globals.g_disable_rescan = bool(config['general']['disable_rescan'])
        logger.debug("Disable Rescan: {}".format(globals.g_disable_rescan))

    if 'num_days_binaries' in config['general']:
        globals.g_num_days_binaries = int(config['general']['num_days_binaries'])
        logger.debug("Number of days for binaries: {}".format(globals.g_num_days_binaries))

    return True


def main():
    global logger

    try:
        # check for single operation
        singleton.SingleInstance()
    except Exception as err:
        logger.error(f"Only one instance of this script is allowed to run at a time: {err}")
    else:
        parser = argparse.ArgumentParser(description='Yara Agent for Yara Connector')
        parser.add_argument('--config-file',
                            required=True,
                            default='yara_agent.conf',
                            help='Location of the config file')
        parser.add_argument('--log-file',
                            default='yara_agent.log',
                            help='Log file output')
        parser.add_argument('--output-file',
                            default='yara_feed.json',
                            help='output feed file')
        parser.add_argument('--validate-yara-rules',
                            action='store_true',
                            help='ONLY validate yara rules in a specified directory')
        parser.add_argument('--debug', action='store_true')

        args = parser.parse_args()

        if args.debug:
            logger.setLevel(logging.DEBUG)

        if args.log_file:
            formatter = logging.Formatter(logging_format)
            handler = logging.handlers.RotatingFileHandler(args.log_file, maxBytes=10 * 1000000, backupCount=10)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        if verify_config(args.config_file, args.output_file):
            if args.validate_yara_rules:
                logger.info("Validating yara rules in directory: {0}".format(globals.g_yara_rules_dir))
                yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
                try:
                    yara.compile(filepaths=yara_rule_map)
                except Exception as err:
                    logger.error(f"There were errors compiling yara rules: {err}")
                    logger.error(traceback.format_exc())
                else:
                    logger.info("All yara rules compiled successfully")
            else:
                try:
                    globals.g_yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
                    generate_yara_rule_map_hash(globals.g_yara_rules_dir)
                    database = SqliteDatabase('binary.db')
                    db.initialize(database)
                    db.connect()
                    db.create_tables([BinaryDetonationResult])
                    generate_feed_from_db()
                    perform(globals.g_yara_rules_dir)
                except Exception as err:
                    logger.error(f"There were errors executing yara rules: {err}")
                    logger.error(traceback.format_exc())


if __name__ == "__main__":
    main()
