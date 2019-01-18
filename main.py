import os
import traceback
import logging
import time
import threading
import humanfriendly
import psycopg2
import json
from datetime import datetime
from peewee import SqliteDatabase
from tasks import analyze_binary, update_yara_rules_remote, generate_rule_map, app
import globals
import argparse
import configparser
import hashlib

from feed import CbFeed, CbFeedInfo, CbReport
from celery import group
from binary_database import db, BinaryDetonationResult
import singleton

logging_format = '%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s'
logging.basicConfig(format=logging_format)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger('celery.app.trace')
celery_logger.setLevel(logging.ERROR)


def generate_feed_from_db():
    query = BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0)
    reports = list()

    for binary in query:
        fields = {'iocs': {'md5': [binary.md5]},
                  'score': binary.score,
                  'timestamp': int(time.mktime(time.gmtime())),
                  'link': '',
                  'id': f'binary_{binary.md5}',
                  'title': '',
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
    logger.debug("dumping feed...")
    created_feed = feed.dump()

    logger.debug("Writing out feed to disk")
    with open(globals.output_file, 'w') as fp:
        fp.write(created_feed)


def generate_yara_rule_map_hash(yara_rule_path):
    md5 = hashlib.md5()

    temp_list = list()

    for fn in os.listdir(yara_rule_path):
        with open(os.path.join(yara_rule_path, fn), 'rb') as fp:
            data = fp.read()
            md5.update(data)
            temp_list.append(str(md5.hexdigest()))

    globals.g_yara_rule_map_hash_list = temp_list
    globals.g_yara_rule_map_hash_list.sort()


def generate_rule_map_remote(yara_rule_path):
    ret_dict = dict()
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar"):
            ret_dict[fn] = open(os.path.join(yara_rule_path, fn), 'rb').read()

    result = update_yara_rules_remote.delay(ret_dict)
    globals.g_yara_rule_map = ret_dict
    while not result.ready():
        time.sleep(.1)


def analyze_binaries(md5_hashes, local):
    if local:
        try:
            results = list()
            for md5_hash in md5_hashes:
                results.append(analyze_binary(md5_hash))
        except:
            logger.error(traceback.format_exc())
            time.sleep(5)
            return
        else:
            return results
    else:
        try:
            scan_group = list()
            for md5_hash in md5_hashes:
                scan_group.append(analyze_binary.s(md5_hash))
            job = group(scan_group)

            result = job.apply_async()

            time_waited = 0
            while not result.ready():
                if time_waited == 100:
                    break
                else:
                    time.sleep(.1)
                    time_waited += 1

        except:
            logger.error(traceback.format_exc())
            time.sleep(5)
            return
        else:
            if result.successful():
                return result.get(timeout=30)


def save_results(analysis_results):
    for analysis_result in analysis_results:
        if analysis_result.binary_not_available:
            globals.g_num_binaries_not_available += 1
            continue
        try:
            bdr = BinaryDetonationResult()
            bdr.md5 = analysis_result.md5
            bdr.last_scan_date = datetime.now()
            bdr.score = analysis_result.score
            bdr.last_error_msg = analysis_result.last_error_msg
            bdr.last_success_msg = analysis_result.short_result
            bdr.misc = json.dumps(globals.g_yara_rule_map_hash_list)
            bdr.save()
            globals.g_num_binaries_analyzed += 1
        except:
            logger.error("Error saving to database")
            logger.error(traceback.format_exc())
        else:
            if analysis_result.score > 0:
                generate_feed_from_db()


def print_statistics():
    pass


def main(yara_rule_dir):
    if globals.g_remote:
        logger.info("Uploading yara rules to workers...")
        generate_rule_map_remote(yara_rule_dir)

    num_total_binaries = 0
    num_binaries_skipped = 0
    num_binaries_queued = 0
    md5_hashes = list()

    start_time = time.time()

    logger.info("Connecting to Postgres database...")
    try:
        conn = psycopg2.connect(host=globals.g_postgres_host,
                                database=globals.g_postgres_db,
                                user=globals.g_postgres_username,
                                password=globals.g_postgres_password,
                                port=globals.g_postgres_port)
        cur = conn.cursor()
        cur.execute("SELECT md5hash FROM storefiles WHERE present_locally = TRUE")
    except:
        logger.error("Failed to connect to Postgres database")
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

            try:
                #
                # see if we have already seen this file before.
                # we need to check to see what yara rules we have scanned with
                #
                bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == md5_hash)
            except:

                #
                # Not found so we have to scan
                #
                pass
            else:
                try:
                    scanned_hash_list = json.loads(bdr.misc)
                    if scanned_hash_list == globals.g_yara_rule_map_hash_list:
                        num_binaries_skipped += 1
                        #
                        # If it is the same then we don't need to scan again
                        #
                        continue
                    else:
                        #
                        # Yara rules were updated, so lets scan
                        #
                        pass
                except:
                    logger.error("Unable to decode yara rule map hash from database")
                    pass

            num_binaries_queued += 1
            md5_hashes.append(md5_hash)

            if len(md5_hashes) >= globals.MAX_HASHES:
                analysis_results = analyze_binaries(md5_hashes, local=(not globals.g_remote))
                if analysis_results:
                    for analysis_result in analysis_results:
                        if analysis_result.last_error_msg:
                            logger.error(analysis_result.last_error_msg)
                    save_results(analysis_results)
                else:
                    logger.error(traceback.format_exc())
                    logger.error("analysis_results is None")
                md5_hashes = list()

        if num_total_binaries % 1000 == 0:
            elapsed_time = time.time() - start_time
            logger.info("elapsed time: {0}".format(humanfriendly.format_timespan(elapsed_time)))
            logger.debug("number binaries scanned: {0}".format(globals.g_num_binaries_analyzed))
            logger.debug("number binaries already scanned: {0}".format(num_binaries_skipped))
            logger.debug("number binaries unavailable: {0}".format(globals.g_num_binaries_not_available))
            logger.info("total binaries from db: {0}".format(num_total_binaries))
            logger.debug("binaries per second: {0}:".format(round(num_total_binaries / elapsed_time, 2)))
            logger.info("num binaries score greater than zero: {0}".format(
                len(BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0))))
            logger.info("")

    conn.close()

    analysis_results = analyze_binaries(md5_hashes, local=(not globals.g_remote))
    save_results(analysis_results)
    md5_hashes = list()

    elapsed_time = time.time() - start_time
    logger.info("elapsed time: {0}".format(humanfriendly.format_timespan(elapsed_time)))
    logger.debug("number binaries scanned: {0}".format(globals.g_num_binaries_analyzed))
    logger.debug("number binaries already scanned: {0}".format(num_binaries_skipped))
    logger.debug("number binaries unavailable: {0}".format(globals.g_num_binaries_not_available))
    logger.info("total binaries from db: {0}".format(num_total_binaries))
    logger.debug("binaries per second: {0}:".format(round(num_total_binaries / elapsed_time, 2)))
    logger.info("num binaries score greater than zero: {0}".format(
        len(BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0))))
    logger.info("")

    generate_feed_from_db()


def verify_config(config_file, output_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    globals.output_file = output_file

    if not config.has_section('general'):
        logger.error("Config file does not have a \'general\' section")
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
    else:
        logger.warn("Config file does not specify worker_type, assuming local")

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

    return True


if __name__ == "__main__":
    try:
        me = singleton.SingleInstance()
    except:
        logger.error("Only one instance of this script is allowed to run at a time")
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
        parser.add_argument('--debug', action='store_true')

        args = parser.parse_args()

        if args.debug:
            logger = logging.getLogger(__name__)
            logger.setLevel(logging.DEBUG)

        if args.log_file:
            formatter = logging.Formatter(logging_format)
            handler = logging.handlers.RotatingFileHandler(args.log_file, maxBytes=10 * 1000000, backupCount=10)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        if verify_config(args.config_file, args.output_file):
            try:
                g_yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
                generate_yara_rule_map_hash(globals.g_yara_rules_dir)
                database = SqliteDatabase('binary.db')
                db.initialize(database)
                db.connect()
                db.create_tables([BinaryDetonationResult])
                generate_feed_from_db()
                main('yara_rules')
            except:
                logger.error(traceback.format_exc())
