import os
import traceback
import logging
import time
import threading
import humanfriendly
import psycopg2
import json
from datetime import datetime, timedelta
from peewee import SqliteDatabase
from tasks import analyze_binary, update_yara_rules_remote, generate_rule_map, app
import globals
import argparse
import configparser
import hashlib
import yara
import subprocess

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
    #logger.debug("dumping feed...")
    created_feed = feed.dump()

    #logger.debug("Writing out feed to disk")
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
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
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
            return None
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
                if time_waited >= 100:
                    break
                else:
                    time.sleep(.1)
                    time_waited += .1

        except:
            logger.error(traceback.format_exc())
            time.sleep(5)
            return
        else:
            if result.successful():
                return result.get(timeout=30)
            else:
                return None


def save_results(analysis_results):
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
        except:
            logger.error("Error saving to database")
            logger.error(traceback.format_exc())
        else:
            if analysis_result.score > 0:
                generate_feed_from_db()


def print_statistics():
    pass


def perform(yara_rule_dir):
    if globals.g_remote:
        logger.info("Uploading yara rules to workers...")
        generate_rule_map_remote(yara_rule_dir)

    num_total_binaries = 0
    num_binaries_skipped = 0
    num_binaries_queued = 0
    md5_hashes = list()

    start_time = time.time()
    start_datetime = datetime.now()

    logger.info("Connecting to Postgres database...")
    try:
        conn = psycopg2.connect(host=globals.g_postgres_host,
                                database=globals.g_postgres_db,
                                user=globals.g_postgres_username,
                                password=globals.g_postgres_password,
                                port=globals.g_postgres_port)
        cur = conn.cursor(name="yara_agent")

        start_date_binaries = datetime.now() - timedelta(days=globals.g_num_days_binaries)
        cur.execute("SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND timestamp >= '{0}' "
                    "ORDER BY timestamp DESC".format(start_date_binaries))

    except:
        logger.error("Failed to connect to Postgres database")
        logger.error(traceback.format_exc())
        return

    logger.info("Enumerating modulestore...")

    while True:
        if cur.closed:
            cur = conn.cursor(name="yara_agent")
            cur.execute("SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND timestamp >= '{0}' "
                    "ORDER BY timestamp DESC".format(start_date_binaries))
        try:    
            rows = cur.fetchmany()
        except psycopg2.OperationalError:
            cur = conn.cursor(name="yara_agent")
            cur.execute("SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND timestamp >= '{0}' "
                    "ORDER BY timestamp DESC".format(start_date_binaries))
            rows = cur.fetchmany()
        if len(rows) == 0:
            break

        for row in rows:
            seconds_since_start = (datetime.now() - start_datetime).seconds
            if seconds_since_start >= globals.g_vacuum_seconds and globals.g_vacuum_seconds > 0:
                cur.close()
                logger.warning("!!!Executing vacuum script!!!")
                target = os.path.join(os.getcwd(), globals.g_vacuum_script)
                prog = subprocess.Popen(target, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = prog.communicate()  # Returns (stdoutdata, stderrdata): stdout and stderr are ignored, here
                logger.info(stdout)
                logger.error(stderr)
                if prog.returncode:
                    logger.warning('program returned error code {0}'.format(prog.returncode))
                start_datetime = datetime.now()
                logger.warning("!!!Done Executing vacuum script!!!")
                break

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
                    logger.error("Unable to decode yara rule map hash from database")
                    logger.error(str(e))

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
                    pass
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
    if analysis_results:
        for analysis_result in analysis_results:
            if analysis_result.last_error_msg:
                logger.error(analysis_result.last_error_msg)
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

    if 'postgres_port' in config['general']:
        globals.g_postgres_port = config['general']['postgres_port']

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

    if 'vacuum_seconds' in config['general']:
        globals.g_vacuum_seconds = int(config['general']['vacuum_seconds'])
        if 'vacuum_script' in config['general'] and globals.g_vacuum_seconds > 0:
            globals.g_vacuum_script = config['general']['vacuum_script']
            logger.warn("!!! Vacuum Script is enabled --- use this advanced feature at your own discretion --- !!!")

    return True


def main():
    global logger

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
        parser.add_argument('--validate-yara-rules',
                            action='store_true',
                            help='ONLY validate yara rules in a specified directory')
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

            if args.validate_yara_rules:
                logger.info("Validating yara rules in directory: {0}".format(globals.g_yara_rules_dir))
                yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
                try:
                    yara.compile(filepaths=yara_rule_map)
                except:
                    logger.error("There were errors compiling yara rules")
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
                except:
                    logger.error(traceback.format_exc())


if __name__ == "__main__":
    main()
