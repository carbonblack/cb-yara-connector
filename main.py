import argparse
import configparser
import hashlib
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time
import signal
import traceback
from daemon import daemon
import lockfile
from functools import partial
from datetime import datetime, timedelta
from typing import List, Optional

from threading import Thread, Event, Barrier
from queue import Queue, Empty

from asyncresultqueue import AsyncResultQueue

import humanfriendly
import psycopg2
import sched

# noinspection PyPackageRequirements
import yara
from celery import group
from celery.bin import worker
from peewee import SqliteDatabase

import globals
from analysis_result import AnalysisResult
from binary_database import BinaryDetonationResult, db
from exceptions import CbInvalidConfig
from feed import CbFeed, CbFeedInfo, CbReport
from tasks import (
    analyze_binary,
    app,
    generate_rule_map,
    update_yara_rules_remote,
    analyze_bins,
)
from utilities import placehold

logging_format = "%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s"
logging.basicConfig(format=logging_format)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger("celery.app.trace")
celery_logger.setLevel(logging.ERROR)


"""
promise worker takes a promise from the task-queue and waits for it to resolve, then puts it into the scanning_results_queue

"""

def promise_worker(exit_event, scanning_promise_queue, scanning_results_queue):
    while not (exit_event.is_set()):
        if not (scanning_promise_queue.empty()):
            try:
                promise = scanning_promise_queue.get()
                if promise:
                    result = promise.get(disable_sync_subtasks=False)
                    scanning_results_queue.put(result)
            except Empty:
                exit_event.wait(1)
        else:
            exit_event.wait(1)


""" Sqlite is not meant to be thread-safe 

This single-worker-thread writes the result(s) to the configured sqlite file to hold the feed-metadata and seen binaries/results from scans
"""


def results_worker(exit_event, results_queue):
    while not (exit_event.is_set()):
        if not (results_queue.empty()):
            try:
                result = results_queue.get()
                save_result(result)
            except Empty:
                exit_event.wait(1)
        else:
            exit_event.wait(1)


def generate_feed_from_db() -> None:
    """
    Creates a feed based on specific database information.
    :return:
    """
    query = BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0)

    reports = []
    for binary in query:
        fields = {
            "iocs": {"md5": [binary.md5]},
            "score": binary.score,
            "timestamp": int(time.mktime(time.gmtime())),
            "link": "",
            "id": "binary_{0}".format(binary.md5),
            "title": binary.last_success_msg,
            "description": binary.last_success_msg,
        }
        reports.append(CbReport(**fields))

    feedinfo = {
        "name": "yara",
        "display_name": "Yara",
        "provider_url": "http://plusvic.github.io/yara/",
        "summary": "Scan binaries collected by Carbon Black with Yara.",
        "tech_data": "There are no requirements to share any data with Carbon Black to use this feed.",
        "icon": "yara-logo.png",
        "category": "Connectors",
    }
    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)

    logger.debug("Writing out feed '{0}' to disk".format(feedinfo.data["name"]))
    with open(globals.output_file, "w") as fp:
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
            with open(os.path.join(yara_rule_path, fn), "rb") as fp:
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
            with open(os.path.join(yara_rule_path, fn), "rb") as fp:
                ret_dict[fn] = fp.read()

    result = update_yara_rules_remote.delay(ret_dict)
    globals.g_yara_rule_map = ret_dict
    while not result.ready():
        time.sleep(0.1)


# Scan a binary and enque the promise/future celery returns
def analyze_binary_and_queue(scanning_promise_queue, md5sum):
    promise = analyze_binary.delay(md5sum)
    scanning_promise_queue.put(promise)


# Scans each binary asyncrhonously not grouping
def analyze_binaries_and_queue(scanning_promise_queue, md5_hashes):
    for h in md5_hashes:
        analyze_binary_and_queue(scanning_promise_queue, h)


# Attempts to do work in chunks of MAX_HASHES, at most
def analyze_binaries_and_queue_chunked(scanning_promise_queue, md5_hashes):
    promise = analyze_binary.chunks(
        [(mh,) for mh in md5_hashes], globals.MAX_HASHES
    ).apply_async()
    for prom in promise.children:
        scanning_promise_queue.put(prom)


# TODO REMOVE THIS
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
                    time.sleep(0.1)
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


def save_results(analysis_results: List[AnalysisResult]) -> None:
    """
    Save the current analysis results.

    TODO: figure out typing!

    :param analysis_results:
    :return:
    """
    for analysis_result in analysis_results:
        save_result(analysis_result)


def save_result(analysis_result):
    if analysis_result.binary_not_available:
        globals.g_num_binaries_not_available += 1
        return

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


def get_database_conn():
    logger.info("Connecting to Postgres database...")
    conn = psycopg2.connect(
        host=globals.g_postgres_host,
        database=globals.g_postgres_db,
        user=globals.g_postgres_username,
        password=globals.g_postgres_password,
        port=globals.g_postgres_port,
    )

    return conn


def get_cursor(conn, start_date_binaries):
    cur = conn.cursor(name="yara_agent")

    # noinspection SqlDialectInspection,SqlNoDataSourceInspection
    cur.execute(
        "SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND timestamp >= '{0}' "
        "ORDER BY timestamp DESC".format(start_date_binaries)
    )

    return cur


def execute_script():
    logger.warning("!!!Executing vacuum script!!!")

    target = os.path.join(os.getcwd(), globals.g_vacuum_script)

    prog = subprocess.Popen(target, shell=True, universal_newlines=True)
    stdout, stderr = prog.communicate()
    logger.info(stdout)
    logger.error(stderr)
    if prog.returncode:
        logger.warning("program returned error code {0}".format(prog.returncode))
    logger.warning("!!!Done Executing vacuum script!!!")


def perform(yara_rule_dir, conn, scanning_promises_queue):
    if globals.g_remote:
        logger.info("Uploading yara rules to workers...")
        generate_rule_map_remote(yara_rule_dir)

    num_total_binaries = 0
    num_binaries_skipped = 0
    num_binaries_queued = 0
    md5_hashes = []

    start_time = time.time()

    start_datetime = datetime.now()

    start_date_binaries = start_datetime - timedelta(days=globals.g_num_days_binaries)

    cur = get_cursor(conn, start_date_binaries)

    rows = cur.fetchall()

    conn.commit()

    # conn.close()
    # Todo needs to be closed by the running-thread or someone
    #

    num_total_binaries = len(rows)

    logger.info(
        f"Enumerating modulestore...found {num_total_binaries} resident binaries"
    )

    ##TODO should send just row over the wire and do the .hex() in the remote worker / tasks.py
    md5_hashes = filter(_check_hash_against_feed, (row[0].hex() for row in rows))

    analyze_binaries_and_queue(scanning_promises_queue, md5_hashes)

    # generate_feed_from_db()


def _check_hash_against_feed(md5_hash):
    # straigthen this out
    query = BinaryDetonationResult.select().where(
        BinaryDetonationResult.md5 == md5_hash
    )
    if query.exists():
        return False
        """
        try:
            bdr = BinaryDetonationResult.get(BinaryDetonationResult.md5 == md5_hash)
            scanned_hash_list = json.loads(bdr.misc)
            if globals.g_disable_rescan and bdr.misc:
                return False

            if scanned_hash_list == globals.g_yara_rule_map_hash_list:
                #
                # If it is the same then we don't need to scan again
                #
                return False
        except Exception as e:
            logger.error(
                "Unable to decode yara rule map hash from database: {0}".format(e)
            )
            return False """
    return True


def _analyze_save_and_log(
    hashes, start_time, num_binaries_skipped, num_total_binaries, local_override=False
):
    analysis_results = analyze_binaries(
        hashes, local=(not globals.g_remote and not local_override)
    )
    logger.debug(analysis_results)
    if analysis_results:
        for analysis_result in analysis_results:
            logger.debug(
                (
                    f"Analysis result is {analysis_result.md5} {analysis_result.binary_not_available}"
                    f" {analysis_result.long_result} {analysis_result.last_error_msg}"
                )
            )
            if analysis_result.last_error_msg:
                logger.error(analysis_result.last_error_msg)
        save_results(analysis_results)

    _rule_logging(start_time, num_binaries_skipped, num_total_binaries)


def _rule_logging(
    start_time: float, num_binaries_skipped: int, num_total_binaries: int
) -> None:
    """
    Simple method to log yara work.
    :param start_time: start time for the work
    :param num_binaries_skipped:
    :param num_total_binaries:
    :return:
    """
    elapsed_time = time.time() - start_time
    logger.info("elapsed time: {0}".format(humanfriendly.format_timespan(elapsed_time)))
    logger.debug(
        "   number binaries scanned: {0}".format(globals.g_num_binaries_analyzed)
    )
    logger.debug("   number binaries already scanned: {0}".format(num_binaries_skipped))
    logger.debug(
        "   number binaries unavailable: {0}".format(
            globals.g_num_binaries_not_available
        )
    )
    logger.info("total binaries from db: {0}".format(num_total_binaries))
    logger.debug(
        "   binaries per second: {0}:".format(
            round(num_total_binaries / elapsed_time, 2)
        )
    )
    logger.info(
        "num binaries score greater than zero: {0}".format(
            len(BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0))
        )
    )
    logger.info("")


# noinspection DuplicatedCode
def verify_config(config_file: str, output_file: str = None) -> None:
    """
    Validate the config file.
    :param config_file: The config file to validate
    :param output_file: the output file; if not specified equals config file plus ".json"
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

    globals.output_file = (
        output_file if output_file is not None else config_file.strip() + ".json"
    )
    globals.output_file = os.path.abspath(
        os.path.expanduser(placehold(globals.output_file))
    )
    logger.debug(f"NOTE: output file will be '{globals.output_file}'")

    the_config = config["general"]

    if "mode" in config["general"]:
        operating_mode = the_config["mode"].lower()
        if operating_mode in ["master", "slave"]:
            globals.g_mode = operating_mode
        else:
            raise CbInvalidConfig(
                f"{header} does not specify a valid operating mode (slave/master)"
            )
    else:
        raise CbInvalidConfig(
            f"{header} does not specify a valid operating mode (slave/master)"
        )

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
        # TODO: validate url & token with test call?

    if "broker_url" in the_config and the_config["broker_url"].strip() != "":
        app.conf.update(
            broker_url=the_config["broker_url"], result_backend=the_config["broker_url"]
        )
    elif globals.g_remote:
        raise CbInvalidConfig(f"{header} is 'remote' and missing 'broker_url'")

    if "yara_rules_dir" in the_config and the_config["yara_rules_dir"].strip() != "":
        check = os.path.abspath(
            os.path.expanduser(placehold(the_config["yara_rules_dir"]))
        )
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

    # NOTE: postgres_host has a default value in globals; use and warn if not defined
    if "postgres_host" in the_config and the_config["postgres_host"].strip() != "":
        globals.g_postgres_host = the_config["postgres_host"]
    else:
        logger.warning(
            f"{header} has no defined 'postgres_host'; using default of '{globals.g_postgres_host}'"
        )

    # NOTE: postgres_username has a default value in globals; use and warn if not defined
    if (
        "postgres_username" in the_config
        and the_config["postgres_username"].strip() != ""
    ):
        globals.g_postgres_username = the_config["postgres_username"]
    else:
        logger.warning(
            f"{header} has no defined 'postgres_username'; using default of '{globals.g_postgres_username}'"
        )

    if (
        "postgres_password" in the_config
        and the_config["postgres_password"].strip() != ""
    ):
        globals.g_postgres_password = the_config["postgres_password"]
    else:
        raise CbInvalidConfig(f"{header} has no 'postgres_password' defined")

    # NOTE: postgres_db has a default value in globals; use and warn if not defined
    if "postgres_db" in the_config and the_config["postgres_db"].strip() != "":
        globals.g_postgres_db = the_config["postgres_db"]
    else:
        logger.warning(
            f"{header} has no defined 'postgres_db'; using default of '{globals.g_postgres_db}'"
        )

    # NOTE: postgres_port has a default value in globals; use and warn if not defined
    if "postgres_port" in the_config:
        globals.g_postgres_port = int(the_config["postgres_port"])
    else:
        logger.warning(
            f"{header} has no defined 'postgres_port'; using default of '{globals.g_postgres_port}'"
        )

    # TODO: validate postgres connection with supplied information?

    if "niceness" in the_config:
        os.nice(int(the_config["niceness"]))

    if "concurrent_hashes" in the_config:
        globals.MAX_HASHES = int(the_config["concurrent_hashes"])
        logger.debug("Consurrent Hashes: {0}".format(globals.MAX_HASHES))

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
        if "vacuum_script" in the_config and the_config["vacuum_seconds"].strip() != "":
            if globals.g_vacuum_seconds > 0:
                check = os.path.abspath(
                    os.path.expanduser(placehold(the_config["vacuum_script"]))
                )
                if os.path.exists(check):
                    if os.path.isdir(check):
                        raise CbInvalidConfig(
                            f"{header} specified 'vacuum_script' ({check}) is a directory"
                        )
                else:
                    raise CbInvalidConfig(
                        f"{header} specified 'vacuum_script' ({check}) does not exist"
                    )
                globals.g_vacuum_script = check
                logger.warning(
                    f"Vacuum Script '{check}' is enabled; use this advanced feature at your own discretion!"
                )
            else:
                logger.debug(
                    f"{header} has 'vacuum_script' defined, but it is disabled"
                )

    if "feed_database_path" in the_config:
        globals.feed_database_path = the_config["feed_database_path"]
        check = os.path.abspath(placehold(the_config["feed_database_path"]))
        if not (os.path.exists(check) and os.path.isdir(check)):
            raise CbInvalidConfig("Invalid database path specified")


def main():
    parser = argparse.ArgumentParser(description="Yara Agent for Yara Connector")

    parser.add_argument(
        "--config-file",
        required=True,
        default="yara_agent.conf",
        help="Location of the config file",
    )

    parser.add_argument("--log-file", default="yara_agent.log", help="Log file output")

    parser.add_argument(
        "--output-file", default="yara_feed.json", help="output feed file"
    )

    parser.add_argument(
        "--working-dir", default=".", help="working directory", required=False
    )

    parser.add_argument(
        "--lock-file", default="./yara.pid", help="lock file", required=False
    )

    parser.add_argument(
        "--validate-yara-rules",
        action="store_true",
        help="ONLY validate yara rules in a specified directory",
    )

    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.log_file:
        formatter = logging.Formatter(logging_format)
        handler = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=10 * 1000000, backupCount=10
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Verify the configuration file and load up important global variables
    try:
        verify_config(args.config_file, args.output_file)
    except Exception as err:
        logger.error(f"Unable to continue due to a configuration problem: {err}")
        sys.exit(1)

    if args.validate_yara_rules:
        logger.info(
            "Validating yara rules in directory: {0}".format(globals.g_yara_rules_dir)
        )
        yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
        try:
            yara.compile(filepaths=yara_rule_map)
            logger.info("All yara rules compiled successfully")
        except Exception as err:
            logger.error(f"There were errors compiling yara rules: {err}")
            logger.error(traceback.format_exc())
    else:

        EXIT_EVENT = Event()

        try:

            working_dir = args.working_dir

            lock_file = lockfile.FileLock(args.lock_file)

            files_preserve = getLogFileHandles(logger)
            files_preserve.extend([args.log_file, args.output_file])

            context = daemon.DaemonContext(
                working_directory=working_dir,
                pidfile=lock_file,
                stdout=sys.stdout,
                stderr=sys.stderr,
                files_preserve=files_preserve,
            )

            scanning_promise_queue = AsyncResultQueue()
            scanning_results_queue = Queue()

            context.signal_map = {signal.SIGTERM: partial(handle_sig, EXIT_EVENT)}

            with context:
                # only connect to cbr if we're the master
                if globals.g_mode == "master":
                    init_local_resources()
                    start_workers(
                        EXIT_EVENT, scanning_promise_queue, scanning_results_queue
                    )
                    # start local celery if working mode is local
                    if not globals.g_remote:
                        start_celery_worker_thread(args.config_file)
                else:
                    # otherwise, we must start a worker since we are not the master
                    start_celery_worker_thread(args.config_file)

                # run until the service/daemon gets a quitting sig
                run_to_signal(EXIT_EVENT)

        except KeyboardInterrupt:
            logger.info("\n\n##### Interupted by User!\n")
            EXIT_EVENT.set()
            sys.exit(2)
        except Exception as err:
            logger.error(f"There were errors executing yara rules: {err}")
            logger.error(traceback.format_exc())
            EXIT_EVENT.set()
            sys.exit(1)


def getLogFileHandles(logger):
    """ Get a list of filehandle numbers from logger
        to be handed to DaemonContext.files_preserve
    """
    handles = []
    for handler in logger.handlers:
        handles.append(handler.stream.fileno())
    if logger.parent:
        handles += getLogFileHandles(logger.parent)
    return handles


#
# Signal handler - handle the signal and mark exit if its an exiting signal
#
def handle_sig(exit_event, sig, frame):
    exit_sigs = (signal.SIGTERM, signal.SIGQUIT)
    if sig in exit_sigs:
        exit_event.set()
        sys.exit()


#
# wait until the exit_event has been set by the signal handler
#
def run_to_signal(exit_event):
    while not exit_event.is_set():
        signal.pause()
    


def init_local_resources():
    globals.g_yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
    generate_yara_rule_map_hash(globals.g_yara_rules_dir)
    database = SqliteDatabase(os.path.join(globals.g_feed_database_path, "binary.db"))
    db.initialize(database)
    db.connect()
    db.create_tables([BinaryDetonationResult])
    generate_feed_from_db()


# Start celery worker
# TODO - Aggresive autoscaling config options
# TODO _ honour the kill sig / exit event
def start_celery_worker_thread(config_file):
    t = Thread(target=launch_celery_worker, kwargs={"config_file": config_file})
    # t.daemon = True
    t.start()


# starts worker-threads (not celery workers)
# worker threads do work until they get the exit_event signal
def start_workers(exit_event, scanning_promises_queue, scanning_results_queue):
    logger.debug("Starting perf thread")

    perf_thread = DatabaseScanningThread(60, scanning_promises_queue)
    perf_thread.start()

    logger.debug("Starting promise thread(s)")
    for _ in range(4):
        promise_worker_thread = Thread(
            target=promise_worker,
            args=(exit_event, scanning_promises_queue, scanning_results_queue),
        )
        promise_worker_thread.start()

    logger.debug("Starting results saver thread")
    results_worker_thread = Thread(
        target=results_worker, args=(exit_event, scanning_results_queue)
    )

    results_worker_thread.start()


class DatabaseScanningThread(Thread):

    """
        A chron like thread that scans over the database for new hashes ever INTERVAL seconds 
        Pushes work to scanning_promises_queue 
        Design is marginal - ideally it would incorporate the event as the others do
    """

    def __init__(self, interval, scanning_promises_queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._args = args
        self._kwargs = kwargs
        self.DB_SCAN_SCHEDULER = sched.scheduler(time.time, time.sleep)
        self._conn = get_database_conn()
        self._interval = interval
        self._scanning_promises_queue = scanning_promises_queue
        self._target = self.do_db_scan


    #use enterabs and non-drifting time ?

    def db_scan_worker(self):
        self.DB_SCAN_SCHEDULER.enter(0, 1, self.do_db_scan)
        self.DB_SCAN_SCHEDULER.run()

    def do_db_scan(self):
        perform(globals.g_yara_rules_dir, self._conn, self._scanning_promises_queue)
        self.DB_SCAN_SCHEDULER.enter(self._interval, 1, self.do_db_scan)
        self.DB_SCAN_SCHEDULER.run()

    def run(self):
        """Method representing the thread's activity.
        You may override this method in a subclass. The standard run() method
        invokes the callable object passed to the object's constructor as the
        target argument, if any, with sequential and keyword arguments taken
        from the args and kwargs arguments, respectively.
        """
        try:
            if self._target:
                self._target(*self._args, **self._kwargs)
        finally:
            # Avoid a refcycle if the thread is running a function with
            # an argument that has a member that points to the thread.
            # shutdown database connection
            self._conn.close()
            del self._target, self._args, self._kwargs

#launch a celery worker using the imported app context
def launch_celery_worker(config_file=None):
    localworker = worker.worker(app=app)
    localworker.run(config_file=config_file)


if __name__ == "__main__":
    main()
