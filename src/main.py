# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta
from functools import partial
from queue import Empty, Queue
from threading import Event, Thread
from typing import List

import humanfriendly
import lockfile
import psycopg2

# noinspection PyPackageRequirements
import yara
from celery.bin import worker

# noinspection PyPackageRequirements
from daemon import daemon
from peewee import SqliteDatabase

import globals
from analysis_result import AnalysisResult
from binary_database import BinaryDetonationResult, db
from config_handling import ConfigurationInit
from feed import CbFeed, CbFeedInfo, CbReport
from tasks import analyze_binary, app, generate_rule_map, update_yara_rules_remote

logging_format = "%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s"
logging.basicConfig(format=logging_format)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger("celery.app.trace")
celery_logger.setLevel(logging.ERROR)


def promise_worker(exit_event, scanning_promise_queue, scanning_results_queue):
    """

    :param exit_event:
    :param scanning_promise_queue:
    :param scanning_results_queue:
    :return:
    """
    try:
        while not (exit_event.is_set()):
            if not (scanning_promise_queue.empty()):
                try:
                    promise = scanning_promise_queue.get(timeout=1.0)
                    result = promise.get(disable_sync_subtasks=False)
                    scanning_results_queue.put(result)
                except Empty:
                    exit_event.wait(1)
            else:
                exit_event.wait(1)
    finally:
        exit_event.set()

    logger.debug("PROMISE WORKING EXITING")


# noinspection PyUnusedFunction
def results_worker(exit_event, results_queue):
    """
    Sqlite is not meant to be thread-safe.

    This single-worker-thread writes the result(s) to the configured sqlite file to hold the feed-metadata and
    seen binaries/results from scans
    """
    try:
        while not (exit_event.is_set()):
            if not (results_queue.empty()):
                try:
                    result = results_queue.get()
                    save_results_with_logging(result)
                except Empty:
                    exit_event.wait(1)
            else:
                exit_event.wait(1)
    finally:
        exit_event.set()

    logger.debug("Results worker thread exiting")


def results_worker_chunked(exit_event, results_queue: Queue):
    """

    :param exit_event:
    :param results_queue:
    :return:
    """
    try:
        while not (exit_event.is_set()):
            if not (results_queue.empty()):
                try:
                    results = results_queue.get()
                    save_results(results)
                except Empty:
                    exit_event.wait(1)
            else:
                exit_event.wait(1)
    finally:
        exit_event.set()

    logger.debug("Results worker thread exiting")


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
    with open(globals.g_output_file, "w") as fp:
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
                md5 = hashlib.md5()
                md5.update(data)
                temp_list.append(str(md5.hexdigest()))

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


def analyze_binary_and_queue(scanning_promise_queue, md5sum):
    """ Analyze Binary And Queue """
    promise = analyze_binary.delay(md5sum)
    scanning_promise_queue.put(promise)


# noinspection PyUnusedFunction
def analyze_binaries_and_queue(scanning_promise_queue, md5_hashes):
    """ Analyze each binary and enqueue """
    for h in md5_hashes:
        analyze_binary_and_queue(scanning_promise_queue, h)


def analyze_binaries_and_queue_chunked(scanning_promise_queue, md5_hashes):
    """
        Attempts to do work in parrallelized chunks of MAX_HASHES grouped
    """
    promise = analyze_binary.chunks(
        [(mh,) for mh in md5_hashes], globals.g_max_hashes
    ).apply_async()
    for prom in promise.children:
        scanning_promise_queue.put(prom)


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


def get_binary_file_cursor(conn, start_date_binaries):
    logger.debug("Getting database cursor...")

    cur = conn.cursor(name="yara_agent")

    # noinspection SqlDialectInspection,SqlNoDataSourceInspection
    query = (
        "SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND "
        + "timestamp >= '{0}' ORDER BY timestamp DESC".format(start_date_binaries)
    )

    logger.debug(query)

    cur.execute(query)

    return cur


def execute_script() -> None:
    """
    Execute a external maintenence script (vacuum script).
    """
    logger.info(
        "----- Executing vacuum script ----------------------------------------"
    )
    prog = subprocess.Popen(
        globals.g_vacuum_script, shell=True, universal_newlines=True
    )
    stdout, stderr = prog.communicate()
    if stdout is not None and len(stdout.strip()) > 0:
        logger.info(stdout)
    if stderr is not None and len(stderr.strip()) > 0:
        logger.error(stderr)
    if prog.returncode:
        logger.warning(f"program returned error code {prog.returncode}")
    logger.info(
        "---------------------------------------- Vacuum script completed -----\n"
    )


def perform(yara_rule_dir: str, conn, scanning_promises_queue: Queue):
    """
    Main routine - checks the cbr modulestore/storfiles table for new hashes by comparing the sliding-window
    with the contents of the feed database on disk.

    :param yara_rule_dir: location of the rules directory
    :param conn: The connection (TODO: type)
    :param scanning_promises_queue:
    """
    if globals.g_remote:
        logger.info("Uploading yara rules to workers...")
        generate_rule_map_remote(yara_rule_dir)

    # Determine our binaries window (date forward)
    start_date_binaries = datetime.now() - timedelta(days=globals.g_num_days_binaries)

    # vacuum script window start
    vacuum_window_start = datetime.now()

    cur = get_binary_file_cursor(conn, start_date_binaries)
    rows = cur.fetchmany(2000)
    num_total_binaries = len(rows)

    while num_total_binaries > 0:
        logger.info(f"Enumerating modulestore...found {len(rows)} resident binaries")

        md5_hashes = filter(_check_hash_against_feed, (row[0].hex() for row in rows))

        # logger.debug(f"After filtering...found new {len(md5_hashes)} hashes to scan")

        analyze_binaries_and_queue_chunked(scanning_promises_queue, md5_hashes)

        """
            Holding the named-cursor through  a large historical result set
            will cause storefiles table fragmentation
            After a configurable amount of time - use the configured 
            script to vacuum the table by hand before continuing
        """

        if globals.g_vacuum_interval > 0:
            seconds_since_start = (datetime.now() - vacuum_window_start).seconds
            if seconds_since_start >= globals.g_vacuum_interval * 60:
                # close connection
                cur.close()
                conn.commit()

                execute_script()
                vacuum_window_start = datetime.now()

                # get the connection back
                cur = get_binary_file_cursor(conn, start_date_binaries)

        rows = cur.fetchmany(2000)
        num_total_binaries = len(rows)

    # Closing since there are no more binaries of interest to scan
    cur.close()
    conn.commit()

    logger.debug("Exiting database sweep routine")


def _check_hash_against_feed(md5_hash):
    query = BinaryDetonationResult.select().where(
        BinaryDetonationResult.md5 == md5_hash
    )

    if query.exists():
        return False

    return True


def save_results_with_logging(analysis_results):
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


# noinspection PyUnusedFunction
def save_and_log(
    analysis_results, start_time, num_binaries_skipped, num_total_binaries
):
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


def get_log_file_handles(use_logger):
    """ Get a list of filehandle numbers from logger
        to be handed to DaemonContext.files_preserve
    """
    handles = []
    for handler in use_logger.handlers:
        handles.append(handler.stream.fileno())
    if use_logger.parent:
        handles += get_log_file_handles(use_logger.parent)
    return handles


# noinspection PyUnusedLocal
def handle_sig(exit_event, sig, frame):
    """
      Signal handler - handle the signal and mark exit if its an exiting signal
    """
    exit_sigs = (signal.SIGTERM, signal.SIGQUIT, signal.SIGKILL)
    if sig in exit_sigs:
        exit_event.set()
        logger.debug("Sig handler set exit event")


#
# wait until the exit_event has been set by the signal handler
#
def run_to_exit_signal(exit_event):
    exit_event.wait()
    logger.debug("Begin graceful shutdown...")


def init_local_resources():
    """
        Initialize the local resources required to get module information
        from cbr module store as well as local storage of module and scanning
        metadata in sqlite 'binary.db' - generate an initial fead from the 
        database

        generate yara_rule_set metadata
    """
    globals.g_yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
    generate_yara_rule_map_hash(globals.g_yara_rules_dir)
    database = SqliteDatabase(os.path.join(globals.g_feed_database_dir, "binary.db"))
    db.initialize(database)
    db.connect()
    db.create_tables([BinaryDetonationResult])
    generate_feed_from_db()


def wait_all_worker_exit():
    """ Await the exit of our worker threads """
    threadcount = 2
    while threadcount > 1:
        threads = list(
            filter(
                lambda running_thread: not running_thread.daemon
                if hasattr(running_thread, "daemon")
                else True,
                threading.enumerate(),
            )
        )
        threadcount = len(threads)
        logger.debug(
            f"Main thread Waiting on {threadcount} live worker-threads (exluding deamons)..."
        )
        logger.debug(f"Live threads (excluding daemons): {threads}")
        time.sleep(0.1)
        pass

    logger.debug("Main thread going to exit...")


def start_workers(exit_event: Event, scanning_promises_queue: Queue, scanning_results_queue: Queue) -> None:
    """
    Starts worker-threads (not celery workers). Worker threads do work until they get the exit_event signal
    :param exit_event: event signaller
    :param scanning_promises_queue: promises queue
    :param scanning_results_queue: results queue
    """
    logger.debug("Starting perf thread")
    perf_thread = DatabaseScanningThread(globals.g_scanning_interval, scanning_promises_queue, exit_event)
    perf_thread.start()

    logger.debug("Starting promise thread(s)")
    for _ in range(2):
        promise_worker_thread = Thread(target=promise_worker, args=(exit_event, scanning_promises_queue,
                                                                    scanning_results_queue))
        promise_worker_thread.start()

    logger.debug("Starting results saver thread")
    results_worker_thread = Thread(target=results_worker_chunked, args=(exit_event, scanning_results_queue))
    results_worker_thread.start()


class DatabaseScanningThread(Thread):
    """
    A worker thread that scans over the database for new hashes ever INTERVAL seconds
    Pushes work to scanning_promises_queue , exits when the event is triggered
    by the signal handler
    """

    def __init__(self, interval: int, scanning_promises_queue: Queue, exit_event: Event, *args, **kwargs):
        """

        :param interval:
        :param scanning_promises_queue: promises queue
        :param exit_event: event signaller
        :param args: optional arguments
        :param kwargs: optional keyword arguments
        """
        super().__init__(*args, **kwargs)

        self._args = args
        self._kwargs = kwargs
        self.exit_event = exit_event
        self._conn = get_database_conn()
        self._interval = interval
        self._scanning_promises_queue = scanning_promises_queue
        self._target = self.scan_until_exit

    def scan_until_exit(self):
        # TODO: DRIFT
        self.do_db_scan()
        while not self.exit_event.is_set():
            self.exit_event.wait(timeout=self._interval)
            if self.exit_event.is_set():
                break
            else:
                self.do_db_scan()
        logger.debug("Database Scanning Thread told to exit")
        return

    def do_db_scan(self):
        logger.debug("START database sweep")
        try:
            perform(globals.g_yara_rules_dir, self._conn, self._scanning_promises_queue)
        except Exception as e:
            logger.error(
                f"Something went wrong sweeping the CbR module store...{str(e)} \n {traceback.format_exc()}"
            )

    def run(self):
        """ Represents the lifetime of the thread """

        try:
            if self._target:
                # noinspection PyArgumentList
                self._target(*self._args, **self._kwargs)
        finally:
            # Avoid a refcycle if the thread is running a function with
            # an argument that has a member that points to the thread.
            # shutdown database connection
            self._conn.close()
            del self._target, self._args, self._kwargs
            logger.debug("Database scanning Thread Exiting gracefully")
            self.exit_event.set()


# Start celery worker in a daemon-thread
# TODO - Aggresive autoscaling config options
def start_celery_worker_thread(config_file):
    t = Thread(target=launch_celery_worker, kwargs={"config_file": config_file})
    t.daemon = True
    t.start()


# launch a celery worker using the imported app context
def launch_celery_worker(config_file=None):
    localworker = worker.worker(app=app)
    localworker.run(config_file=config_file)
    logger.debug("CELERY WORKER LAUNCHING THREAD EXITED")


################################################################################
# Main entrypoint
################################################################################


def handle_arguments():
    """
    Setup the main program options.

    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description="Yara Agent for Yara Connector")

    parser.add_argument(
        "--config-file",
        required=True,
        default="yaraconnector.conf",
        help="Location of the config file",
    )
    parser.add_argument(
        "--log-file", default="yaraconnector.log", help="Log file output"
    )
    parser.add_argument(
        "--output-file", default="yara_feed.json", help="output feed file"
    )
    parser.add_argument(
        "--working-dir", default=".", help="working directory", required=False
    )
    parser.add_argument(
        "--lock-file", default="./yaraconnector", help="lock file", required=False
    )
    parser.add_argument(
        "--validate-yara-rules",
        action="store_true",
        help="Only validate yara rules, then exit",
    )
    parser.add_argument("--debug", action="store_true")

    return parser.parse_args()


def main():
    """
    Main execution function.  Script will exit with a non-zero value based on the following:
        1: Not the only instance running
        2: Configuration problem
        3: User interrupt
        4: Unexpected Yara scan exception
        5: Yara rule validation problem
    """
    args = handle_arguments()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.log_file:
        use_log_file = os.path.abspath(os.path.expanduser(args.log_file))
        formatter = logging.Formatter(logging_format)
        handler = logging.handlers.RotatingFileHandler(
            use_log_file, maxBytes=10 * 1000000, backupCount=10
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    else:
        use_log_file = None

    # Verify the configuration file and load up important global variables
    try:
        ConfigurationInit(args.config_file, use_log_file)
    except Exception as err:
        logger.error(f"Unable to continue due to a configuration problem: {err}")
        sys.exit(2)

    if args.validate_yara_rules:
        logger.info(f"Validating yara rules in directory: {globals.g_yara_rules_dir}")
        yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
        try:
            yara.compile(filepaths=yara_rule_map)
            logger.info("All yara rules compiled successfully")
        except Exception as err:
            logger.error(
                f"There were errors compiling yara rules: {err}\n{traceback.format_exc()}"
            )
            sys.exit(5)
    else:
        exit_event = Event()

        try:
            working_dir = os.path.abspath(os.path.expanduser(args.working_dir))

            lock_file = lockfile.FileLock(args.lock_file)

            files_preserve = get_log_file_handles(logger)
            files_preserve.extend([args.lock_file, args.log_file, args.output_file])

            # defauls to piping to /dev/null

            deamon_kwargs = {
                "working_directory": working_dir,
                "pidfile": lock_file,
                "files_preserve": files_preserve,
            }
            if args.debug:
                deamon_kwargs.update({"stdout": sys.stdout, "stderr": sys.stderr})
            context = daemon.DaemonContext(**deamon_kwargs)

            run_as_master = globals.g_mode == "master"

            scanning_promise_queue = Queue()
            scanning_results_queue = Queue()

            sig_handler = partial(handle_sig, exit_event)

            context.signal_map = {
                signal.SIGTERM: sig_handler,
                signal.SIGQUIT: sig_handler,
            }

            with context:
                # only connect to cbr if we're the master
                if run_as_master:
                    init_local_resources()
                    start_workers(exit_event, scanning_promise_queue, scanning_results_queue)
                    # start local celery if working mode is local
                    if not globals.g_remote:
                        start_celery_worker_thread(args.config_file)
                else:
                    # otherwise, we must start a worker since we are not the master
                    start_celery_worker_thread(args.config_file)

                # run until the service/daemon gets a quitting sig
                run_to_exit_signal(exit_event)
                wait_all_worker_exit()
                logger.info("Yara connector shutdown OK")

        except KeyboardInterrupt:
            logger.info("\n\n##### Interupted by User!\n")
            exit_event.set()
            sys.exit(3)
        except Exception as err:
            logger.error(
                f"There were errors executing yara rules: {err}\n{traceback.format_exc()}"
            )
            exit_event.set()
            sys.exit(4)


if __name__ == "__main__":
    main()
