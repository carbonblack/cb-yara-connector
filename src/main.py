# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import argparse
import json
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from functools import partial
from queue import Empty, Queue
from threading import Event, Thread
from typing import List

import lockfile
import psutil
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
from celery_app import app
from config_handling import ConfigurationInit
from feed import CbFeed, CbFeedInfo, CbReport
from rule_handling import generate_yara_rule_map_hash
from tasks import analyze_binary, generate_rule_map, update_yara_rules_remote

logging_format = "%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s"
logging.basicConfig(format=logging_format)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger("celery.app.trace")
celery_logger.setLevel(logging.CRITICAL)


def analysis_worker(exit_event: Event, hash_queue: Queue, scanning_results_queue: Queue) -> None:
    """
    The promise worker scanning function.

    :param exit_event: event signaller
    :param hash_queue 
    :param scanning_results_queue: the results queue
    """
    try:
        while not (exit_event.is_set()):
            if not (hash_queue.empty()):
                try:
                    exit_set = False
                    md5_hashes = hash_queue.get()
                    promise = analyze_binary.chunks([(mh,) for mh in md5_hashes], globals.g_max_hashes).apply_async()
                    for prom in promise.children:
                        exit_set = exit_event.is_set()
                        if exit_set:
                            break
                        results = prom.get(disable_sync_subtasks=False)
                        scanning_results_queue.put(results)
                    if not exit_set:
                        promise.get(disable_sync_subtasks=False, timeout=1)
                    else:
                        promise.forget()
                    hash_queue.task_done()
                except Empty:
                    exit_event.wait(1)
                except Exception as err:
                    logger.debug(f"Exception in wait: {err}")
                    exit_event.wait(0.1)
            else:
                exit_event.wait(1)
    finally:
        logger.debug(f"ANALYSIS WORKER EXITING {exit_event.is_set()}")


def results_worker_chunked(exit_event: Event, results_queue: Queue) -> None:
    """
    Prossess entries in the results queue in chunks.

    :param exit_event: event signaller
    :param results_queue: the results queue
    :return:
    """
    try:
        while not (exit_event.is_set()):
            if not (results_queue.empty()):
                try:
                    results = results_queue.get()
                    save_results(results)
                    results_queue.task_done()
                except Empty:
                    exit_event.wait(1)
            else:
                exit_event.wait(1)
    finally:
        logger.debug(f"Results worker thread exiting {exit_event.is_set()}")


def generate_feed_from_db() -> None:
    """
    Creates a feed based on specific database information and save to our output file.
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

    # logger.debug("Writing out feed '{0}' to disk".format(feedinfo.data["name"]))
    with open(globals.g_output_file, "w") as fp:
        fp.write(feed.dump())


def generate_rule_map_remote(yara_rule_path: str) -> None:
    """
    Get remote rules and store into an internal map keyed by file name.

    :param yara_rule_path: path to where the rules are stored
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


def save_results(analysis_results: List[AnalysisResult]) -> None:
    """
    Save the current set of analysis results.

    :param analysis_results: list of current analysis results
    """
    logger.debug(
        f"Saving {len(list(filter(lambda ar: not ar.binary_not_available, analysis_results)))} analysis results...")
    for analysis_result in analysis_results:
        save_result(analysis_result)


def save_result(analysis_result: AnalysisResult) -> None:
    """
    Save an individual analysis result.

    :param analysis_result: result to be saved
    """
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
        logger.exception("Error saving to database: {0}".format(err))
    else:
        if analysis_result.score > 0:
            generate_feed_from_db()


def get_database_conn():
    """
    Get a postgres database connection.

    :return: the connection
    """
    logger.info("Connecting to Postgres database...")
    conn = psycopg2.connect(
        host=globals.g_postgres_host,
        database=globals.g_postgres_db,
        user=globals.g_postgres_username,
        password=globals.g_postgres_password,
        port=globals.g_postgres_port,
    )
    return conn


def get_binary_file_cursor(conn, start_date_binaries: datetime):
    """
    Get the cursor index to the binaries.

    :param conn: the postgres connection
    :param start_date_binaries: earliest start time for the search window (up to now)
    :return: the results cursor
    """
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
    Execute an external utility script.
    """
    logger.info("----- Executing utility script ----------------------------------------")
    prog = subprocess.Popen(
        globals.g_utility_script, shell=True, universal_newlines=True
    )
    stdout, stderr = prog.communicate()
    if stdout is not None and len(stdout.strip()) > 0:
        logger.info(stdout)
    if stderr is not None and len(stderr.strip()) > 0:
        logger.error(stderr)
    if prog.returncode:
        logger.warning(f"program returned error code {prog.returncode}")
    logger.info("---------------------------------------- Utility script completed -----\n")


def perform(yara_rule_dir: str, conn, hash_queue: Queue) -> None:
    """
    Main routine - checks the cbr modulestore/storfiles table for new hashes by comparing the sliding-window
    with the contents of the feed database on disk.

    :param yara_rule_dir: location of the rules directory
    :param conn: The postgres connection
    :param hash_queue: the queue of hashes to handle
    """
    if globals.g_remote:
        logger.info("Uploading yara rules to workers...")
        generate_rule_map_remote(yara_rule_dir)

    # Determine our binaries window (date forward)
    start_date_binaries = datetime.now() - timedelta(days=globals.g_num_days_binaries)

    # utility script window start
    utility_window_start = datetime.now()

    cur = get_binary_file_cursor(conn, start_date_binaries)
    rows = cur.fetchall()
    # Closing since there are no more binaries of interest to scan
    cur.close()
    conn.commit()

    logger.info(f"Enumerating modulestore...found {len(rows)} resident binaries")

    md5_hashes = list(filter(_check_hash_against_feed, (row[0].hex() for row in rows)))
    hash_queue.put(md5_hashes)
    # analyze_binaries_and_queue_chunked(scanning_promises_queue, md5_hashes)

    # if gathering and analysis took longer than out utility script interval windo, kick it off
    if globals.g_utility_interval > 0:
        seconds_since_start = (datetime.now() - utility_window_start).seconds
        if seconds_since_start >= globals.g_utility_interval * 60 if not globals.g_utility_debug else 1:
            execute_script()

    logger.info(f"Queued {len(md5_hashes)} new binaries for analysis")

    logger.debug("Exiting database sweep routine")


def _check_hash_against_feed(md5_hash: str) -> bool:
    """
    Check discovered hash against the current feed.
    :param md5_hash: md5 hash
    :return: True if the hash needs to be added
    """
    query = BinaryDetonationResult.select().where(BinaryDetonationResult.md5 == md5_hash)
    # logger.debug(f"Hash = {md5_hash} exists = {query.exists()}")
    return not query.exists()


# FIXME: Unused
def save_results_with_logging(analysis_results: List[AnalysisResult]) -> None:
    """
    Save all analysis results, with extended logging.

    :param analysis_results: list of analysis results
    """
    logger.debug(analysis_results)
    if analysis_results:
        for analysis_result in analysis_results:
            logger.debug((f"Analysis result is {analysis_result.md5} {analysis_result.binary_not_available}"
                          f" {analysis_result.long_result} {analysis_result.last_error_msg}"))
            if analysis_result.last_error_msg:
                logger.error(analysis_result.last_error_msg)
        save_results(analysis_results)


def get_log_file_handles(use_logger) -> List:
    """
    Get a list of filehandle numbers from logger to be handed to DaemonContext.files_preserve.

    :param use_logger: logger to check
    :return: List of file handlers
    """
    handles = []
    for handler in use_logger.handlers:
        handles.append(handler.stream.fileno())
    if use_logger.parent:
        handles += get_log_file_handles(use_logger.parent)
    return handles


def handle_sig(exit_event: Event, sig: int) -> None:
    """
    Signal handler - handle the signal and mark exit if its an exiting signal type.

    :param exit_event: the event handler
    :param sig: the signal seen
    """
    exit_sigs = (signal.SIGTERM, signal.SIGQUIT, signal.SIGKILL)
    if sig in exit_sigs:
        exit_event.set()
        logger.debug("Sig handler set exit event")


#
# wait until the exit_event has been set by the signal handler
#
def run_to_exit_signal(exit_event: Event) -> None:
    """
    Wait-until-exit polling loop function.
    :param exit_event: the event handler
    """
    while not (exit_event.is_set()):
        exit_event.wait(30.0)
        numbins = BinaryDetonationResult.select().count()
        logger.info(f"Analyzed {numbins} binaries so far ... ")
    logger.debug("Begin graceful shutdown...")


def init_local_resources() -> None:
    """
    Initialize the local resources required to get module information
    from cbr module store as well as local storage of module and scanning
    metadata in sqlite 'binary.db' - generate an initial fead from the
    database.

    generate yara_rule_set metadata
    """
    globals.g_yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
    generate_yara_rule_map_hash(globals.g_yara_rules_dir, return_list=False)  # save to globals

    database = SqliteDatabase(os.path.join(globals.g_feed_database_dir, "binary.db"))
    db.initialize(database)
    db.connect()
    db.create_tables([BinaryDetonationResult])
    generate_feed_from_db()


def wait_all_worker_exit() -> None:
    """
    Await the exit of our worker threads.
    """
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
        logger.debug(f"Main thread Waiting on {threadcount} live worker-threads (exluding deamons)...")
        logger.debug(f"Live threads (excluding daemons): {threads}")
        time.sleep(0.1)

    logger.debug("Main thread going to exit...")


def start_workers(exit_event: Event, hash_queue: Queue, scanning_results_queue: Queue,
                  run_only_once=False) -> None:
    """
    Starts worker-threads (not celery workers). Worker threads do work until they get the exit_event signal
    :param exit_event: event signaller
    :param hash_queue: promises queue
    :param scanning_results_queue: results queue
    :param run_only_once: if True, run once an exit (default False)
    """
    logger.debug("Starting perf thread")
    perf_thread = DatabaseScanningThread(globals.g_scanning_interval, hash_queue, scanning_results_queue,
                                         exit_event, run_only_once)
    perf_thread.start()

    logger.debug("Starting analysis thread")
    analysis_worker_thread = Thread(target=analysis_worker,
                                    args=(exit_event, hash_queue, scanning_results_queue))
    analysis_worker_thread.start()

    logger.debug("Starting results saver thread")
    results_worker_thread = Thread(target=results_worker_chunked, args=(exit_event, scanning_results_queue))
    results_worker_thread.start()


class DatabaseScanningThread(Thread):
    """
    A worker thread that scans over the database for new hashes ever INTERVAL seconds
    Pushes work to scanning_promises_queue , exits when the event is triggered
    by the signal handler
    """

    def __init__(self, interval: int, hash_queue: Queue, scanning_results_queue: Queue, exit_event: Event,
                 run_only_once: bool, *args, **kwargs):
        """
        Create a new database scanning object.

        :param interval: interval in seconds between scans
        :param scanning_promises_queue: promises queue
        :param scanning_results_queue: results queue
        :param exit_event: event signaller
        :param run_only_once: if True, run once and then exit
        :param args: optional arguments
        :param kwargs: optional keyword arguments
        """
        super().__init__(*args, **kwargs)

        self._args = args
        self._kwargs = kwargs
        self.exit_event = exit_event
        self._conn = get_database_conn()
        self._interval = interval
        self._hash_queue = hash_queue
        self._scanning_results_queue = scanning_results_queue
        self._run_only_once = run_only_once
        if not self._run_only_once:
            self._target = self.scan_until_exit
        else:
            self._target = self.scan_once_and_exit

    def scan_once_and_exit(self) -> None:
        """
        Perform a database scan one, then exit.
        """
        self.do_db_scan()
        self._hash_queue.join()
        self._scanning_results_queue.join()
        self.exit_event.set()

    def scan_until_exit(self) -> None:
        """
        Continually scan the database until instructed to quit.
        """
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
        """
        Do the actual database scan, trappig ang problems.
        """
        logger.debug("START database sweep")
        try:
            perform(globals.g_yara_rules_dir, self._conn, self._hash_queue)

        except Exception as err:
            logger.exception(f"Something went wrong sweeping the CbR module store: {err} ")

    def run(self):
        """
        Represents the lifetime of the thread.
        """

        try:
            if self._target:
                # noinspection PyArgumentList
                self._target(*self._args, **self._kwargs)
        finally:
            # Avoid a recycle if the thread is running a function with
            # an argument that has a member that points to the thread.
            # shutdown database connection
            self._conn.close()
            del self._target, self._args, self._kwargs
            logger.debug("Database scanning Thread Exiting gracefully")
            self.exit_event.set()


def start_celery_worker_thread(worker_obj: worker.worker, workerkwargs: dict = None, config_file: str = None) -> None:
    """
    Start celery worker in a daemon-thread.

    TODO: - Aggresive autoscaling config options
    :param worker_obj: worker object
    :param workerkwargs: dictionary of arguments
    :param config_file: path to the yara configuration file
    :return:
    """
    t = Thread(target=launch_celery_worker,
               kwargs={"worker": worker_obj, "workerkwargs": workerkwargs, "config_file": config_file})
    t.daemon = True
    t.start()


def launch_celery_worker(worker_obj: worker.worker, workerkwargs=None, config_file: str = None) -> None:
    """
    Launch a celery worker using the imported app context
    :param worker_obj: worker object
    :param workerkwargs: dictionary of arguments
    :param config_file: optional path to a configuration file
    """
    logger.debug(f"Celery worker args are  {workerkwargs} ")
    if workerkwargs is None:
        worker_obj.run(loglevel=logging.ERROR, config_file=config_file, pidfile='/tmp/yaraconnectorceleryworker')
    else:
        worker_obj.run(loglevel=logging.ERROR, config_file=config_file, pidfile='/tmp/yaraconnectorceleryworker',
                       **workerkwargs)
    logger.debug("CELERY WORKER LAUNCHING THREAD EXITED")


def terminate_celery_worker(worker_obj: worker.worker = None):
    """
    Attempt to use the pidfile to gracefully terminate celery workers if they exist
    if the worker hasn't terminated gracefully after 5 seconds, kill it using the .die() command

    :param worker_obj: worker object
    """
    with open('/tmp/yaraconnectorceleryworker') as cworkerpidfile:
        worker_pid = int(cworkerpidfile.readline())
        parent = psutil.Process(worker_pid)
        children = parent.children(recursive=True)
        for child in children:
            logger.debug(f"Sending term sig to celery worker child - {worker_pid}")
            os.kill(child.pid, signal.SIGTERM)
        logger.debug(f"Sending term sig to celery worker - {worker_pid}")
        os.kill(worker_pid, signal.SIGTERM)

    time.sleep(5.0)
    if worker_obj:
        worker_obj.die("Worker terminated")


################################################################################
# Main entrypoint
################################################################################


def handle_arguments():
    """
    Setup the main program options.

    :return: parsed arguments
    """
    parser = argparse.ArgumentParser(description="Yara Agent for Yara Connector")

    # Controls config file  (ini)
    parser.add_argument(
        "--config-file",
        required=True,
        default="yaraconnector.conf",
        help="Location of the config file",
    )
    # Controls log file location+name
    parser.add_argument(
        "--log-file", default="yaraconnector.log", help="Log file output"
    )
    # Controls the output feed location+name
    parser.add_argument(
        "--output-file", default="yara_feed.json", help="output feed file"
    )
    # Controls the working directory
    parser.add_argument(
        "--working-dir", default=".", help="working directory", required=False
    )
    # Controls the lock File
    parser.add_argument(
        "--lock-file", default="./yaraconnector", help="lock file", required=False
    )
    # Controls batch vs continous mode , defaults to batch processing
    parser.add_argument(
        "--run-once", default=True, help="Run as batch mode or no", required=False
    )

    # Validates the rules
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
        1: Configuration problem
        2: Yara rule validation problem
        3: User interrupt
        4: Unexpected Yara scan exception
    """
    args = handle_arguments()

    # check for extended logging
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # check for additional log file
    if args.log_file:
        use_log_file = os.path.abspath(os.path.expanduser(args.log_file))
        formatter = logging.Formatter(logging_format)
        handler = logging.handlers.RotatingFileHandler(use_log_file, maxBytes=10 * 1000000, backupCount=10)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    # Verify the configuration file and load up important global variables
    try:
        ConfigurationInit(args.config_file, args.output_file)
    except Exception as err:
        logger.error(f"Unable to continue due to a configuration problem: {err}")
        sys.exit(1)

    if args.validate_yara_rules:
        logger.info(f"Validating yara rules in directory: {globals.g_yara_rules_dir}")
        yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
        try:
            yara.compile(filepaths=yara_rule_map)
            logger.info("All yara rules compiled successfully")
        except Exception as err:
            logger.error(f"There were errors compiling yara rules: {err}")
            sys.exit(2)
    else:  # Doing a real run
        # Exit condition and queues for doing work
        exit_event = Event()
        hash_queue = Queue()
        scanning_results_queue = Queue()
        # Lock file so this process is a singleton
        lock_file = lockfile.FileLock(args.lock_file)
        localworker = None
        workerkwargs = json.loads(globals.g_celeryworkerkwargs) if globals.g_celeryworkerkwargs is not None else None
        if workerkwargs and len(workerkwargs) == 0:
            workerkwargs = None

        try:
            if not args.run_once:  # Running as a deamon
                # Get working dir setting
                working_dir = os.path.abspath(os.path.expanduser(args.working_dir))

                # Mark files to be preserved
                files_preserve = get_log_file_handles(logger)
                files_preserve.extend([args.lock_file, args.log_file, args.output_file])

                # defaults to piping to /dev/null
                deamon_kwargs = {"working_directory": working_dir, "pidfile": lock_file,
                                 "files_preserve": files_preserve}

                # If in debug mode, make sure stdout and stderr don't go to /dev/null
                if args.debug:
                    deamon_kwargs.update({"stdout": sys.stdout, "stderr": sys.stderr})
                context = daemon.DaemonContext(**deamon_kwargs)

                # Operating mode - are we the master a worker?
                run_as_master = globals.g_mode == "master"

                # Signal handler partial function
                sig_handler = partial(handle_sig, exit_event)
                context.signal_map = {signal.SIGTERM: sig_handler, signal.SIGQUIT: sig_handler}

                # Make sure we close the deamon context at the end
                with context:
                    # only connect to cbr if we're the master
                    if run_as_master:
                        # initialize local resources
                        init_local_resources()

                        # start working threads
                        start_workers(exit_event, hash_queue, scanning_results_queue)

                        # start local celeryD worker if working mode is local
                        if not globals.g_remote:
                            localworker = worker.worker(app=app)
                            start_celery_worker_thread(localworker, workerkwargs, args.config_file)
                    else:
                        # otherwise, we must start a celeryD worker since we are not the master
                        localworker = worker.worker(app=app)
                        start_celery_worker_thread(localworker, workerkwargs, args.config_file)

                    # run until the service/daemon gets a quitting sig
                    run_to_exit_signal(exit_event)
                    wait_all_worker_exit()
                    terminate_celery_worker(localworker)
                    logger.info("Yara connector shutdown OK")
            else:  # Just do one batch
                # init local resources
                init_local_resources()

                # start necessary worker threads
                start_workers(exit_event, hash_queue, scanning_results_queue, run_only_once=True)

                # Start a celery worker if we need one
                if not globals.g_remote:
                    localworker = worker.worker(app=app)
                    start_celery_worker_thread(localworker, workerkwargs, args.config_file)
                run_to_exit_signal(exit_event)
                wait_all_worker_exit()
                terminate_celery_worker(localworker)
        except KeyboardInterrupt:
            logger.info("\n\n##### Interupted by User!\n")
        except Exception as err:
            logger.error(f"There were errors executing yara rules: {err}")
        finally:
            exit_event.set()
            # wait_all_worker_exit()
            terminate_celery_worker(localworker)


if __name__ == "__main__":
    main()
