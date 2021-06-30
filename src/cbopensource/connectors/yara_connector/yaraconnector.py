import logging
import logging
import logging.handlers
# noinspection PyUnresolvedReferences
import mmap  # NEEDED FOR RPM BUILD
import os
import signal
import sys
import time
from functools import partial
from queue import Queue
from threading import Event, Thread
from typing import List

# noinspection PyPackageRequirements
# noinspection PyPackageRequirements
from celery.bin.worker import worker
# noinspection PyPackageRequirements
from daemon import daemon
from peewee import SqliteDatabase

from . import globals
from .analysis_worker import analysis_minion
from .binary_database import BinaryDetonationResult, db
from .celery_app import app
from .database_scanning import DatabaseScanningThread, ModuleStoreConnection
from .feed import generate_feed_from_db
from .loggers import logger
from .results_worker import results_minion_chunked
from .rule_handling import generate_yara_rule_map_hash
from .tasks import generate_rule_map


class YaraConnector(object):

    def __init__(self, args):
        self.exit_event = Event()
        self.hash_queue = Queue()
        self.scanning_results_queue = Queue()
        write_pid_file(args.pid_file)
        self.args = args

    def run_as_deamon(self):
        logger.debug("RUNNING AS DEMON")
        # Get working dir setting
        working_dir = os.path.abspath(os.path.expanduser(self.args.working_dir))

        # Mark files to be preserved
        files_preserve = get_log_file_handles(logger)
        files_preserve.extend([self.args.log_file, self.args.output_file])

        context = daemon.DaemonContext(
            working_directory=working_dir,
            files_preserve=files_preserve,
            stdout=sys.stdout if self.args.debug else None,
            stderr=sys.stderr if self.args.debug else None
        )

        # Operating mode - are we the primary?
        run_as_primary = "master" in globals.g_mode or "primary" in globals.g_mode

        # noinspection PyBroadException
        try:
            if run_as_primary and not ModuleStoreConnection.test_database_conn():
                sys.exit(1)
        except Exception as ex:
            logger.error(F"Failed database connection test: {ex}")
            sys.exit(1)

        # Signal handler
        sig_handler = partial(handle_sig, self.exit_event)
        context.signal_map = {
            signal.SIGTERM: sig_handler,
            signal.SIGQUIT: sig_handler,
        }

        # Make sure we close the deamon context at the end
        threads = []
        with context:
            write_pid_file(self.args.pid_file)
            # only connect to cbr if we're the primary
            if run_as_primary:
                # initialize local resources
                init_local_resources()

                # start working threads
                threads = start_minions(
                    self.exit_event, self.hash_queue, self.scanning_results_queue
                )

                # start local celeryD worker if working mode is local
                if "worker" in globals.g_mode or "minion" in globals.g_mode:
                    local_minion = worker(app=app)
                    threads.append(
                        start_celery_worker_thread(
                            local_minion, globals.g_celery_worker_kwargs, self.args.config_file
                        )
                    )
            else:
                # otherwise, we must start a celeryD worker since we are not the master
                local_minion = worker(app=app)
                threads.append(
                    start_celery_worker_thread(
                        local_minion, globals.g_celery_worker_kwargs, self.args.config_file
                    )
                )

            # run until the service/daemon gets a quitting sig
            try:
                logger.debug("Started as demon OK")
                run_to_exit_signal(self.exit_event)
            except Exception as e:
                logger.exception(f"Error while executing: {e}")
            finally:
                try:
                    wait_all_worker_exit_threads(threads, timeout=4.0)
                finally:
                    logger.info("Yara connector shutdown")
                    # noinspection PyProtectedMember
                    os._exit(0)

    def run_batch(self):
        logger.debug("BATCH MODE")
        init_local_resources()

        # start necessary worker threads
        threads = start_minions(
            self.exit_event, self.hash_queue, self.scanning_results_queue, run_only_once=True
        )

        # Start a celery worker if we need one
        if "worker" in globals.g_mode or "minion" in globals.g_mode:
            local_minion = worker(app=app)
            threads.append(
                start_celery_worker_thread(
                    local_minion, globals.g_celery_worker_kwargs, self.args.config_file
                )
            )
        run_to_exit_signal(self.exit_event)
        wait_all_worker_exit_threads(threads, timeout=4.0)

    def run(self):
        if self.args.daemon:
            self.run_as_deamon()
        else:
            self.run_batch()


def write_pid_file(file_location: str):
    if not file_location:
        return
    try:
        os.makedirs(os.path.dirname(file_location), exist_ok=True)
        with open(file_location, 'w+') as f:
            f.write(str(os.getpid()))
    except (IOError, OSError) as ex:
        logger.error(F"Failed to write to PID file: {ex}")
        sys.exit(1)


# noinspection PyUnusedLocal
def handle_sig(exit_event: Event, sig: int, frame) -> None:
    """
    Signal handler - handle the signal and mark exit if its an exiting signal type.

    :param exit_event: the event handler
    :param sig: the signal seen
    :param frame: frame event (sent by DaemonContext, unused)
    """
    exit_sigs = (signal.SIGTERM, signal.SIGQUIT, signal.SIGKILL, signal.SIGQUIT)
    if sig in exit_sigs:
        exit_event.set()
        logger.debug("Sig handler set exit event")


#
# wait until the exit_event has been set by the signal handler
#
def run_to_exit_signal(exit_event: Event) -> None:
    """
    Wait-until-exit polling loop function.  Spam reduced by only updating when count changes.
    :param exit_event: the event handler
    """
    last_numbins = 0
    while not (exit_event.is_set()):
        exit_event.wait(30.0)
        if "master" in globals.g_mode or "primary" in globals.g_mode:
            numbins = BinaryDetonationResult.select().count()
            if numbins != last_numbins:
                logger.info(f"Analyzed {numbins} binaries so far ... ")
                last_numbins = numbins
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
    generate_yara_rule_map_hash(
        globals.g_yara_rules_dir, return_list=False
    )  # save to globals

    database = SqliteDatabase(os.path.join(globals.g_feed_database_dir, "binary.db"))
    db.initialize(database)
    db.connect()
    db.create_tables([BinaryDetonationResult])
    generate_feed_from_db()


def wait_all_worker_exit_threads(threads, timeout=None):
    """ return when all of the given threads
         have exited (sans daemon threads) """
    living_threads_count = 2
    start = time.time()
    while living_threads_count > 1:
        living_threads_count = len(
            list(
                filter(
                    lambda t: t.isAlive() and not getattr(t, "daemon", True), threads
                )
            )
        )
        time.sleep(0.1)
        now = time.time()
        elapsed = now - start
        if timeout and elapsed >= timeout:
            return


def start_minions(exit_event: Event, hash_queue: Queue, scanning_results_queue: Queue,
                  run_only_once=False) -> List[Thread]:
    """
    Starts minion-threads (not celery workers). Minion threads do work until they get the exit_event signal
    :param exit_event: event signaller
    :param hash_queue: promises queue
    :param scanning_results_queue: results queue
    :param run_only_once: if True, run once an exit (default False)
    """
    logger.debug("Starting perf thread")
    perf_thread = DatabaseScanningThread(
        globals.g_scanning_interval,
        hash_queue,
        scanning_results_queue,
        exit_event,
        run_only_once,
    )
    perf_thread.start()

    logger.debug("Starting analysis thread")
    analysis_minion_thread = Thread(
        target=analysis_minion, args=(exit_event, hash_queue, scanning_results_queue)
    )
    analysis_minion_thread.start()

    logger.debug("Starting results saver thread")
    results_minion_thread = Thread(
        target=results_minion_chunked, args=(exit_event, scanning_results_queue)
    )
    results_minion_thread.start()

    return [perf_thread, results_minion_thread, analysis_minion_thread]


def start_celery_worker_thread(worker_obj, workerkwargs: dict = None, config_file: str = None) -> Thread:
    """
    Start celery worker in a daemon-thread.

    TODO: - Aggressive autoscaling config options
    :param worker_obj: worker object
    :param workerkwargs: dictionary of arguments
    :param config_file: path to the yara configuration file
    :return the thread, started:
    """
    t = Thread(
        target=launch_celery_worker,
        kwargs={
            "worker_obj": worker_obj,
            "worker_kwargs": workerkwargs,
            "config_file": config_file,
        },
    )
    t.daemon = True
    t.start()

    return t


def launch_celery_worker(worker_obj, worker_kwargs=None, config_file: str = None) -> None:
    """
    Launch a celery worker using the imported app context
    :param worker_obj: worker object
    :param worker_kwargs: dictionary of arguments
    :param config_file: optional path to a configuration file
    """
    logger.debug(f"Celery minion args are  {worker_kwargs} ")
    if worker_kwargs is None:
        worker_obj.run(loglevel=logging.ERROR, config_file=config_file, pidfile='/tmp/yaraconnectorceleryworker')
    else:
        worker_obj.run(loglevel=logging.ERROR, config_file=config_file, pidfile='/tmp/yaraconnectorceleryworker',
                       **worker_kwargs)
    logger.debug("CELERY MINION LAUNCHING THREAD EXITED")


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
