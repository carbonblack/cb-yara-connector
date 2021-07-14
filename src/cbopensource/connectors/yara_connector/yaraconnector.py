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
from threading import Event, Thread, Condition
from typing import List

# noinspection PyPackageRequirements
# noinspection PyPackageRequirements
from celery.bin.worker import worker
# noinspection PyPackageRequirements
from daemon import daemon
from peewee import SqliteDatabase

from .analysis_worker import analysis_minion
from .binary_database import get_analyzed_binaries, db, BinaryDetonationResult
from .celery_app import app
from .config_handling import YaraConnectorMode, YaraConnectorConfig
from .database_scanning import DatabaseScanningThread, ModuleStoreConnection
from .feed import generate_feed_from_db, feed_worker
from .loggers import logger, get_log_file_handles
from .results_worker import results_minion
from .tasks import set_task_config


class YaraConnector(object):

    def __init__(self, args, config: YaraConnectorConfig):
        self.exit_event = Event()
        self.hash_queue = Queue()
        self.scanning_results_queue = Queue()
        write_pid_file(args.pid_file)
        self.args = args
        # Operating mode - are we the primary?
        self.operation_mode = config.operation_mode
        self.config = config
        self.set_celery_conf_as_needed()

    def set_celery_conf_as_needed(self):
        if self.operation_mode in [YaraConnectorMode.PRIMARY, YaraConnectorMode.MINION]:
            app.conf.update(broker_url=self.config.broker_url, result_backend=self.config.results_backend)

    def alert_user_feed_location(self):
        if self.operation_mode in [YaraConnectorMode.PRIMARY, YaraConnectorMode.STANDALONE]:
            logger.critical(f"Manually add the feed to EDR by path file://{self.args.output_file}")

    def test_database_connectivity(self):
        # noinspection PyBroadException
        try:
            if self.operation_mode in [YaraConnectorMode.PRIMARY,
                                       YaraConnectorMode.STANDALONE] and not ModuleStoreConnection(
                self.config).test_database_conn():
                sys.exit(1)
        except Exception as ex:
            logger.error(F"Failed database connection test: {ex}")
            sys.exit(1)

    def run_daemon_mode(self):
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

        # Signal handler
        sig_handler = partial(handle_sig, self.exit_event)
        context.signal_map = {
            signal.SIGTERM: sig_handler,
            signal.SIGQUIT: sig_handler,
        }

        # Make sure we close the daemon context at the end
        threads = []
        with context:
            write_pid_file(self.args.pid_file)
            # only connect to cbr if we're the primary
            if self.operation_mode in [YaraConnectorMode.PRIMARY, YaraConnectorMode.STANDALONE]:
                # initialize local resources
                self.init_local_resources()

                # start working threads
                threads = self.start_worker_threads(run_only_once=False)
            else:
                # otherwise, we must start a celeryD worker since we are not the master
                local_minion = worker(app=app)
                threads.append(
                    start_celery_worker_thread(
                        local_minion, self.config.celery_worker_kwargs, self.args.config_file
                    )
                )

            # run until the service/daemon gets a quitting sig
            try:
                self.run_until_told_to_exit()
            except Exception as e:
                logger.exception(f"Error while executing: {e}")
            finally:
                try:
                    wait_all_worker_exit_threads(threads, timeout=4.0)
                finally:
                    logger.info("Yara connector shutdown")

    def run_batch(self):
        if self.operation_mode in [YaraConnectorMode.STANDALONE, YaraConnectorMode.PRIMARY]:
            self.init_local_resources()

        # start necessary worker threads
        threads = self.start_worker_threads(run_only_once=True)

        # Start a celery worker if we need one
        if self.operation_mode == YaraConnectorMode.MINION:
            local_minion = worker(app=app)
            threads.append(
                start_celery_worker_thread(
                    local_minion, self.config.celery_worker_kwargs, self.args.config_file
                )
            )
        self.run_until_told_to_exit()
        wait_all_worker_exit_threads(threads, timeout=4.0)

    def run(self):
        logger.info(f"Running in {self.operation_mode.name} mode")
        self.test_database_connectivity()
        if self.operation_mode in [YaraConnectorMode.PRIMARY, YaraConnectorMode.MINION] and self.config.celery_app_conf:
            app.conf.update(**self.config.celery_app_conf)
        elif self.operation_mode == YaraConnectorMode.STANDALONE:
            set_task_config(self.config)
        if self.args.daemon:
            self.run_daemon_mode()
        else:
            self.run_batch()

    def exit(self, wait_timeout=None):
        self.exit_event.set()
        if wait_timeout:
            time.sleep(wait_timeout)

    def init_local_resources(self) -> None:
        """
        Initialize the local resources required to get module information
        from cbr module store as well as local storage of module and scanning
        metadata in sqlite 'binary.db' - generate an initial fead from the
        database.

        generate yara_rule_set metadata
        """
        database = SqliteDatabase(os.path.join(self.config.feed_database_dir, "binary.db"))
        db.initialize(database)
        db.connect()
        db.create_tables([BinaryDetonationResult])
        generate_feed_from_db(self.args.output_file)

        #

    # wait until the exit_event has been set by the signal handler
    #
    def run_until_told_to_exit(self) -> None:
        last_numbins = 0
        while not (self.exit_event.is_set()):
            self.exit_event.wait(30.0)
            if self.operation_mode in [YaraConnectorMode.STANDALONE, YaraConnectorMode.PRIMARY]:
                numbins = get_analyzed_binaries()
                if numbins != last_numbins:
                    logger.info(f"Analyzed {numbins} binaries so far ... ")
                    last_numbins = numbins
        self.exit(5.0)

    def start_worker_threads(self, run_only_once=False) -> List[Thread]:
        is_standalone_mode = self.config.operation_mode == YaraConnectorMode.STANDALONE
        threads = []

        feed_thread = Thread(
            target=feed_worker, args=(self.exit_event, self.config.output_file)
        )
        feed_thread.start()
        threads.append(feed_thread)

        perf_thread = DatabaseScanningThread(self.config,
                                             self.hash_queue,
                                             self.scanning_results_queue,
                                             self.exit_event,
                                             run_only_once,
                                             is_standalone_mode=is_standalone_mode
                                             )
        perf_thread.start()
        threads.append(perf_thread)

        max_hashes = self.config.max_hashes

        number_of_analysis_workers = max_hashes * 2 if is_standalone_mode else 1
        for i in range(0, number_of_analysis_workers):
            analysis_minion_thread = Thread(
                target=analysis_minion,
                args=(i, self.exit_event, self.hash_queue, self.scanning_results_queue, not is_standalone_mode)
            )
            analysis_minion_thread.start()
            threads.append(analysis_minion_thread)

        results_minion_thread = Thread(
            target=results_minion, args=(self.exit_event, self.scanning_results_queue, not is_standalone_mode)
        )
        results_minion_thread.start()
        threads.append(results_minion_thread)

        return threads


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


def wait_all_worker_exit_threads(threads, timeout=None):
    """ return when all of the given threads
         have exited (sans daemon threads) """
    living_threads_count = len(threads)
    start = time.time()
    while living_threads_count > 1:
        living_threads_count = len(
            list(
                filter(
                    lambda t: t.is_alive() and not getattr(t, "daemon", True), threads
                )
            )
        )
        time.sleep(0.1)
        now = time.time()
        elapsed = now - start
        if timeout and elapsed >= timeout:
            return


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
