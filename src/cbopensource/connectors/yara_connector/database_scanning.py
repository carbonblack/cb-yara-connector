import os
import subprocess
import time
from datetime import datetime, timedelta
from queue import Queue
from threading import Event, Thread

import psycopg2

from . import globals
from .binary_database import BinaryDetonationResult
from .loggers import logger
from .tasks import update_yara_rules_remote


class ModuleStoreConnection(object):

    def __init__(self):
        self._conn = None

    @property
    def conn(self):
        if not self._conn:
            self._conn = self.get_database_connection()
        return self._conn

    def get_hashes(self):
        try:
            # Determine our binaries window (date forward)
            start_date_binaries = datetime.now() - timedelta(days=globals.g_num_days_binaries)
            cursor = self.get_binary_file_cursor(start_date_binaries)
            rows = cursor.fetchall()
            # Closing since there are no more binaries of interest to scan
            cursor.close()
            self.conn.commit()
            logger.info(f"Enumerating modulestore...found {len(rows)} resident binaries")
            return rows
        except Exception:
            self.reset_connection()
            logger.info(f"Enumerating modulestore...connection is dead will retry")
            return []

    def get_binary_file_cursor(self, start_date_binaries: datetime):
        """
        Get the cursor index to the binaries.

        :param conn: the postgres connection
        :param start_date_binaries: earliest start time for the search window (up to now)
        :return: the results cursor
        """
        logger.debug("Getting database cursor...")

        cur = self.conn.cursor(name="yara_agent")

        # noinspection SqlDialectInspection,SqlNoDataSourceInspection
        query = (
                "SELECT md5hash FROM storefiles WHERE present_locally = TRUE AND "
                + "timestamp >= '{0}' ORDER BY timestamp DESC".format(start_date_binaries)
        )

        logger.debug(query)
        cur.execute(query)

        return cur

    @staticmethod
    def get_database_connection(should_log=True):
        """
        Get a postgres database connection.

        :return: the connection
        """
        if should_log:
            logger.info("Connecting to Postgres database...")
        conn = psycopg2.connect(
            host=globals.g_postgres_host,
            database=globals.g_postgres_db,
            user=globals.g_postgres_username,
            password=globals.g_postgres_password,
            port=globals.g_postgres_port,
        )
        return conn

    @staticmethod
    def test_database_conn() -> bool:
        """
        Tests the connection to the postgres database.  Closes the connection if successful.
        :return: Returns True if connection to db was successful.
        """
        logger.info("Testing connection to Postgres database...")
        try:
            conn = ModuleStoreConnection.get_database_connection(False)
            conn.close()
        except psycopg2.DatabaseError as ex:
            logger.error(F"Failed to connect to postgres database: {ex}")
            return False
        return True

    def reset_connection(self):
        self._conn = None

    def close(self):
        self._conn.close()


class Performer(object):

    def __init__(self, hash_queue: Queue):
        self._hash_queue = hash_queue
        self._module_store_connection = ModuleStoreConnection()
        self._yara_rules_dir = globals.g_yara_rules_dir

    def close(self):
        self._module_store_connection.close()

    @staticmethod
    def execute_script() -> None:
        """
        Execute an external utility script.
        """
        logger.info(
            "----- Executing utility script ----------------------------------------"
        )
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
        logger.info(
            "---------------------------------------- Utility script completed -----\n"
        )

    def perform(self) -> None:
        """
        Main routine - checks the cbr modulestore/storfiles table for new hashes by comparing the sliding-window
        with the contents of the feed database on disk.

        :param yara_rule_dir: location of the rules directory
        :param conn: The postgres connection
        :param hash_queue: the queue of hashes to handle
        """
        if globals.g_mode == "master" or globals.g_mode == "primary":
            logger.info("Uploading Yara rules to minions...")
            self.generate_rule_map_remote()

        # utility script window start
        utility_window_start = datetime.now()

        rows = self._module_store_connection.get_hashes()

        md5_hashes = list(filter(Performer._check_hash_against_feed, (row[0].hex() for row in rows)))
        self._hash_queue.put(md5_hashes)

        # if gathering and analysis took longer than out utility script interval window, kick it off
        if globals.g_utility_interval > 0:
            seconds_since_start = (datetime.now() - utility_window_start).seconds
            if (
                    seconds_since_start >= globals.g_utility_interval * 60
                    if not globals.g_utility_debug
                    else 1
            ):
                Performer.execute_script()

        logger.info(f"Queued {len(md5_hashes)} new binaries for analysis")

        logger.debug("Exiting database sweep routine")

    @staticmethod
    def _check_hash_against_feed(md5_hash: str) -> bool:
        """
        Check discovered hash against the current feed.
        :param md5_hash: md5 hash
        :return: True if the hash needs to be added
        """
        query = BinaryDetonationResult.select().where(
            BinaryDetonationResult.md5 == md5_hash
        )
        # logger.debug(f"Hash = {md5_hash} exists = {query.exists()}")
        return not query.exists()

    def generate_rule_map_remote(self) -> None:
        """
        Get remote rules and store into an internal map keyed by file name.

        :param yara_rule_path: path to where the rules are stored
        """
        ret_dict = {}
        for fn in os.listdir(self._yara_rules_dir):
            if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
                fullpath = os.path.join(self._yara_rules_dir, fn)
                if not os.path.isfile(fullpath):
                    continue
                with open(os.path.join(self._yara_rules_dir, fn), "rb") as fp:
                    ret_dict[fn] = fp.read()

        result = update_yara_rules_remote.delay(ret_dict)
        globals.g_yara_rule_map = ret_dict
        while not result.ready():
            time.sleep(0.1)


class DatabaseScanningThread(Thread):
    """
    A worker thread that scans over the database for new hashes ever INTERVAL seconds
    Pushes work to scanning_promises_queue , exits when the event is triggered
    by the signal handler
    """

    def __init__(
            self,
            interval: int,
            hash_queue: Queue,
            scanning_results_queue: Queue,
            exit_event: Event,
            run_only_once: bool,
            *args,
            **kwargs,
    ):
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

        self.performer = Performer(hash_queue)
        self._args = args
        self._kwargs = kwargs
        self.exit_event = exit_event
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
        logger.debug("Scanning once before exit (batch)")
        self.do_db_scan()
        self._hash_queue.join()
        self._scanning_results_queue.join()
        self.exit_event.set()
        logger.debug("Batch done!")

    def scan_until_exit(self) -> None:
        """
        Continually scan the database until instructed to quit.
        """
        logger.debug("Scanning until exit...(continuous)")
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
        Do the actual database scan, traping any problems.
        """
        logger.debug("START database sweep")
        try:
            self.performer.perform()
        except Exception as err:
            logger.exception(
                f"Something went wrong sweeping the CbR module store: {err} "
            )

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
            self.performer.close()
            del self._target, self._args, self._kwargs
            logger.debug("Database scanning Thread Exiting gracefully")
            self.exit_event.set()
