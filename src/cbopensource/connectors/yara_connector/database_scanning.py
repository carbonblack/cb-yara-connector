import os
from datetime import datetime, timedelta
from queue import Queue
from threading import Event, Thread

import psycopg2

from .binary_database import does_hash_exist
from .config_handling import YaraConnectorConfig
from .loggers import logger, log_extra_information
from .tasks import update_yara_rules, update_yara_rules_task


class ModuleStoreConnection(object):

    def __init__(self, config):
        self._conn = None
        self.config = config
        self._is_initial_search = True
        self._initial_search_time = datetime.now() - timedelta(days=self.config.num_days_binaries)
        self._last_search_time = None

    @property
    def conn(self):
        if not self._conn:
            self._conn = self.get_database_connection()
        return self._conn

    @property
    def last_search_time(self):
        return self._last_search_time

    @last_search_time.setter
    def last_search_time(self, value):
        self._last_search_time = value

    def get_hashes(self):
        try:
            # Determine our binaries window (date forward)
            cursor = self.get_binary_file_cursor(
                self._initial_search_time if self._is_initial_search else self._last_search_time)
            rows = cursor.fetchall()
            # Closing since there are no more binaries of interest to scan
            cursor.close()
            self.conn.commit()
            if self._is_initial_search:
                logger.info(f"Initial search found {len(rows)} resident binaries in EDR")
            else:
                logger.info(f"Found {len(rows)} new resident binaries in EDR since last check")
            self._last_search_time = datetime.now()
            self._is_initial_search = False
            return rows
        except Exception as ex:
            self.reset_connection()
            logger.warning(f"EDR modulestore connection not working - will retry {ex}")
            return []

    def get_binary_file_cursor(self, start_date_binaries: datetime):

        cur = self.conn.cursor(name="yara_agent")

        # noinspection SqlDialectInspection,SqlNoDataSourceInspection
        query = (
                "SELECT md5hash, node_id FROM storefiles WHERE present_locally = TRUE AND "
                + "timestamp >= '{0}' ORDER BY timestamp DESC".format(start_date_binaries)
        )

        logger.debug(query)
        cur.execute(query)

        return cur

    def get_database_connection(self, should_log=True):
        """
        Get a postgres database connection.

        :return: the connection
        """
        if should_log:
            log_extra_information("Connecting to Postgres database...")
        conn = psycopg2.connect(
            host=self.config.postgres_host,
            database=self.config.postgres_db,
            user=self.config.postgres_username,
            password=self.config.postgres_password,
            port=self.config.postgres_port,
        )
        return conn

    def test_database_conn(self) -> bool:
        """
        Tests the connection to the postgres database.  Closes the connection if successful.
        :return: Returns True if connection to db was successful.
        """
        logger.debug("Testing connection to Postgres database...")
        try:
            conn = self.get_database_connection(False)
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

    def __init__(self, hash_queue: Queue, config: YaraConnectorConfig, is_standalone_mode=False):
        self._hash_queue = hash_queue
        self._module_store_connection = ModuleStoreConnection(config)
        self._yara_rules_dir = config.yara_rules_dir
        self.standalone_mode = is_standalone_mode
        self.current_ruleset_time = None

    def close(self):
        self._module_store_connection.close()

    def queue_hashes_for_scanning(self, md5_hashes, last_search_time):
        if self.standalone_mode:
            if self._hash_queue.empty():
                for entry in md5_hashes:
                    self._hash_queue.put(entry)
            else:
                # ensure that the last search time is not updated in this case
                self._module_store_connection.last_search_time = last_search_time
                logger.warning(
                    f"There are still too many outstanding scans - please increase the database scanning interval if "
                    f"this condition persists in your environment")
        else:
            self._hash_queue.put(md5_hashes)

        if len(md5_hashes) > 0:
            logger.info(f"Queued new binaries for analysis")
        else:
            logger.info("There were no new binaries queued for analysis")

    def perform(self) -> None:
        self.ensure_yara_rules_up_to_date()

        self.get_and_queue_hashes()

    @staticmethod
    def filter_hashes(rows):
        return list(filter(Performer._check_hash_against_feed, ((row[0].hex(), row[1]) for row in rows)))

    @staticmethod
    def _check_hash_against_feed(row) -> bool:
        md5_hash = row[0]
        return does_hash_exist(md5_hash)

    def get_rules_as_json(self):
        ret_dict = {}
        for fn in os.listdir(self._yara_rules_dir):
            if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
                fullpath = os.path.join(self._yara_rules_dir, fn)
                if not os.path.isfile(fullpath):
                    continue
                with open(os.path.join(self._yara_rules_dir, fn), "rb") as fp:
                    ret_dict[fn] = fp.read()
        return ret_dict

    @property
    def ruleset_has_changed(self):
        current_mod_time = os.path.getmtime(self._yara_rules_dir)
        return_value = current_mod_time != self.current_ruleset_time
        self.current_ruleset_time = current_mod_time
        return return_value

    def ensure_yara_rules_up_to_date(self) -> None:
        if self.ruleset_has_changed:
            log_extra_information("Configured yara ruleset has changed...updating compiled rules")
            if self.standalone_mode:
                update_yara_rules()
            else:
                self.do_remote_rule_update()
        else:
            logger.debug("Ruleset has not changed... Scanning with previous ruleset")

    def get_and_queue_hashes(self):
        original_last_scan_time = self._module_store_connection.last_search_time

        rows = self._module_store_connection.get_hashes()

        md5_hashes = Performer.filter_hashes(rows)

        self.queue_hashes_for_scanning(md5_hashes, original_last_scan_time)

    def do_remote_rule_update(self):
        rule_map = self.get_rules_as_json()
        result = update_yara_rules_task.delay(remote=True, yara_rules=rule_map)
        logger.debug("Waiting for remote minion to process ruleset...")
        try:
            result.wait(timeout=120)
        except Exception:
            logger.warning(
                "The remote minion has not finished processing yara ruleset update for 120 seconds. Ensure the "
                "remote minion is available and can reach the configured celery broker")
            raise Exception
        logger.info("Yara rules are up to date")


class DatabaseScanningThread(Thread):
    """
    A worker thread that scans over the database for new hashes ever INTERVAL seconds
    Pushes work to scanning_promises_queue , exits when the event is triggered
    by the signal handler
    """

    def __init__(
            self,
            config: YaraConnectorConfig,
            hash_queue: Queue,
            scanning_results_queue: Queue,
            exit_event: Event,
            run_only_once: bool,
            is_standalone_mode: bool = False,
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

        self.performer = Performer(hash_queue, config, is_standalone_mode=is_standalone_mode)
        self._args = args
        self._kwargs = kwargs
        self.exit_event = exit_event
        self._interval = config.scanning_interval
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
        try:
            logger.debug("Looking for new modules in EDR modulestore...")
            self.performer.perform()
        except Exception as err:
            logger.exception(
                f"Something went wrong sweeping the CbR module store: {err} "
            )

    def run(self):
        """
        Represents the lifetime of the thread.
        """
        logger.debug("Database sweeping thread starting")
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
            logger.debug("Database scanning thread exiting")
            self.exit_event.set()
