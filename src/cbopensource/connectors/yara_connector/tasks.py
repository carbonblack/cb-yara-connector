# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import datetime
import glob
import logging
import multiprocessing
import os
import traceback

import urllib3
# noinspection PyPackageRequirements
import yara
# noinspection PyProtectedMember
from celery import bootsteps, Task
from celery.utils.log import get_task_logger

from .analysis_result import AnalysisResult
from .celery_app import app
from .config_handling import YaraConnectorConfig
from .rule_handling import generate_rule_map
from .task_utils import lookup_binary_by_hash, lookup_local_module

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = get_task_logger(__name__)
logger.setLevel(logging.CRITICAL)

rulelogger = logging.getLogger("yaraworker")
rulelogger.setLevel(logging.INFO)


# noinspection PyAbstractClass
class MyTask(Task):

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        pass
        # print('{0!r} failed: {1!r}'.format(task_id, exc))


# ----- Lock Object Class ------------------------------------------------------------


class ReadWriteLock:
    """
    A lock object that allows many simultaneous "read locks", but
    only one "write lock."
    """

    def __init__(self):
        self._read_ready = multiprocessing.Condition(multiprocessing.Lock())
        self._readers = 0

    def acquire_read(self) -> None:
        """
        Acquire a read lock. Blocks only if a thread has acquired the write lock.
        """
        self._read_ready.acquire()
        try:
            self._readers += 1
        finally:
            self._read_ready.release()

    def release_read(self) -> None:
        """
        Release a read lock.
        """
        self._read_ready.acquire()
        try:
            self._readers -= 1
            if not self._readers:
                self._read_ready.notify_all()
        finally:
            self._read_ready.release()

    def acquire_write(self) -> None:
        """
        Acquire a write lock. Blocks until there are no
        acquired read or write locks. """
        self._read_ready.acquire()
        while self._readers > 0:
            self._read_ready.wait()

    def release_write(self) -> None:
        """
        Release a write lock.
        """
        self._read_ready.release()


# ----- Actual task functions ------------------------------------------------------------

compiled_yara_rules = None
compiled_rules_hash = None
compiled_rules_lock = ReadWriteLock()


def add_minion_arguments(parser) -> None:
    """
    Add yara min minion configuration option.
    :param parser: option parser
    """
    parser.add_argument(
        "--config-file", default="yara_minion.conf", help="Yara minion config"
    )


app.user_options["worker"].add(add_minion_arguments)

yara_connector_configuration: YaraConnectorConfig = None


def set_task_config(config: YaraConnectorConfig):
    global yara_connector_configuration
    yara_connector_configuration = config


class MyBootstep(bootsteps.Step):
    """
    Define the bootstrap task.
    """

    # noinspection PyUnusedLocal
    def __init__(self, minion, config_file="yara_minion.conf", **options):
        super().__init__(self)
        set_task_config(YaraConnectorConfig(config_file, None))


app.steps["worker"].add(MyBootstep)


def write_rules_from_json(yara_rules: dict):
    global yara_connector_configuration
    try:
        for key in yara_rules:
            with open(os.path.join(yara_connector_configuration.yara_rules_dir, key), "wb") as fp:
                fp.write(yara_rules[key])
    except Exception as err:
        logger.exception(f"Error writing rule file: {err}")


@app.task(base=MyTask)
def update_yara_rules_task(remote=False, yara_rules=None):
    return update_yara_rules(remote, yara_rules)


def update_yara_rules(remote=False, yara_rules: dict = None) -> None:
    """
    Update remote yara rules.
    :param yara_rules: dict of rules, keyed by file name
    """
    if remote and yara_rules:
        write_rules_from_json(yara_rules)
    compile_yara_rules()


# Caller is obliged to compiled_rules_lock.release_read()
def compile_yara_rules():
    """
    gets a read-access on the in-memory set of yara rules , which are locked with multiple possible readers
    if there is no current in memory reference to the current yara rules
    this function attempts to read the yara-rules directory on the minion, and a produce a new set of compiled rules
    the rules are written to disk so that other minions can load them from disk rather than re-compiling them
    """
    global yara_connector_configuration

    rule_location = yara_connector_configuration.yara_rules_dir

    logger.debug("Updating Yara rules in minion(s)")
    yara_rule_map, ruleset_hash = generate_rule_map(rule_location)

    compiled_rules_filepath = os.path.join(
        rule_location, ".YARA_RULES_{0}".format(ruleset_hash)
    )
    logger.debug("Yara rule path is {0}".format(compiled_rules_filepath))

    new_rules_object = yara.compile(filepaths=yara_rule_map)
    rulelogger.info(f"Compiled new set of yara-rules  - {ruleset_hash} - ")
    for rulesetfp in glob.glob(os.path.join(rule_location, ".YARA_RULES_*")):
        os.remove(rulesetfp)
    rulelogger.info(f"Saved ruleset to disk {compiled_rules_filepath}")
    new_rules_object.save(compiled_rules_filepath)
    set_compiled_rules(new_rules_object, ruleset_hash)


def set_compiled_rules(new_rules_object, ruleset_hash: str):
    global compiled_yara_rules
    global compiled_rules_hash
    global compiled_rules_lock
    compiled_rules_lock.acquire_write()
    compiled_yara_rules = new_rules_object
    compiled_rules_hash = ruleset_hash
    logger.debug("Successfully updated Yara rules")
    compiled_rules_lock.release_write()


def get_module(md5hash, node_id: int):
    global yara_connector_configuration
    md5_up = md5hash.upper()
    current_node_id = yara_connector_configuration.node_id
    is_local = node_id == current_node_id
    module_store_path = yara_connector_configuration.module_store_location

    if is_local:
        found = lookup_local_module(md5_up, module_store_path)
        if found:
            return found

    return get_remote_binary_by_hash(md5_up)


def get_remote_binary_by_hash(hsum: str):
    """

        do a binary-retrival-by hash (husm) api call
        the configured server-by (url) using (token)
    """
    global yara_connector_configuration
    token = yara_connector_configuration.cb_server_token
    url = yara_connector_configuration.cb_server_url
    timeout = yara_connector_configuration.minion_network_timeout
    return lookup_binary_by_hash(hsum, url, token, timeout)


def scan_with_compiled_rules(binary_data):
    global compiled_yara_rules
    global compiled_rules_lock
    try:
        compiled_rules_lock.acquire_read()
        matches = compiled_yara_rules.match(data=binary_data.read(), timeout=30)
    finally:
        compiled_rules_lock.release_read()
    return matches


@app.task(base=MyTask)
def analyze_binary_task(md5sum: str, node_id=0) -> AnalysisResult:
    return analyze_binary(md5sum, node_id)


def analyze_binary(md5sum: str, node_id=0) -> AnalysisResult:
    """
    Analyze binary information.
    :param md5sum: md5 binary to check
    :return: AnalysisResult instance
    """

    logger.debug(f"{md5sum}: in analyze_binary")
    analysis_result = AnalysisResult(md5sum)

    try:
        analysis_result.last_scan_date = datetime.datetime.now()

        binary_data = get_module(md5sum, node_id)

        if not binary_data:
            logger.debug(f"No binary available for {md5sum}")
            analysis_result.binary_not_available = True
            return analysis_result

        try:
            matches = scan_with_compiled_rules(binary_data)
            # NOTE: Below is for debugging use only
            # matches = "debug"

            if matches:
                score = get_high_score(matches)
                analysis_result.score = score
                analysis_result.short_result = "Matched yara rules: %s" % ", ".join(
                    [match.rule for match in matches]
                )
                analysis_result.long_result = analysis_result.short_result
            else:
                analysis_result.score = 0
                analysis_result.short_result = "No Matches"
        except yara.TimeoutError:
            # yara timed out
            analysis_result.last_error_msg = "Analysis timed out after 60 seconds"
            analysis_result.stop_future_scans = True
            analysis_result.score = 0
        except yara.Error as err:
            # Yara errored while trying to scan binary
            analysis_result.last_error_msg = f"Yara exception: {err}"
            analysis_result.score = 0
        except Exception as err:
            analysis_result.score = 0
            analysis_result.last_error_msg = (
                    f"Other exception while matching rules: {err}\n"
                    + traceback.format_exc()
            )
        finally:
            binary_data.close()
            compiled_rules_lock.release_read()
        return analysis_result
    except Exception as err:
        error = f"Unexpected error: {err}\n" + traceback.format_exc()
        logger.error(error)
        analysis_result.last_error_msg = error
        return analysis_result


def get_high_score(matches) -> int:
    """
    Find the highest match score. If score is unset, default to 100.

    :param matches: List of rule matches.
    :return: highest score
    """
    # NOTE: if str(matches) == "debug", return 100
    if matches == "debug":
        return 100

    score = -1
    for match in matches:
        if match.meta.get("score", -1) > score:
            score = match.meta.get("score")
    if score == -1:
        return 100
    else:
        return score
