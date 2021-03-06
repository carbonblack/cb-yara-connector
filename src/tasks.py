# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import datetime
import glob
import hashlib
import io
import logging
import multiprocessing
import os
import traceback
import zipfile

import requests
import urllib3
# noinspection PyPackageRequirements
import yara
# noinspection PyProtectedMember
from celery import bootsteps, Task
from celery.utils.log import get_task_logger

import globals
from analysis_result import AnalysisResult
from celery_app import app
from config_handling import ConfigurationInit
from rule_handling import generate_yara_rule_map_hash

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


class MyBootstep(bootsteps.Step):
    """
    Define the bootstrap task.
    """

    # noinspection PyUnusedLocal
    def __init__(self, minion, config_file="yara_minion.conf", **options):
        super().__init__(self)
        ConfigurationInit(config_file, None)


app.steps["worker"].add(MyBootstep)


def generate_rule_map(yara_rule_path: str) -> dict:
    """
    Create a dictionary keyed by filename containing file paths
    :param yara_rule_path: location of yara rules
    :return: dict of paths keyed by namespace
    """
    rule_map = {}
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
            fullpath = os.path.join(yara_rule_path, fn)
            if not os.path.isfile(fullpath):
                continue

            last_dot = fn.rfind(".")
            if last_dot != -1:
                namespace = fn[:last_dot]
            else:
                namespace = fn
            rule_map[namespace] = fullpath

    return rule_map


@app.task(base=MyTask)
def update_yara_rules_remote(yara_rules: dict) -> None:
    """
    Update remote yara rules.
    :param yara_rules: dict of rules, keyed by file name
    """
    try:
        for key in yara_rules:
            with open(os.path.join(globals.g_yara_rules_dir, key), "wb") as fp:
                fp.write(yara_rules[key])
    except Exception as err:
        logger.exception(f"Error writing rule file: {err}")


# Caller is obliged to compiled_rules_lock.release_read()
def update_yara_rules():
    """
    gets a read-access on the in-memory set of yara rules , which are locked with multiple possible readers
    if there is no current in memory reference to the current yara rules
    this function attempts to read the yara-rules directory on the minion, and a produce a new set of compiled rules
    the rules are written to disk so that other minions can load them from disk rather than re-compiling them
    """
    global compiled_yara_rules
    global compiled_rules_hash
    global compiled_rules_lock

    compiled_rules_lock.acquire_read()
    if compiled_yara_rules:
        logger.debug("Reading the Compiled rules")
    else:
        logger.debug("Updating Yara rules in minion(s)")
        yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
        generate_yara_rule_map_hash(globals.g_yara_rules_dir)
        md5sum = hashlib.md5()
        for h in globals.g_yara_rule_map_hash_list:
            md5sum.update(h.encode("utf-8"))
        rules_hash = md5sum.hexdigest()

        compiled_rules_filepath = os.path.join(
            globals.g_yara_rules_dir, ".YARA_RULES_{0}".format(rules_hash)
        )
        logger.debug("Yara rule path is {0}".format(compiled_rules_filepath))

        rules_already_exist = os.path.exists(compiled_rules_filepath)
        if not rules_already_exist:
            new_rules_object = yara.compile(filepaths=yara_rule_map)
            rulelogger.info(f"Compiled new set of yara-rules  - {rules_hash} - ")
            # remove old rule set files
            for rulesetfp in glob.glob(os.path.join(globals.g_yara_rules_dir, ".YARA_RULES_*")):
                os.remove(rulesetfp)
        else:
            rulelogger.info(f"Loaded compiled rule set from disk at {compiled_rules_filepath}")
            new_rules_object = yara.load(compiled_rules_filepath)
        compiled_rules_lock.release_read()
        compiled_rules_lock.acquire_write()
        if not rules_already_exist:
            rulelogger.info(f"Saved ruleset to disk {compiled_rules_filepath}")
            new_rules_object.save(compiled_rules_filepath)
        compiled_yara_rules = new_rules_object
        compiled_rules_hash = rules_hash
        logger.debug("Successfully updated Yara rules")
        compiled_rules_lock.release_write()
        compiled_rules_lock.acquire_read()
    # logger.debug("Exiting update routine ok")


def get_binary_by_hash(url: str, hsum: str, token: str):
    """

        do a binary-retrival-by hash (husm) api call 
        the configured server-by (url) using (token)
    """
    headers = {"X-Auth-Token": token}
    request_url = f"{url}/api/v1/binary/{hsum}"
    response = requests.get(
        request_url,
        headers=headers,
        stream=True,
        verify=False,
        timeout=globals.g_minion_network_timeout,
    )
    if response:
        with zipfile.ZipFile(io.BytesIO(response.content)) as the_binary_zip:
            # the response contains the file zipped in 'filedata'
            fp = the_binary_zip.open("filedata")
            the_binary_zip.close()
            return fp
    else:
        # otherwise return None which will be interpreted correctly in analyze_binary as haven failed to lookup the hash
        return None


@app.task(base=MyTask)
def analyze_binary(md5sum: str) -> AnalysisResult:
    """
    Analyze binary information.
    :param md5sum: md5 binary to check
    :return: AnalysisResult instance
    """
    global compiled_yara_rules
    global compiled_rules_hash
    global compiled_rules_lock

    logger.debug(f"{md5sum}: in analyze_binary")
    analysis_result = AnalysisResult(md5sum)

    try:
        analysis_result.last_scan_date = datetime.datetime.now()

        binary_data = get_binary_by_hash(
            globals.g_cb_server_url, md5sum.upper(), globals.g_cb_server_token
        )

        if not binary_data:
            logger.debug(f"No binary available for {md5sum}")
            analysis_result.binary_not_available = True
            return analysis_result

        try:
            update_yara_rules()

            matches = compiled_yara_rules.match(data=binary_data.read(), timeout=30)

            # NOTE: Below is for debugging use only
            # matches = "debug"

            if matches:
                score = get_high_score(matches)
                analysis_result.score = score
                analysis_result.short_result = "Matched yara rules: %s" % ", ".join(
                    [match.rule for match in matches]
                )
                # analysis_result.short_result = "Matched yara rules: debug"
                analysis_result.long_result = analysis_result.long_result
                analysis_result.misc = compiled_rules_hash
            else:
                analysis_result.score = 0
                analysis_result.short_result = "No Matches"
        except yara.TimeoutError:
            # yara timed out
            analysis_result.last_error_msg = "Analysis timed out after 60 seconds"
            analysis_result.stop_future_scans = True
        except yara.Error as err:
            # Yara errored while trying to scan binary
            analysis_result.last_error_msg = f"Yara exception: {err}"
        except Exception as err:
            analysis_result.last_error_msg = (
                    f"Other exception while matching rules: {err}\n"
                    + traceback.format_exc()
            )
        finally:
            compiled_rules_lock.release_read()
            binary_data.close()
        return analysis_result
    except Exception as err:
        error = f"Unexpected error: {err}\n" + traceback.format_exc()
        logger.error(error)
        analysis_result.last_error_msg = error
        return analysis_result


def get_high_score(matches) -> int:
    """
    Find the highest match score.

    :param matches: List of rule matches.
    :return: highest score
    """
    # NOTE: if str(matches) == "debug", return 100
    if matches == "debug":
        return 100

    score = 0
    for match in matches:
        if match.meta.get("score", 0) > score:
            score = match.meta.get("score")
    if score == 0:
        return 100
    else:
        return score
