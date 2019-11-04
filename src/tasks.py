# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import datetime
import hashlib
import io
import logging
import multiprocessing
import os
import traceback
import zipfile
from typing import List

import requests
# noinspection PyPackageRequirements
import yara
from celery import bootsteps, Celery, group

import globals
from analysis_result import AnalysisResult
from config_handling import ConfigurationInit

app = Celery()
# noinspection PyUnusedName
app.conf.task_serializer = "pickle"
# noinspection PyUnusedName
app.conf.result_serializer = "pickle"
# noinspection PyUnusedName
app.conf.accept_content = {"pickle"}

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class ReadWriteLock:
    """ A lock object that allows many simultaneous "read locks", but
    only one "write lock." """

    def __init__(self):
        self._read_ready = multiprocessing.Condition(multiprocessing.Lock())
        self._readers = 0

    def acquire_read(self):
        """ Acquire a read lock. Blocks only if a thread has
        acquired the write lock. """
        self._read_ready.acquire()
        try:
            self._readers += 1
        finally:
            self._read_ready.release()

    def release_read(self):
        """ Release a read lock. """
        self._read_ready.acquire()
        try:
            self._readers -= 1
            if not self._readers:
                self._read_ready.notify_all()
        finally:
            self._read_ready.release()

    def acquire_write(self):
        """ Acquire a write lock. Blocks until there are no
        acquired read or write locks. """
        self._read_ready.acquire()
        while self._readers > 0:
            self._read_ready.wait()

    def release_write(self):
        """ Release a write lock. """
        self._read_ready.release()


compiled_yara_rules = None
compiled_rules_lock = ReadWriteLock()


def add_worker_arguments(parser):
    parser.add_argument(
        "--config-file", default="yara_worker.conf", help="Yara Worker Config"
    )


app.user_options["worker"].add(add_worker_arguments)


class MyBootstep(bootsteps.Step):
    """
    Define the bootstrap task.
    """

    # noinspection PyUnusedLocal
    def __init__(self, worker, config_file='yara_worker.conf', **options):
        super().__init__(self)
        ConfigurationInit(config_file, None)


app.steps["worker"].add(MyBootstep)


def generate_rule_map(yara_rule_path: str) -> dict:
    """
    Create a dictionary keyed by filename containing file paths
    :param yara_rule_path: location of yara rules
    :return:
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


# noinspection DuplicatedCode
def generate_yara_rule_map_hash(yara_rule_path: str) -> List:
    """
    Create a list of md5 hashes based on rule file contents.

    :param yara_rule_path: location of the yara rules
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

    temp_list.sort()
    return temp_list


@app.task
def update_yara_rules_remote(yara_rules: dict) -> None:
    """
    Update remote yara rules.
    :param yara_rules: dict of rules, keyed by file name
    :return:
    """
    try:
        for key in yara_rules:
            with open(os.path.join(globals.g_yara_rules_dir, key), "wb") as fp:
                fp.write(yara_rules[key])
    except Exception as err:
        logger.error(f"Error writing rule file: {err}")
        logger.error(traceback.format_exc())


def update_yara_rules():
    global compiled_yara_rules
    global compiled_rules_lock
    compiled_rules_lock.acquire_read()
    if compiled_yara_rules:
        logger.debug("Reading the Compiled rules")
        return
    else:
        logger.debug("Updating yara rules in worker(s)")
        yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
        new_rules_object = yara.compile(filepaths=yara_rule_map)
        compiled_rules_lock.release_read()
        compiled_rules_lock.acquire_write()
        compiled_yara_rules = new_rules_object
        logger.debug("Succesfully updated yara rules")
        compiled_rules_lock.release_write()
        compiled_rules_lock.acquire_read()
        return


def get_binary_by_hash(url, hsum, token):
    """
        do a binary-retrival-by hash (husm) api call against 
        the configured server-by (url) using (token)
    """
    headers = {"X-Auth-Token": token}
    request_url = f"{url}/api/v1/binary/{hsum}"
    response = requests.get(request_url, headers=headers, stream=True, verify=False,
                            timeout=globals.g_worker_network_timeout)
    if response:
        with zipfile.ZipFile(io.BytesIO(response.content)) as the_binary_zip:
            # the response contains the file ziped in 'filedata'
            fp = the_binary_zip.open("filedata")
            the_binary_zip.close()
            return fp
    else:
        # otherwise return None which will be interpreted correctly in analyze_binary as haven failed to lookup the hash
        return None


# noinspection PyUnusedFunction
@app.task
def analyze_bins(hashes):
    return group(analyze_binary.s(h) for h in hashes).apply_async()


@app.task
def analyze_binary(md5sum: str) -> AnalysisResult:
    """
    Analyze binary information.
    :param md5sum: md5 binary to check
    :return: AnalysisResult instance
    """
    global compiled_yara_rules
    global compiled_rules_lock

    logger.debug(f"{md5sum}: in analyze_binary")
    analysis_result = AnalysisResult(md5sum)

    try:
        analysis_result.last_scan_date = datetime.datetime.now()

        binary_data = get_binary_by_hash(
            globals.g_cb_server_url, md5sum.upper(), globals.g_cb_server_token
        )

        if not binary_data:
            logger.debug(f"No binary agailable for {md5sum}")
            analysis_result.binary_not_available = True
            return analysis_result

        try:
            # matches = "debug"
            update_yara_rules()
            matches = compiled_yara_rules.match(data=binary_data.read(), timeout=30)
            if matches:
                score = get_high_score(matches)
                analysis_result.score = score
                analysis_result.short_result = "Matched yara rules: %s" % ", ".join(
                    [match.rule for match in matches]
                )
                # analysis_result.short_result = "Matched yara rules: debug"
                analysis_result.long_result = analysis_result.long_result
                analysis_result.misc = generate_yara_rule_map_hash(
                    globals.g_yara_rules_dir
                )
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
    Find the higest match score.

    :param matches: List of rule matches.
    :return:
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
