import configparser
import datetime
import hashlib
import logging
import os
import traceback
from typing import List

# noinspection PyPackageRequirements
import yara
from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI
from celery import bootsteps, Celery

import globals
from analysis_result import AnalysisResult

app = Celery()
# noinspection PyUnusedName
app.conf.task_serializer = "pickle"
# noinspection PyUnusedName
app.conf.result_serializer = "pickle"
# noinspection PyUnusedName
app.conf.accept_content = {"pickle"}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def verify_config(config_file: str) -> bool:
    """
    Read and validate the current config file.
    :param config_file: path to the config file
    :return: True if valid
    """
    config = configparser.ConfigParser()
    config.read(config_file)

    if not config.has_section('general'):
        logger.error("Config file does not have a \'general\' section")
        return False

    if 'yara_rules_dir' in config['general']:
        globals.g_yara_rules_dir = config['general']['yara_rules_dir']

    if 'cb_server_url' in config['general']:
        globals.g_cb_server_url = config['general']['cb_server_url']

    if 'cb_server_token' in config['general']:
        globals.g_cb_server_token = config['general']['cb_server_token']

    if 'broker_url' in config['general']:
        app.conf.update(
            broker_url=config['general']['broker_url'],
            result_backend=config['general']['broker_url'])

    return True


def add_worker_arguments(parser):
    parser.add_argument('--config-file', default='yara_worker.conf', help='Yara Worker Config')


app.user_options['worker'].add(add_worker_arguments)


class MyBootstep(bootsteps.Step):

    # noinspection PyUnusedLocal
    def __init__(self, worker, config_file='yara_worker.conf', **options):
        super().__init__(self)
        verify_config(config_file)

        # g_yara_rules_dir = yara_rules_dir


app.steps['worker'].add(MyBootstep)


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

            last_dot = fn.rfind('.')
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
    md5 = hashlib.md5()

    temp_list = []
    for fn in os.listdir(yara_rule_path):
        if fn.lower().endswith(".yar") or fn.lower().endswith(".yara"):
            with open(os.path.join(yara_rule_path, fn), 'rb') as fp:
                data = fp.read()
                # TODO: Original logic did not have this, resulting in a cumulative hash for each file (linking them)
                md5.new()
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
            with open(os.path.join(globals.g_yara_rules_dir, key), 'wb') as fp:
                fp.write(yara_rules[key])
    except Exception as err:
        logger.error(f"Error writing rule file: {err}")
        logger.error(traceback.format_exc())


@app.task
def analyze_binary(md5sum: str) -> AnalysisResult:
    """
    Analyze binary information.
    :param md5sum: md5 binary to check
    :return: AnalysisResult instance
    """
    logger.debug(f"{md5sum}: in analyze_binary")
    analysis_result = AnalysisResult(md5sum)

    try:
        analysis_result.last_scan_date = datetime.datetime.now()

        cb = CbResponseAPI(url=globals.g_cb_server_url,
                           token=globals.g_cb_server_token,
                           ssl_verify=False,
                           timeout=5)

        binary_query = cb.select(Binary).where(f"md5:{md5sum}")

        if binary_query:
            try:
                binary_data = binary_query[0].file.read()
            except Exception as err:
                logger.debug(f"No binary agailable for {md5sum}: {err}")
                analysis_result.binary_not_available = True
                return analysis_result

            yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
            yara_rules = yara.compile(filepaths=yara_rule_map)

            try:
                # matches = "debug"
                matches = yara_rules.match(data=binary_data, timeout=30)
            except yara.TimeoutError:
                # yara timed out
                analysis_result.last_error_msg = "Analysis timed out after 60 seconds"
                analysis_result.stop_future_scans = True
            except yara.Error as err:
                # Yara errored while trying to scan binary
                analysis_result.last_error_msg = f"Yara exception: {err}"
            except Exception as err:
                analysis_result.last_error_msg = f"Other exception while matching rules: {err}\n" + \
                                                 traceback.format_exc()
            else:
                if matches:
                    score = get_high_score(matches)
                    analysis_result.score = score
                    analysis_result.short_result = "Matched yara rules: %s" % ', '.join(
                        [match.rule for match in matches])
                    # analysis_result.short_result = "Matched yara rules: debug"
                    analysis_result.long_result = analysis_result.long_result
                    analysis_result.misc = generate_yara_rule_map_hash(globals.g_yara_rules_dir)
                else:
                    analysis_result.score = 0
                    analysis_result.short_result = "No Matches"

        else:
            analysis_result.binary_not_available = True
        return analysis_result
    except Exception as err:
        error = f"Unexpected error: {err}\n" + traceback.format_exc()
        logger.error(error)
        analysis_result.last_error_msg = error
        return analysis_result


def get_high_score(matches) -> int:
    """
    Find the higest match score.

    NOTE: if str(matches) == "debug", return 100
    :param matches: List of rule matches.
    :return:
    """
    score = 0
    for match in matches:
        if match.meta.get('score', 0) > score:
            score = match.meta.get('score')
    if score == 0:
        return 100
    else:
        return score
