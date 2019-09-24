from celery import Celery, bootsteps
import globals

app = Celery()
app.conf.task_serializer = "pickle"
app.conf.result_serializer = "pickle"
app.conf.accept_content = {"pickle"}

import yara
import logging
import traceback
import datetime
import configparser
import os
import shutil
import hashlib
from analysis_result import AnalysisResult
from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI
import globals

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

g_config = dict()


def verify_config(config_file):
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

    def __init__(self, worker, config_file='yara_worker.conf', **options):
        super().__init__(self)
        verify_config(config_file)

        # g_yara_rules_dir = yara_rules_dir


app.steps['worker'].add(MyBootstep)


def generate_rule_map(yara_rule_path):
    global yara_rule_map_hash

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


def generate_yara_rule_map_hash(yara_rule_path):
    global g_yara_rule_map_hash_list

    md5 = hashlib.md5()

    temp_list = list()

    for fn in os.listdir(yara_rule_path):
        with open(os.path.join(yara_rule_path, fn), 'rb') as fp:
            data = fp.read()
            md5.update(data)
            temp_list.append(str(md5.hexdigest()))

    temp_list.sort()
    return temp_list


@app.task
def update_yara_rules_remote(yara_rules):
    try:
        shutil.rmtree(globals.g_yara_rules_dir)
        for key in yara_rules:
            open(os.path.join(globals.g_yara_rules_dir, key), 'wb').write(yara_rules[key])
    except:
        logger.error(traceback.format_exc())


@app.task
def analyze_binary(md5sum):
    logger.debug("{}: in analyze_binary".format(md5sum))
    analysis_result = AnalysisResult(md5sum)

    try:

        analysis_result.last_scan_date = datetime.datetime.now()

        cb = CbResponseAPI(url=globals.g_cb_server_url,
                           token=globals.g_cb_server_token,
                           ssl_verify=False,
                           timeout=5)

        binary_query = cb.select(Binary).where("md5:{0}".format(md5sum))

        if binary_query:
            try:
                binary_data = binary_query[0].file.read()
            except:
                analysis_result.binary_not_available = True
                return analysis_result

            yara_rule_map = generate_rule_map(globals.g_yara_rules_dir)
            yara_rules = yara.compile(filepaths=yara_rule_map)

            try:
                # matches = "debug"
                matches = yara_rules.match(data=binary_data, timeout=30)
            except yara.TimeoutError:
                #
                # yara timed out
                #
                analysis_result.last_error_msg = "Analysis timed out after 30 seconds"
                analysis_result.stop_future_scans = True
            except yara.Error:
                #
                # Yara errored while trying to scan binary
                #
                analysis_result.last_error_msg = "Yara exception"
            except:
                analysis_result.last_error_msg = traceback.format_exc()
            else:
                if matches:
                    score = getHighScore(matches)
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
    except:
        error = traceback.format_exc()
        logger.error(traceback.format_exc())
        analysis_result.last_error_msg = error
        return analysis_result


def getHighScore(matches):
    #######
    # if str(matches) == "debug":
    #     return 100
    #######
    score = 0
    for match in matches:
        if match.meta.get('score', 0) > score:
            score = match.meta.get('score')
    if score == 0:
        return 100
    else:
        return score
