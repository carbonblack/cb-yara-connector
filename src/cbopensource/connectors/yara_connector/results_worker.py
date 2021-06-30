import json
from datetime import datetime
from queue import Empty, Queue
from threading import Event
from typing import List

from cbopensource.connectors.yara_connector.analysis_result import AnalysisResult
from cbopensource.connectors.yara_connector.binary_database import BinaryDetonationResult
from cbopensource.connectors.yara_connector.feed import generate_feed_from_db
from . import globals
from .loggers import logger


def results_minion_chunked(exit_event: Event, results_queue: Queue) -> None:
    """
    Process entries in the results queue in chunks.

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
        logger.debug(f"Results minion thread exiting {exit_event.is_set()}")


def save_results(analysis_results: List[AnalysisResult]) -> None:
    """
    Save the current set of analysis results.

    :param analysis_results: list of current analysis results
    """
    logger.debug(
        f"Saving {len(list(filter(lambda ar: not ar.binary_not_available, analysis_results)))} analysis results..."
    )
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
