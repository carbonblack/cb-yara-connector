from queue import Empty, Queue
from threading import Event
from typing import List

from cbopensource.connectors.yara_connector.analysis_result import AnalysisResult
from cbopensource.connectors.yara_connector.binary_database import save_analysis_result
from .loggers import logger


def results_minion(exit_event: Event, results_queue: Queue, chunked=True) -> None:
    logger.debug("Results thread starting")
    exception = None
    try:
        while not (exit_event.is_set()):
            if not (results_queue.empty()):
                try:
                    if chunked:
                        results = results_queue.get()
                        save_results(results)
                    else:
                        result = results_queue.get()
                        save_result(result)
                except Empty:
                    exit_event.wait(1)
                except Exception as e:
                    logger.exception(f"Error saving analysis result {e}")
                    exception = e
                finally:
                    results_queue.task_done()
            else:
                exit_event.wait(0.25)
    finally:
        if exit_event.is_set():
            logger.debug(f"Results minion thread exiting normally")
        else:
            logger.exception(f"Results minion exiting due to error {exception}")


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
    logger.debug(f"Saving result: md5 = {analysis_result.md5} score = {analysis_result.score}")

    save_analysis_result(analysis_result)
