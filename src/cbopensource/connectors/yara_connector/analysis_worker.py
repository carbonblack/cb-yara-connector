from queue import Empty, Queue
from threading import Event

from celery.exceptions import WorkerLostError

from cbopensource.connectors.yara_connector.loggers import logger
from .tasks import analyze_binary
from . import globals


def analysis_minion(exit_event: Event, hash_queue: Queue, scanning_results_queue: Queue) -> None:
    """
    The promise worker scanning function.

    :param exit_event: event signaller
    :param hash_queue
    :param scanning_results_queue: the results queue
    """
    try:
        while not (exit_event.is_set()):
            if not (hash_queue.empty()):
                try:
                    exit_set = False
                    md5_hashes = hash_queue.get()
                    promise = analyze_binary.chunks(
                        [(mh,) for mh in md5_hashes], globals.g_max_hashes
                    ).apply_async()
                    for prom in promise.children:
                        exit_set = exit_event.is_set()
                        if exit_set:
                            break
                        results = prom.get(disable_sync_subtasks=False)
                        scanning_results_queue.put(results)
                    if not exit_set:
                        promise.get(disable_sync_subtasks=False, timeout=1)
                    else:
                        promise.forget()
                    hash_queue.task_done()
                except Empty:
                    exit_event.wait(1)
                except WorkerLostError as err:
                    logger.debug(f"Lost connection to remote minion and exiting: {err}")
                    exit_event.set()
                    break
                except Exception as err:
                    logger.debug(f"Exception in wait: {err}")
                    exit_event.wait(0.1)
            else:
                exit_event.wait(1)
    finally:
        logger.debug(f"ANALYSIS MINION EXITING {exit_event.is_set()}")
