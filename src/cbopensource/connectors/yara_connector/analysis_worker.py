from queue import Empty, Queue
from threading import Event

from celery.exceptions import WorkerLostError

from cbopensource.connectors.yara_connector.loggers import logger
from .tasks import analyze_binary, analyze_binary_task


def analysis_minion(thread_num: int, exit_event: Event, hash_queue: Queue, scanning_results_queue: Queue, chunked=True,
                    max_hashes: int = 8) -> None:
    logger.debug(f"Analysis thread {thread_num} starting")
    exception = None
    try:
        while not (exit_event.is_set()):
            if not (hash_queue.empty()):
                try:
                    if chunked:
                        handle_chunked(hash_queue, exit_event, scanning_results_queue, max_hashes=max_hashes)
                    else:
                        handle_single(hash_queue, scanning_results_queue)
                except Empty:
                    exit_event.wait(1)
                except WorkerLostError as err:
                    exception = err
                    logger.exception(f"Lost connection to remote minion and exiting: {err}")
                except Exception as err:
                    logger.exception(f"Error in analysis worker: {err}")
                    exception = err
                finally:
                    hash_queue.task_done()
            else:
                exit_event.wait(0.25)
    finally:
        if exit_event.is_set():
            logger.debug(f"Analysis worker {thread_num} exiting")
        else:
            logger.exception(f"Analysis worker {thread_num} exiting due to error {exception}")


def handle_chunked(hash_queue, exit_event, scanning_results_queue, max_hashes: int = 8):
    exit_set = False
    md5_hashes = hash_queue.get()
    promise = analyze_binary_task.chunks(
        [(mh[0], mh[1]) for mh in md5_hashes], max_hashes
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


def handle_single(hash_queue, scanning_results_queue):
    md5_hash, node_id = hash_queue.get()
    logger.debug(f"Analyzing hash {md5_hash}")
    result = analyze_binary(md5_hash, node_id)
    logger.debug(f"Done Analyzing {md5_hash}")
    scanning_results_queue.put(result)
