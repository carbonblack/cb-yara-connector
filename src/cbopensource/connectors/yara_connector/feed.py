import time
from threading import Event, Condition

from cbfeeds import CbReport

from .binary_database import get_scoring_binaries
from .feed_utils import write_feed
from .loggers import logger


def feed_worker(exit_event: Event, feed_location: str):
    logger.debug("Feed-worker thread starting")
    old_report_count = 0
    error = None
    while not exit_event.is_set():
        try:
            error = None
            exit_event.wait(30.0)
            logger.debug("Considering updating the feed...")
            old_report_count = generate_feed_from_db(feed_location, old_report_count, True)
        except Exception as e:
            error = e
            logger.exception(f"There was an error generating the feed: {e}")

    if exit_event.is_set():
        logger.debug("Feed-worker exiting")
    else:
        logger.exception(f"Feed worker exited with error {error}")


def generate_feed_from_db(feed_location: str, previous_report_count=0, honour_report_count=False) -> int:
    """
    Creates a feed based on specific database information and save to our output file.
    """

    reports = []
    binaries = get_scoring_binaries()
    for binary in binaries:
        try:
            fields = {
                "iocs": {"md5": [binary.md5]},
                "score": binary.score,
                "timestamp": int(time.mktime(time.gmtime())),
                "link": "",
                "id": "binary_{0}".format(binary.md5),
                "title": binary.last_success_msg,
                "description": binary.last_success_msg,
            }
            reports.append(CbReport(**fields))
        except Exception as e:
            logger.exception(f"There was an error processing a report to create the feed {e}")

    report_count = len(reports)
    exists_new_reports = report_count > previous_report_count
    if honour_report_count and exists_new_reports:
        logger.debug(f"There are {report_count} new analysis results available. Feed updating")
        write_feed(feed_location, reports)
    elif not honour_report_count:
        write_feed(feed_location, reports)
    else:
        logger.debug("There are no new reports...skipping feed update")
    return report_count
