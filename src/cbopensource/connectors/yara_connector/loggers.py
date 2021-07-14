import logging
import logging.handlers
import os
from typing import List

logging_format = "%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s"
logging.basicConfig(format=logging_format)

logger = logging.getLogger("yaraconnector")
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger("celery.app.trace")
celery_logger.setLevel(logging.CRITICAL)


def handle_logging(log_file, log_level="VERBOSE"):
    use_log_file = os.path.abspath(os.path.expanduser(log_file))
    formatter = logging.Formatter(logging_format)
    handler = logging.handlers.RotatingFileHandler(
        use_log_file, maxBytes=10 * 1000000, backupCount=10
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logging.addLevelName(15, "VERBOSE")
    detected_log_level = logging.getLevelName(log_level.upper())
    logger.setLevel(detected_log_level)
    logging.basicConfig(level=detected_log_level)


def log_extra_information(msg : any):
    logger.log(level=logging.getLevelName("VERBOSE"), msg=msg)


def get_log_file_handles(use_logger) -> List:
    """
    Get a list of filehandle numbers from logger to be handed to DaemonContext.files_preserve.

    :param use_logger: logger to check
    :return: List of file handlers
    """
    handles = []
    for handler in use_logger.handlers:
        handles.append(handler.stream.fileno())
    if use_logger.parent:
        handles += get_log_file_handles(use_logger.parent)
    return handles
