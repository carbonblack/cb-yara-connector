import logging
import logging.handlers
import os

logging_format = "%(asctime)s-%(name)s-%(lineno)d-%(levelname)s-%(message)s"
logging.basicConfig(format=logging_format)

logger = logging.getLogger("yaraconnector")
logger.setLevel(logging.INFO)

celery_logger = logging.getLogger("celery.app.trace")
celery_logger.setLevel(logging.CRITICAL)


def handle_logging(log_file):
    use_log_file = os.path.abspath(os.path.expanduser(log_file))
    formatter = logging.Formatter(logging_format)
    handler = logging.handlers.RotatingFileHandler(
        use_log_file, maxBytes=10 * 1000000, backupCount=10
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)