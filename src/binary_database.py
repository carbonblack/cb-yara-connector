import logging

from peewee import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

#
# autostart must be False if we intend to dynamically create the database.
#
db = Proxy()


# noinspection PyUnusedName
class BinaryDetonationResult(Model):
    md5 = CharField(index=True, unique=True)
    last_scan_date = DateTimeField(null=True)
    last_success_msg = CharField(default='', null=True)

    last_error_msg = CharField(default='', null=True)
    last_error_date = DateTimeField(null=True)

    score = IntegerField(default=0)

    scan_count = IntegerField(default=0)

    #
    # If There was a permanent error then set this to True
    #
    stop_future_scans = BooleanField(default=False)

    #
    # if we could not download the binary then set this to False
    # We will need to wait for alliance download
    #
    binary_not_available = BooleanField(null=True)

    #
    # Last attempt to scan this binary.  Which could have thrown an error if the binary was not available to download
    #
    last_scan_attempt = DateTimeField(null=True)

    #
    #
    #
    num_attempts = IntegerField(default=0)

    #
    # Misc use for connectors
    #
    misc = CharField(default='')

    # noinspection PyUnusedClass,PyUnusedName
    class Meta:
        database = db
