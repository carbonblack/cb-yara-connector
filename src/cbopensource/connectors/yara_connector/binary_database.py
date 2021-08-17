# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import logging
from datetime import datetime

from peewee import *

# noinspection PyUnusedName
from cbopensource.connectors.yara_connector.loggers import log_extra_information

logger = logging.getLogger(__name__)

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


def get_analyzed_binaries():
    return BinaryDetonationResult.select().count()


def does_hash_exist(md5_hash):
    query = BinaryDetonationResult.select().where(
        BinaryDetonationResult.md5 == md5_hash
    )
    return not query.exists()


def get_scoring_binaries():
    query = BinaryDetonationResult.select().where(
        (BinaryDetonationResult.score > 0) & (BinaryDetonationResult.binary_not_available == False))
    return query


def binary_detonation_result_from_analysis_result(bdr, analysis_result):
    bdr.md5 = analysis_result.md5
    bdr.last_scan_date = datetime.now()
    bdr.score = analysis_result.score
    bdr.last_error_msg = analysis_result.last_error_msg
    bdr.last_success_msg = analysis_result.short_result
    bdr.misc = analysis_result.misc
    bdr.binary_not_available = analysis_result.binary_not_available
    return bdr


def save_analysis_result(analysis_result):
    bdr, created = BinaryDetonationResult.get_or_create(md5=analysis_result.md5)

    try:
        binary_detonation_result_from_analysis_result(bdr, analysis_result)
        bdr.save()
    except Exception as err:
        logger.exception("Error saving to database: {0}".format(err))


def warn_user_about_potential_problems():
    binaries_that_scored_zero = len(BinaryDetonationResult.select().where(
        BinaryDetonationResult.score == 0 and BinaryDetonationResult.binary_not_available == False))
    binaries_that_were_not_available = len(BinaryDetonationResult.select().where(
        BinaryDetonationResult.binary_not_available == True))
    if binaries_that_scored_zero > 1000:
        log_extra_information(
            f"{binaries_that_scored_zero} didn't match the configured yara ruleset. Are you sure your rules should be generating hits in your environment?")
    if binaries_that_were_not_available > 1000:
        log_extra_information(
            f"{binaries_that_were_not_available} didn't match the configured yara ruleset. Ensure the cb_server_url and cb_server_token are appropriate for your environment")
