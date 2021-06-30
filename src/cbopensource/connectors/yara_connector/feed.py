import time

from . import globals
from .binary_database import BinaryDetonationResult
from cbfeeds import CbFeed, CbFeedInfo, CbReport


def generate_feed_from_db() -> None:
    """
    Creates a feed based on specific database information and save to our output file.
    """
    query = BinaryDetonationResult.select().where(BinaryDetonationResult.score > 0)

    reports = []
    for binary in query:
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

    feedinfo = {
        "name": "yara",
        "display_name": "Yara",
        "provider_url": "http://plusvic.github.io/yara/",
        "summary": "Scan binaries collected by Carbon Black with Yara.",
        "tech_data": "There are no requirements to share any data with Carbon Black to use this feed.",
        "icon": "./yara-logo.png",
        "category": "Connectors",
    }
    feedinfo = CbFeedInfo(**feedinfo)
    feed = CbFeed(feedinfo, reports)

    # logger.debug("Writing out feed '{0}' to disk".format(feedinfo.data["name"]))
    with open(globals.g_output_file, "w") as fp:
        fp.write(feed.dump())
