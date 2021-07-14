from cbfeeds import CbFeed, CbFeedInfo

from cbopensource.connectors.yara_connector.loggers import log_extra_information


def write_feed(feed_location, reports):
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

    with open(feed_location, "w") as fp:
        fp.write(feed.dump())
        log_extra_information("Updated the feed file")
