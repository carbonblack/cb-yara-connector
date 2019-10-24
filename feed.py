import base64
import binascii
import json
import logging
import os
import re
import socket
import string
import time
from typing import List

# noinspection PyUnusedName
logger = logging.getLogger(__name__)


################################################################################
# Exception Classes
################################################################################

class CbException(Exception):
    pass


class CbIconError(CbException):
    pass


class CbInvalidFeed(CbException):
    pass


class CbInvalidReport(CbException):
    pass


################################################################################
# Working Code Classes
################################################################################

class CbJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        return obj.data


class CbFeedInfo(object):
    """
    Contains data relating feed information.
    """

    def __init__(self, strict_validation: bool = False, **kwargs):
        """
        Initizlize the feed info object.
        :param strict_validation: If True, validate data on every reference (default False)
        :param kwargs:
        """
        self._strict = strict_validation

        # these fields are required in every feed descriptor
        self.required = {
            "display_name": str,
            "provider_url": str,
            "name": str,
            "summary": str,
            "tech_data": str
        }

        # these fields are optional
        self.optional = {
            "category": str,
            "icon": str,
            "icon_small": str,
            "version": int
        }

        # these string fields cannot be empty string
        self.noemptystrings = ["name", "display_name", "summary", "tech_data", "category"]

        self._data = kwargs

        # if they are present, the icon and icon_small parameters represent either actual base64 encoded data
        # or a path to a local file containing the icon data, which must be read and encoded
        for icon_field in ["icon", "icon_small"]:
            if icon_field in self._data:
                try:
                    base64.b64decode(self._data[icon_field])
                    continue  # yes, is actual base64 encoded data
                except (binascii.Error, TypeError):
                    pass  # No, must be a path; try processing as such

                if os.path.exists(self._data[icon_field]):
                    icon_path = self._data.pop(icon_field)
                    try:
                        with open(icon_path, "rb") as fp:
                            self._data[icon_field] = base64.b64encode(fp.read()).decode('utf-8')
                    except Exception as err:
                        raise CbIconError(f"Unknown error reading/encoding icon data: {err}")
                else:
                    raise CbIconError("No such icon file at '{0}'".format(self._data[icon_field]))

        if self._strict:
            self.validate()

    def __str__(self):
        return "CbFeed(%s)" % (self._data.get("name", "unnamed"))

    def __repr__(self):
        return repr(self._data)

    # --------------------------------------------------------------------------------

    @property
    def data(self) -> dict:
        if self._strict:
            self.validate()
        return self._data

    def validate(self) -> None:
        """
        A set of checks to validate the internal data.
        :raises CbInvalidFeed:
        :raises CbIconError:
        """
        if not all([x in self._data.keys() for x in self.required.keys()]):
            missing_fields = ", ".join(set(self.required).difference(set(self._data.keys())))
            raise CbInvalidFeed(f"FeedInfo missing required field(s): {missing_fields}")

        # verify no non-supported keys are present
        for key in self._data.keys():
            if key not in self.required and key not in self.optional:
                raise CbInvalidFeed(f"FeedInfo includes extraneous key '{key}'")

        # check to see if icon_field can be base64 decoded
        for icon_field in ["icon", "icon_small"]:
            try:
                base64.b64decode(self._data[icon_field])
            except binascii.Error as err:
                logger.debug("Feed '{0}' has incorrect {1} data: {2}".format(self._data['name'], icon_field, err))
            except TypeError as err:
                logger.debug("Feed '{0}' has incorrect {1} data: {2}".format(self._data['name'], icon_field, err))
            except KeyError:
                # we don't want to cause a ruckus if the icon is missing
                pass

        # all fields in feedinfo must be the correct type
        for key in self._data.keys():
            needed = self.required.get(key, self.optional.get(key, None))
            if not isinstance(self._data[key], needed):
                raise CbInvalidFeed(
                    "FeedInfo field '{0}' must be of type '{1}'; we see type '{2}'".format(key, self.required[key],
                                                                                           type(self._data[key])))

        # certain fields, when present, must not be empty strings
        for key in self._data.keys():
            if key in self.noemptystrings and self._data[key] == "":
                raise CbInvalidFeed(f"The '{key}' field must not be an empty string")

        # validate shortname of this field is just a-z and 0-9, with at least one character
        if not self._data["name"].isalnum():
            raise CbInvalidFeed(
                "Feed name '{0}' may only contain a-z, A-Z, 0-9 and must have one character".format(self._data["name"]))


class CbReport(object):
    def __init__(self, strict_validation: bool = False, allow_negative_scores: bool = False, **kwargs):
        """
        Contains data relating information for a single report.

        :param strict_validation: If True, validate data on every reference (default False)
        :param allow_negative_scores: If True, allow negative score values (default False)
        :param kwargs:
        """
        self._strict = strict_validation

        # negative scores introduced in CB 4.2;  a measure of "goodness" versus "badness"
        self.allow_negative_scores = allow_negative_scores

        # these fields are required in every report
        self.required = {
            "id": str,
            "iocs": dict,
            "link": str,
            "score": int,
            "timestamp": int,
            "title": str
        }

        # these fields are optional
        self.optional = {
            "description": str,
            "tags": list
        }

        # valid IOC types are "sha256", "md5", "ipv4", "dns", "query"
        self.valid_ioc_types = ["sha256", "md5", "ipv4", "dns", "query"]

        # valid index_type options for "query" IOC
        self.valid_query_ioc_types = ["events", "modules"]

        if "timestamp" not in kwargs:
            kwargs["timestamp"] = int(time.mktime(time.gmtime()))

        self._data = kwargs

        if self._strict:
            self.validate()

    def __str__(self):
        return "CbReport(%s)" % (self._data.get("title", self._data.get("id", '')))

    def __repr__(self):
        return repr(self._data)

    # --------------------------------------------------------------------------------

    @property
    def data(self) -> dict:
        if self._strict:
            self.validate()
        return self._data

    @staticmethod
    def is_valid_query(query: str, reportid: str):
        """
        Make a determination as to if this is a valid query.
        :param query: An ioc query
        :param reportid: the report id
        :raises CbInvalidReport:
        """
        # the query itself must be percent-encoded; verify there are only non-reserved characters present
        #   -- no logic to detect unescaped '%' characters
        for c in query:
            if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%*()":
                raise CbInvalidReport((f"Unescaped non-reserved character '{c}' ",
                                       f"found in query for report {reportid}; use percent-encoding"))

    def validate(self, pedantic: bool = False) -> None:
        """
        A set of checks to validate the report.

        :param pedantic: If True, limit to required fields (default False)
        :raises CbInvalidReport:
        """
        # validate we have all required keys
        if not all([x in self._data.keys() for x in self.required.keys()]):
            missing_fields = ", ".join(set(self.required).difference(set(self._data.keys())))
            raise CbInvalidReport(f"Report missing required field(s): {missing_fields}")

        # if we get here, create convenience variable for later use
        rid = self._data['id']

        # validate that no extra keys are present
        for key in self._data.keys():
            if key not in self.required and key not in self.optional:
                raise CbInvalidReport(f"Report contains extra key '{key}'")
            if pedantic and key not in self.required:
                raise CbInvalidReport(f"Report contains non-required key '{key}'")

        # CBAPI-36
        # all fields in feedinfo must be the correct type
        for key in self._data.keys():
            needed = self.required.get(key, self.optional.get(key, None))
            if not isinstance(self._data[key], needed):
                raise CbInvalidFeed(
                    "report field '{0}' must be of type '{1}'; we see type '{2}'".format(key, self.required[key],
                                                                                         type(self._data[key])))

        # validate that tags is a list of alphanumeric strings
        if "tags" in self._data.keys():
            if not isinstance(self._data["tags"], list):
                raise CbInvalidReport("Tags must be a list")
            for tag in self._data["tags"]:
                if not str(tag).isalnum():
                    raise CbInvalidReport(f"Tag '{tag}' is not alphanumeric")
                if len(tag) > 32:
                    raise CbInvalidReport("Tags must be 32 characters or fewer")

        # validate score is integer between -100 (if so specified) or 0 and 100
        try:
            int(self._data["score"])
        except ValueError:
            raise CbInvalidReport(
                "Report has non-integer score {0} in report '{1}'".format(self._data["score"], rid))

        if self._data["score"] < -100 or self._data["score"] > 100:
            raise CbInvalidReport(
                "Report score {0} out of range -100 to 100 in report '{1}'".format(self._data["score"], rid))

        if not self.allow_negative_scores and self._data["score"] < 0:
            raise CbInvalidReport(
                "Report score {0} out of range 0 to 100 in report '{1}'".format(self._data["score"], rid))

        # validate id of this report is just a-z and 0-9 and - and ., with at least one character
        if not re.match("^[a-zA-Z0-9-_.]+$", rid):
            raise CbInvalidReport(f"Report ID '{rid}' may only contain a-z, A-Z, 0-9, - and must have one character")

        # validate there is at least one IOC for each report and each IOC entry has at least one entry
        if not all([len(self._data["iocs"][ioc]) >= 1 for ioc in self._data['iocs']]):
            raise CbInvalidReport(f"Report IOC list with zero length in report '{rid}'")

        # convenience variable
        iocs = self._data['iocs']

        # validate that there are at least one type of ioc present
        if len(iocs.keys()) == 0:
            raise CbInvalidReport(f"Report with no IOCs in report '{rid}'")

        # (pedantically) validate that no extra iocs are present
        if pedantic and len(set(iocs.keys()) - set(self.valid_ioc_types)) > 0:
            raise CbInvalidReport(
                "Report IOCs section contains extra keys: {0}".format(set(iocs.keys()) - set(self.valid_ioc_types)))

        # Let us check and make sure that for "query" ioc type does not contain other types of ioc
        query_ioc = "query" in iocs.keys()
        if query_ioc and len(iocs.keys()) > 1:
            raise CbInvalidReport(
                "Report IOCs section for \"query\" contains extra keys: {0} for report '{1}'".format(set(iocs.keys()),
                                                                                                     rid))

        if query_ioc:
            iocs_query = iocs["query"][0]

            if not isinstance(iocs_query, dict):
                raise CbInvalidReport(f"Query IOC section not a dict structure")

            # validate that the index_type field exists
            if "index_type" not in iocs_query.keys():
                raise CbInvalidReport(f"Query IOC section for report '{rid}' missing index_type")

            # validate that the index_type is a valid value
            if not iocs_query.get("index_type", None) in self.valid_query_ioc_types:
                raise CbInvalidReport(
                    "Report IOCs section for 'query' contains invalid index_type: {0} for report '{1}".format(
                        iocs_query.get("index_type", None), rid))

            # validate that the search_query field exists
            if "search_query" not in iocs_query.keys():
                raise CbInvalidReport(f"Query IOC for report {rid} missing 'search_query'")

            # validate that the search_query field is at least minimally valid
            # in particular, we are looking for a "q=" or "cb.q."
            # this is by no means a complete validation, but it does provide a protection
            # against leaving the actual query unqualified
            if "q=" not in iocs_query["search_query"] and "cb.q." not in iocs_query["search_query"]:
                raise CbInvalidReport(f"Query IOC for report {rid} missing q= on query")

            for kvpair in iocs_query["search_query"].split('&'):
                if 2 != len(kvpair.split('=')):
                    continue
                if kvpair.split('=')[0] == 'q':
                    self.is_valid_query(kvpair.split('=')[1], rid)

        hex_digits = "0123456789ABCDEF"

        # validate all md5 fields are 32 hex (0-F) characters
        for md5 in iocs.get("md5", []):
            if 32 != len(md5):
                raise CbInvalidReport(f"Invalid md5 length for md5 ({md5}) for report '{rid}'")
            for c in md5.upper():
                if c not in hex_digits:
                    raise CbInvalidReport(f"Malformed md5 ({md5}) in IOC list for report '{rid}'")

        # validate all sha256 fields are 64 hex (0-F) characters
        for sha256 in iocs.get("sha256", []):
            if 64 != len(sha256):
                raise CbInvalidReport("Invalid sha256 length for md5 ({sha256) for report '{rid}'")
            for c in sha256.upper():
                if c not in hex_digits:
                    raise CbInvalidReport(f"Malformed sha256 ({sha256}) in IOC list for report '{rid}'")

        # validate all IPv4 fields pass socket.inet_ntoa()
        try:
            [socket.inet_aton(ip) for ip in iocs.get("ipv4", [])]
        except socket.error as err:
            raise CbInvalidReport(f"Malformed IPv4 addr in IOC list for report '{rid}': {err}")

        # validate all lowercased domains have just printable ascii
        # 255 chars allowed in dns; all must be printables, sans control characters
        # hostnames can only be A-Z, 0-9 and - but labels can be any printable.  See
        # O'Reilly's DNS and Bind Chapter 4 Section 5:
        # "Names that are not host names can consist of any printable ASCII character."
        allowed_chars = string.printable[:-6]  # all but whitespace
        for domain in iocs.get("dns", []):
            if len(domain) > 255:
                raise CbInvalidReport(
                    f"Excessively long domain name ({domain}) in IOC list for report '{rid}'")
            if not all([c in allowed_chars for c in domain]):
                raise CbInvalidReport(
                    f"Malformed domain name ({domain}) in IOC list for report '{rid}'")
            labels = domain.split('.')
            if 0 == len(labels):
                raise CbInvalidReport(f"Empty domain name in IOC list for report '{rid}'")
            for label in labels:
                if len(label) < 1 or len(label) > 63:
                    raise CbInvalidReport(
                        f"Invalid label length ({label}) in domain name ({domain}) for report '{rid}'")


class CbFeed(object):
    def __init__(self, feedinfo: CbFeedInfo, reports: List[CbReport], strict_validation: bool = False):
        """
        Contains data relating information for a single report.

        :param feedinfo: dict represnation of the feed information
        :param reports: list of dict represenations for east report
        :param strict_validation: If True, validate data on every reference (default False)
        """
        self._strict = strict_validation

        self._data = {'feedinfo': feedinfo, 'reports': reports}

        if self._strict:
            self.validate()

    def __repr__(self):
        return repr(self._data)

    def __str__(self):
        return "CbFeed(%s)" % (self._data.get('feedinfo', "unknown"))

    # --------------------------------------------------------------------------------

    @property
    def data(self) -> dict:
        if self._strict:
            self.validate()
        return self._data

    @staticmethod
    def load(serialized_data: str, strict_validation: bool = False) -> 'CbFeed':
        """
        Take in a feed descripotion as a JSON string and convert to a CbFeed object.

        :param serialized_data: source JSON string
        :param strict_validation: If True, validate data on every reference (default False)
        :return:
        """
        raw_data = json.loads(serialized_data)

        if "feedinfo" not in raw_data:
            raise CbInvalidFeed("Feed missing 'feedinfo' data")

        if 'reports' not in raw_data:
            raise CbInvalidFeed("Feed missing 'reports' structure")

        fi = CbFeedInfo(**raw_data["feedinfo"])
        rpt = [CbReport(**rp) for rp in raw_data["reports"]]

        new_feed = CbFeed(fi, rpt, strict_validation=strict_validation)
        new_feed.validate()
        return new_feed

    def dump(self) -> str:
        """
        Dumps the feed data as a JSON object.

        :return: json data object
        """
        return json.dumps(self.data, cls=CbJSONEncoder, sort_keys=True, indent=2)

    def dumpjson(self) -> json:
        """
        Dumps the feed data as a JSON object.

        :return: json data object
        """
        return json.loads(self.dump())

    def iter_iocs(self):
        """
        Yields all iocs in the feed.
        """

        for report in self._data["reports"]:
            for sha256 in report.data.get("iocs", {}).get("sha256", []):
                yield {"type": "sha256", "ioc": sha256, "report_id": report.data.get("id", "")}
            for md5 in report.data.get("iocs", {}).get("md5", []):
                yield {"type": "md5", "ioc": md5, "report_id": report.data.get("id", "")}
            for ip in report.data.get("iocs", {}).get("ipv4", []):
                yield {"type": "ipv4", "ioc": ip, "report_id": report.data.get("id", "")}
            for domain in report.data.get("iocs", {}).get("dns", []):
                yield {"type": "dns", "ioc": domain, "report_id": report.data.get("id", "")}

    @staticmethod
    def validate_report_list(reports: List[CbReport]) -> None:
        """
        Validates reports as a set, as compared to each report as a standalone entity.

        :param reports: list of reports
        :raises CbInvalidFeed:
        """
        reportids = set()

        # verify that no two reports have the same report id
        # see CBAPI-17
        for report in reports:
            if report.data['id'] in reportids:
                raise CbInvalidFeed("duplicate report id '{0}'".format(report.data['id']))
            reportids.add(report.data['id'])

    def validate(self, pedantic: bool = False) -> None:
        """
        Validates the feed.

        :param pedantic: when set, perform strict validation on reports
        """
        self._data['feedinfo'].validate()

        # validate each report individually
        for rep in self._data['reports']:
            rep.validate(pedantic=pedantic)

        # validate the reports as a whole
        self.validate_report_list(self._data['reports'])
