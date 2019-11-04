# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import json
from datetime import datetime


class AnalysisResult(object):
    """
    This class holds binary analysis results information.
    """

    def __init__(self, md5: str, score: int = 0, short_result: str = '', long_result: str = '', last_scan_date=None,
                 last_error_msg: str = '', last_error_date=None, stop_future_scans: bool = False,
                 binary_not_available: bool = False, misc: str = ''):
        self.md5 = md5
        self.short_result = short_result
        self.long_result = long_result
        self.last_error_msg = last_error_msg
        self.last_error_date = last_error_date
        self.last_scan_date = last_scan_date
        self.score = score
        self.stop_future_scans = stop_future_scans
        self.binary_not_available = binary_not_available
        self.misc = misc

    def toJSON(self):
        dict_rep = self.__dict__
        for key, value in dict_rep.items():
            if isinstance(value, datetime):
                dict_rep[key] = value.timetuple()

        return json.dumps(dict_rep)
