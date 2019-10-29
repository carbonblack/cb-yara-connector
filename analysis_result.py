import json

class AnalysisResult(object):
    def __init__(self,
                 md5,
                 score=0,
                 short_result='',
                 long_result='',
                 last_scan_date=None,
                 last_error_msg='',
                 last_error_date=None,
                 stop_future_scans=False,
                 binary_not_available=False,
                 misc=''):
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
        return json.dumps(self.__dict__)


