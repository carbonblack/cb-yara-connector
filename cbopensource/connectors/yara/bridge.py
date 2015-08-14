__author__ = 'jgarman'

from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import yara
import time
import logging


log = logging.getLogger(__name__)


class YaraProvider(BinaryAnalysisProvider):
    def __init__(self, yara_rules):
        super(YaraProvider, self).__init__('yara')
        self.yara_rules = yara.compile(filepath=yara_rules)

    # take default definition of check_result_for (return None)
    def check_result_for(self, md5sum):
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        start_dl_time = time.time()
        d = binary_file_stream.read()
        end_dl_time = time.time()

        log.debug("%s: Took %0.3f seconds to download the file" % (md5sum, end_dl_time-start_dl_time))

        try:
            start_analyze_time = time.time()
            matches = self.yara_rules.match(data=d, timeout=60)
            end_analyze_time = time.time()
            log.debug("%s: Took %0.3f seconds to analyze the file" % (md5sum, end_analyze_time-start_analyze_time))
        except yara.TimeoutError:
            raise AnalysisPermanentError("Analysis timed out after 60 seconds")
        except yara.Error:
            raise AnalysisTemporaryError("Yara exception", retry_in=10)
        else:
            if matches:
                return AnalysisResult(message="Matched yara rules",
                                      extended_message="%s" % ', '.join([match.rule for match in matches]),
                                      analysis_version=1, score=100)
            else:
                return AnalysisResult(score=0)


class YaraConnector(DetonationDaemon):
    @property
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        return 10

    def get_provider(self):
        yara_provider = YaraProvider("/Users/jgarman/tmp/yara.rule")
        return yara_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="Yara stuff",
                        tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                        provider_url="http://yara/", icon_path='',
                        display_name="Yara thing", category="Connectors")


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/yara"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = YaraConnector('yaratest', configfile=config_path, work_directory=temp_directory,
                                logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()
