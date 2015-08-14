__author__ = 'jgarman'

from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed

import yara


class YaraProvider(BinaryAnalysisProvider):
    def __init__(self, yara_rules):
        super(YaraProvider, self).__init__('yara')
        self.yara_rules = yara.compile(filepath=yara_rules)

    # take default definition of check_result_for (return None)
    def check_result_for(self, md5sum):
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        d = binary_file_stream.read()
        try:
            matches = self.yara_rules.match(data=d, timeout=60)
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
