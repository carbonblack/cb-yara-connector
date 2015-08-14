__author__ = 'jgarman'

from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult, BinaryConsumerThread)
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
    def __init__(self, name, **kwargs):
        super(YaraConnector, self).__init__(name, **kwargs)

    def validate_config(self):
        super(YaraConnector, self).validate_config()

    def run(self):
        work_queue = self.initialize_queue()

        consumer_threads = []

        yara_provider = YaraProvider("/Users/jgarman/tmp/yara.rule")
        for i in range(10):
            consumer_threads.append(BinaryConsumerThread(work_queue, self.cb, yara_provider))

        for t in consumer_threads:
            t.start()

        self.start_binary_collectors()
