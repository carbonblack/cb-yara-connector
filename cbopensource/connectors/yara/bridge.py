from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import yara
import time
import logging

import os

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class YaraProvider(BinaryAnalysisProvider):
    def __init__(self, name, yara_rule_directory):
        super(YaraProvider, self).__init__(name)
        self.yara_rules = self.compile_rules(yara_rule_directory)

    def compile_rules(self, pathname):
        rule_map = {}
        for fn in os.listdir(pathname):
            fullpath = os.path.join(pathname, fn)
            if not os.path.isfile(fullpath):
                continue

            last_dot = fn.rfind('.')
            if last_dot != -1:
                namespace = fn[:last_dot]
            else:
                namespace = fn
            rule_map[namespace] = fullpath

        return yara.compile(filepaths=rule_map)

    # take default definition of check_result_for (return None)
    def check_result_for(self, md5sum):
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        log.debug("%s: in analyze_binary" % md5sum)
        d = binary_file_stream.read()

        try:
            start_analyze_time = time.time()
            matches = self.yara_rules.match(data=d, timeout=60)
            end_analyze_time = time.time()
            log.debug("%s: Took %0.3f seconds to analyze the file" % (md5sum, end_analyze_time - start_analyze_time))
        except yara.TimeoutError:
            raise AnalysisPermanentError(message="Analysis timed out after 60 seconds")
        except yara.Error:
            raise AnalysisTemporaryError(message="Yara exception", retry_in=10)
        else:
            if matches:
                score = self.getHighScore(matches)
                return AnalysisResult(message="Matched yara rules: %s" % ', '.join([match.rule for match in matches]),
                                      extended_message="%s" % ', '.join([match.rule for match in matches]),
                                      analysis_version=1, score=score)
            else:
                return AnalysisResult(score=0)

    def getHighScore(self, matches):
        score = 0
        for match in matches:
            if match.meta.get('score') > score:
                score = match.meta.get('score')
        if score == 0:
            return 100
        else:
            return score


class YaraConnector(DetonationDaemon):
    @property
    def integration_name(self):
        return 'Cb Yara Connector 1.3.2'

    @property
    def filter_spec(self):
        filters = []
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            log.info("Binary Filter Query: {0}".format(additional_filter_requirements))
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        yara_num_threads = self.get_config_integer("yara_num_threads", 4)
        log.info("Number of deep scan threads: {0}".format(yara_num_threads))
        return yara_num_threads

    @property
    def up_to_date_rate_limiter(self):
        return 0

    @property
    def historical_rate_limiter(self):
        return 0

    def get_provider(self):
        yara_provider = YaraProvider(self.name, self.yara_rule_directory)
        return yara_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="Scan binaries collected by Carbon Black with Yara.",
                                              tech_data="There are no requirements to share any data with Carbon Black to use this feed.",
                                              provider_url="http://plusvic.github.io/yara/",
                                              icon_path='/usr/share/cb/integrations/yara/yara-logo.png',
                                              display_name="Yara", category="Connectors")

    def validate_config(self):
        super(YaraConnector, self).validate_config()

        self.yara_rule_directory = self.get_config_string("yara_rule_directory", None)
        if not self.yara_rule_directory:
            raise ConfigurationError("A yara_rule_directory stanza is required in the configuration file")

        return True


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/yara"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = YaraConnector('yaratest', configfile=config_path, work_directory=temp_directory,
                           logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()
