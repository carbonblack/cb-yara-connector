import unittest
from collections import namedtuple
from unittest.mock import patch, MagicMock

from cbopensource.connectors.yara_connector.tasks import analyze_binary, set_task_config, set_compiled_rules, \
    compile_yara_rules

MockYaraConfig = namedtuple('MockYaraConfig', ['node_id', 'module_store_location', 'cb_server_url', 'cb_server_token',
                                               "minion_network_timeout", "yara_rules_dir"])


def get_mock_match(rule_name: str, score: int = 10):
    mock_match = MagicMock()
    mock_match.meta.get.return_value = score
    mock_match.rule = rule_name
    return mock_match


DEFAULT_MOCK_RULESET = ["rule 1", "rule two", "another rule"]


def get_working_mock_ruleset(rules=None):
    if not rules:
        rules = DEFAULT_MOCK_RULESET
    mock_rules = MagicMock()
    mock_rules.match.return_value = [get_mock_match(rulename) for rulename in rules]
    return mock_rules


def get_mock_module_data():
    mock_module = MagicMock()
    mock_module.read.return_value = ""
    return mock_module


class TaskTests(unittest.TestCase):

    def setUp(self) -> None:
        self.config = MockYaraConfig(0, "/var/cb/data/modulestore", "https://localhost", "someapikey", 30, "./rules")
        set_task_config(self.config)

    @patch("cbopensource.connectors.yara_connector.tasks.lookup_local_module", new=get_mock_module_data())
    def test_scan_local(self):
        set_compiled_rules(get_working_mock_ruleset(DEFAULT_MOCK_RULESET), "DEADBEEF")
        analysis_result = analyze_binary("14018EB9E2F4488101719C4D29DE2230", 0)
        for rule in DEFAULT_MOCK_RULESET:
            assert rule in analysis_result.long_result

        assert analysis_result.md5 is not ""
        assert analysis_result.score == 10

    @patch("cbopensource.connectors.yara_connector.tasks.lookup_binary_by_hash", new=get_mock_module_data())
    def test_scan_remote(self):
        set_compiled_rules(get_working_mock_ruleset(DEFAULT_MOCK_RULESET), "DEADBEEF")
        analysis_result = analyze_binary("14018EB9E2F4488101719C4D29DE2230", 1)
        for rule in DEFAULT_MOCK_RULESET:
            assert rule in analysis_result.long_result

        assert analysis_result.md5 is not ""
        assert analysis_result.score == 10

    @patch("cbopensource.connectors.yara_connector.tasks.yara")
    @patch("cbopensource.connectors.yara_connector.tasks.generate_rule_map")
    def test_compile_rules(self, generate_rule_map, yara):
        generate_rule_map.return_value = {"rule.yara": "/path/to/rule.yara"}, "14018EB9E2F4488101719C4D29DE2230"
        compile_yara_rules()
        assert yara.compile.called


if __name__ == '__main__':
    unittest.main()
