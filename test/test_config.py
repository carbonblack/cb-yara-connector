from unittest import TestCase
from unittest.mock import patch, MagicMock, Mock

from cbopensource.connectors.yara_connector.config_handling import YaraConnectorConfig, YaraConnectorMode
from cbopensource.connectors.yara_connector.exceptions import CbInvalidConfig


def get_mock_config(mode=YaraConnectorMode.STANDALONE, config_items=None, include_postgres=True):
    yara_connector_config = Mock()
    yara_connector_config_dict = config_items if config_items else {}
    if include_postgres:
        yara_connector_config_dict.update({"postgres_password": "afdsafdsa"})
    if not config_items:
        standalone_mode_keys = {"mode": "standalone", "yara_rules_dir": "./yara_rules_dir",
                                "cb_server_url": "https://carbonblack.io",
                                "cb_server_token": "APITOKEN"}
        primary_mode_keys = {"mode": "primary", "yara_rules_dir": "./yara_rules_dir", "broker_url": "redis://"}
        minion_mode_keys = {"broker_url": "redis://", "yara_rules_dir": "./yara_rules_dir", "mode": "minion",
                            "cb_server_url": "https://afdsafdsa", "cb_server_token": "afdasfdas"}
        if mode == YaraConnectorMode.STANDALONE:
            yara_connector_config_dict.update(**standalone_mode_keys)
        elif mode == YaraConnectorMode.PRIMARY:
            yara_connector_config_dict.update(**primary_mode_keys)
        else:
            yara_connector_config_dict.update(**minion_mode_keys)

    def mock_config_lookup(key, default=None):
        if key in yara_connector_config_dict:
            return yara_connector_config_dict.get(key, "")
        else:
            return default

    yara_connector_config.get = mock_config_lookup

    return yara_connector_config


def os_path_exists_iterator(base_array=[False, True], default_value=True):
    for item in base_array:
        yield item
    while True:
        yield default_value


def patch_config_for_testing(mode=YaraConnectorMode.STANDALONE, config_items=None):
    mock_config = MagicMock()
    mock_config.__getitem__.return_value = get_mock_config(mode=mode, config_items=config_items)
    config_parser_mock = patch("cbopensource.connectors.yara_connector.config_handling.configparser.ConfigParser",
                               return_value=mock_config)
    os_path_patch_config = {"expanduser.return_value": "/path/to/config",
                            "abspath.return_value": "/path/to/config",
                            "isdir.side_effect": os_path_exists_iterator(),
                            "exists.return_value": True}
    os_path = patch("cbopensource.connectors.yara_connector.config_handling.os.path", **os_path_patch_config)
    os_path.start()
    config_parser_mock.start()

    return os_path, config_parser_mock


class TestConfiguration(TestCase):

    def tearDown(self) -> None:
        for patcher in self.patchers:
            patcher.stop()

    def test_standalone_config_default(self):
        self.patchers = patch_config_for_testing()
        test_config = YaraConnectorConfig("/path/to/config.ini", "/path/to/output.json")
        assert test_config.mode == "standalone"
        assert test_config.operation_mode == YaraConnectorMode.STANDALONE
        assert test_config.cb_server_url
        assert test_config.cb_server_token
        assert test_config.yara_rules_dir != ""
        assert test_config.feed_database_dir != ""
        assert test_config.scanning_interval == 360
        assert test_config.broker_url is None
        assert test_config.results_backend is None
        assert test_config.minion_network_timeout > 0
        assert test_config.node_id == 0
        assert test_config.log_level == "INFO"


    def test_standalone_config_requires_api(self):
        self.patchers = patch_config_for_testing(config_items={"yara_rules_dir": "./yara_rules_dir"})
        with self.assertRaises(CbInvalidConfig):
            YaraConnectorConfig("/path/to/config.ini", "/path/to/output.json")

    def test_standalone_config_requires_rules_dir(self):
        self.patchers = patch_config_for_testing(config_items={"cb_server_token": "AFDFd", "cb_server_url": "afdafdsa"})
        with self.assertRaises(CbInvalidConfig):
            YaraConnectorConfig("/path/to/config.ini", "/path/to/output.json")

    def test_primary_config(self):
        self.patchers = patch_config_for_testing(mode=YaraConnectorMode.PRIMARY)
        test_config = YaraConnectorConfig("/path/to/config.ini", "/path/to/output.json")
        assert test_config.mode == "primary"
        assert test_config.operation_mode == YaraConnectorMode.PRIMARY
        assert not test_config.cb_server_url
        assert not test_config.cb_server_token
        assert test_config.yara_rules_dir != ""
        assert test_config.feed_database_dir != ""
        assert test_config.scanning_interval == 360
        assert test_config.broker_url is not None
        assert test_config.results_backend is not None
        assert test_config.minion_network_timeout > 0
        assert test_config.node_id == 0
        assert test_config.log_level == "INFO"

    def test_minion_config(self):
        self.patchers = patch_config_for_testing(mode=YaraConnectorMode.MINION)
        test_config = YaraConnectorConfig("/path/to/config.ini", "/path/to/output.json")
        assert test_config.mode == "minion"
        assert test_config.operation_mode == YaraConnectorMode.MINION
        assert test_config.cb_server_url
        assert test_config.cb_server_token
        assert test_config.yara_rules_dir != ""
        assert test_config.feed_database_dir != ""
        assert test_config.scanning_interval == 360
        assert test_config.broker_url is not None
        assert test_config.results_backend is not None
        assert test_config.minion_network_timeout > 0
        assert test_config.node_id == -1
        assert test_config.log_level == "INFO"

    def test_minion_config_no_broker(self):
        minion_mode_keys = {"yara_rules_dir": "./yara_rules_dir", "mode": "minion",
                            "cb_server_url": "https://afdsafdsa", "cb_server_token": "afdasfdas"}

        self.patchers = patch_config_for_testing(mode=YaraConnectorMode.MINION, config_items=minion_mode_keys)
        with self.assertRaises(CbInvalidConfig):
            YaraConnectorConfig("/path/to/config.ini", "/path/to/output.json")

