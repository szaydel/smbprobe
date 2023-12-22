import io
import unittest

from common.classes import ShareInfo
from common.configuration import config_to_si_list, load_config, display_parsed_config


class TestConfig(unittest.TestCase):
    def test_bad_config_fails_to_load(self):
        """Validates proper detection of known bad config"""
        _, msg = load_config("../testdata/test_bad1.toml")
        self.assertIsNotNone(msg)

    def test_good_config_loads_successfully(self):
        """Validates proper loading of known good config"""
        conf, _ = load_config("testdata/test_good3.toml")
        self.assertEqual(
            conf,
            {
                "probes": [
                    {
                        "name": "",
                        "address": "10.2.2.23",
                        "domain": "racktoplabs.com",
                        "share": "smb01",
                        "username": "probeuser",
                        "password": "$ENV_PASSWORD_PROBE1",
                        "remote_basedir": ".",
                        "interval": 5,
                    },
                    {
                        "name": "",
                        "address": "10.2.2.123",
                        "domain": "racktoplabs.com",
                        "share": "smb02",
                        "username": "probeuser",
                        "password": "$ENV_PASSWORD_PROBE2",
                        "remote_basedir": ".",
                        "interval": 5,
                    },
                ],
                "notifications": [
                    {
                        "headers": {"alpha-header": "alpha", "beta-header": "beta"},
                        "target": "request-bin",
                    },
                    {
                        "url": "https://events.pagerduty.com/v2/enqueue",
                        "integration_key": "this-is-a-mock-key",
                        "severity": "error",
                        "target": "pager-duty",
                    },
                    {
                        "url": "https://events.pagerduty.com/v2/enqueue",
                        "integration_key": "this-is-a-mock-key",
                        "severity": "error",
                        "target": "pager-duty",
                    },
                ],
            },
        )

    def test_config_to_si_list(self):
        """Validates proper conversion of the configuration to ShareInfo list"""
        expect_list = [
            ShareInfo(
                addr="10.2.2.23",
                share="smb01",
                domain="racktoplabs.com",
                user="probeuser",
                passwd="invalid",
            ),
            ShareInfo(
                addr="10.2.2.123",
                share="smb02",
                domain="racktoplabs.com",
                user="probeuser",
                passwd="invalid",
            ),
        ]
        config, msg = load_config("testdata/test_good1.toml")
        self.assertIsNone(msg)
        actual_list = config_to_si_list(config)
        self.assertEqual(expect_list, actual_list)

    def test_display_parsed_config(self):
        """Validates that parsed config displayed on stderr matches expectations"""
        config, msg = load_config("testdata/test_good3.toml")
        self.assertIsNone(msg)
        mock_stderr = io.StringIO()
        display_parsed_config(config, file=mock_stderr)
        actual_output = mock_stderr.getvalue()

        with open("testdata/test_good3_parsed_display.txt", "rt") as expected:
            expected_output = expected.read()
            self.assertMultiLineEqual(actual_output, expected_output)
