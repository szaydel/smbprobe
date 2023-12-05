import io
import json
import os
import sys
import unittest

import requests_mock

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from common.notifications.classes import Data, Notification, Result  # noqa: E402
from notifications import (  # noqa: E402
    generate_summary,
    msft_teams_alert_body_generator,
    pagerduty_event_dest,
)


class TestNotifications(unittest.TestCase):
    PAGER_DUTY_EVENT_DEST = Notification(
        url="https://events.pagerduty.com/v2/enqueue",
        integration_key="alphabetagammadelta",
        headers=None,
        severity="error",
        target="pager-duty",
    )

    def test_generate_summary(self):
        cases = {
            "healthy": (
                Data(
                    target_address="1.2.3.4",
                    target_share="share",
                    target_domain="test.example.com",
                    latencies={"login": [0.1, 0.2, 0.3]},
                    failed_ops={
                        "login": 0,
                        "read": 0,
                        "write": 0,
                        "ls_dir": 0,
                        "unlink": 0,
                    },
                    correlation_id="123",
                ),
                "Periodic SMB probing on 1.2.3.4/share which previously detected a problem is now healthy",
            ),
            "unhealthy:low-latency": (
                Data(
                    target_address="1.2.3.4",
                    target_share="share",
                    target_domain="test.example.com",
                    latencies={"login": [0.1, 0.2, 0.3]},
                    failed_ops={
                        "login": 3,
                        "read": 0,
                        "write": 0,
                        "ls_dir": 0,
                        "unlink": 0,
                    },
                    correlation_id="123",
                ),
                "Periodic SMB probing on 1.2.3.4/share detected a problem",
            ),
            "unhealthy:high-latency": (
                Data(
                    target_address="1.2.3.4",
                    target_share="share",
                    target_domain="test.example.com",
                    latencies={"login": [2.1, 2.2, 2.3]},
                    failed_ops={
                        "login": 0,
                        "read": 0,
                        "write": 0,
                        "ls_dir": 0,
                        "unlink": 0,
                    },
                    high_latency=True,
                    correlation_id="123",
                ),
                "Periodic SMB probing on 1.2.3.4/share detected a problem",
            ),
        }

        for name, test_case in cases.items():
            data, expected = test_case
            actual = generate_summary(data)

            self.assertEqual(
                expected,
                actual,
                msg=f"Equality assertion failed for test case '{name}'",
            )

    def test_msft_teams_alert_body_generator(self):
        latencies = dict(
            login=[
                2.4163775299154433,
                4.457721214459032,
                3.809273464213238,
                3.8594737758377256,
                2.9488558185249705,
            ],
            read=[
                2.4163775299154433,
                4.457721214459032,
                3.809273464213238,
                3.8594737758377256,
                2.9488558185249705,
            ],
            write=[
                2.4163775299154433,
                4.457721214459032,
                3.809273464213238,
                3.8594737758377256,
                2.9488558185249705,
            ],
            ls_dir=[
                2.4163775299154433,
                4.457721214459032,
                3.809273464213238,
                3.8594737758377256,
                2.9488558185249705,
            ],
            unlink=[
                2.4163775299154433,
                4.457721214459032,
                3.809273464213238,
                3.8594737758377256,
                2.9488558185249705,
            ],
        )
        failed_ops = dict(login=1, read=2, write=3, unlink=4, ls_dir=5)

        data: Data = Data(
            target_address="192.168.100.101",
            target_share="test01",
            target_domain="test.example.com",
            latencies=latencies,
            failed_ops=failed_ops,
            correlation_id="fake-correlation-id",
        )

        actual = msft_teams_alert_body_generator(data)
        baseline_file = os.path.join(
            os.path.dirname(__file__), "..", "testdata", "msft_teams_alert_card.json"
        )

        with open(baseline_file, "rb") as f:
            expected = json.load(f)

        self.assertEqual(expected, actual)

    def test_pager_duty_event_dest_success(self):
        correlation_id = "alpha123"
        mock_http_client = requests_mock.Mocker()
        try:
            mock_http_client.start()
            mock_http_client.post(
                self.PAGER_DUTY_EVENT_DEST.url,
                status_code=202,
                json={
                    "status": "success",
                    "message": "Event processed",
                    "dedup_key": correlation_id,
                },
            )
            actual = pagerduty_event_dest(
                Data(
                    target_address="192.168.100.101",
                    target_share="share",
                    target_domain="test.example.com",
                    latencies={"login": [0.1, 0.2, 0.3]},
                    failed_ops={
                        "login": 3,
                        "read": 0,
                        "write": 0,
                        "ls_dir": 0,
                        "unlink": 0,
                    },
                    correlation_id=correlation_id,
                ),
                dest=self.PAGER_DUTY_EVENT_DEST,
            )

            self.assertTrue(mock_http_client.called)
            self.assertEqual(
                Result(
                    success=True,
                    resp_code=202,
                    resp_body='{"status": "success", "message": "Event processed", "dedup_key": "alpha123"}',
                    resp_dict={
                        "status": "success",
                        "message": "Event processed",
                        "dedup_key": "alpha123",
                    },
                ),
                actual,
            )

        finally:
            mock_http_client.stop()

    def test_pager_duty_event_dest_400_error(self):
        correlation_id = "alpha123"
        mock_http_client = requests_mock.Mocker()
        try:
            mock_http_client.start()
            mock_http_client.post(
                self.PAGER_DUTY_EVENT_DEST.url,
                status_code=400,
                body=io.BytesIO(b"Invalid routing key"),
            )
            actual = pagerduty_event_dest(
                Data(
                    target_address="192.168.100.101",
                    target_share="share",
                    target_domain="test.example.com",
                    latencies={"login": [0.1, 0.2, 0.3]},
                    failed_ops={
                        "login": 3,
                        "read": 0,
                        "write": 0,
                        "ls_dir": 0,
                        "unlink": 0,
                    },
                    correlation_id=correlation_id,
                ),
                dest=self.PAGER_DUTY_EVENT_DEST,
            )

            self.assertTrue(mock_http_client.called)
            self.assertEqual(
                Result(
                    success=False,
                    resp_code=400,
                    resp_body="Invalid routing key",
                    resp_dict={},
                ),
                actual,
            )

        finally:
            mock_http_client.stop()
