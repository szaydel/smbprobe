import io
import json
import os
import requests
import sys
import unittest

import requests_mock

from unittest.mock import Mock

from notifier.classes import URL

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from common.notifications.classes import Data, Notification, Result  # noqa: E402


from notifications import (  # noqa: E402
    betterstack_alert_body,
    generate_summary,
    generic_event_dest,
    msft_teams_alert_body_generator,
    pagerduty_event_dest,
    requestbin_event_dest,
    betterstack_event_dest,
    target_to_callable,
)


class TestNotifications(unittest.TestCase):
    MOCK_DATA = Data(
        target_address="12.13.14.15",
        target_share="alphashare",
        target_domain="example.com",
        latencies={"login": 1, "read": 2, "write": 3, "ls_dir": 5, "unlink": 4},
        failed_ops=dict(login=1, read=2, write=3, unlink=4, ls_dir=5),
    )

    PAGER_DUTY_EVENT_DEST = Notification(
        url="https://events.pagerduty.com/v2/enqueue",
        integration_key="alphabetagammadelta",
        headers=None,
        severity="error",
        target="pager-duty",
    )

    REQUEST_BIN_EVENT_DEST = Notification(
        url="https://dummy.example.com",
        integration_key="alphabetagammadelta",
        headers=None,
        target="request-bin",
    )

    GENERIC_EVENT_DEST = Notification(
        url="https://generic.example.com/v2/notifications",
        headers={
            "test-header-1": "test-header-1-value",
            "test-header-2": "test-header-2-value",
        },
        target="generic-post",
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

    def test_generic_event_dest_success(self):
        correlation_id = "alpha123"
        mock_http_client = requests_mock.Mocker()
        try:
            mock_http_client.start()
            mock_http_client.post(
                self.GENERIC_EVENT_DEST.url,
                status_code=200,
                json={
                    "status": "success",
                    "message": "Thank you for posting this event",
                },
            )
            data = Data(
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
            )
            actual = generic_event_dest(
                data,
                dest=self.GENERIC_EVENT_DEST,
                url=self.GENERIC_EVENT_DEST.url,
            )

            self.assertTrue(mock_http_client.called)
            self.assertEqual(
                mock_http_client.request_history[0].json().get("probe_metrics"),
                data.as_dict,
            )
            self.assertEqual(
                Result(
                    success=True,
                    resp_code=200,
                    resp_dict={
                        "status": "success",
                        "message": "Thank you for posting this event",
                    },
                ),
                actual,
            )

        finally:
            mock_http_client.stop()

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
            data = Data(
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
            )
            actual = pagerduty_event_dest(
                data,
                dest=self.PAGER_DUTY_EVENT_DEST,
            )

            self.assertTrue(mock_http_client.called)
            self.assertEqual(
                mock_http_client.request_history[0]
                .json()
                .get("payload")
                .get("custom_details"),
                data.as_dict,
            )
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

    def test_requestbin_event_dest_success(self):

        correlation_id = "alpha123"
        mock_http_client = requests_mock.Mocker()
        try:
            mock_http_client.start()
            mock_http_client.post(
                self.REQUEST_BIN_EVENT_DEST.url,
                status_code=200,
                json={"success": True},
            )

            data = Data(
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
            )
            actual = requestbin_event_dest(
                data,
                dest=self.REQUEST_BIN_EVENT_DEST,
            )

            self.assertTrue(mock_http_client.called)
            self.assertEqual(
                mock_http_client.request_history[0].json().get("probe_metrics"),
                data.as_dict,
            )
            self.assertEqual(
                Result(
                    success=True,
                    resp_code=200,
                    resp_dict={"success": True},
                ),
                actual,
            )

        finally:
            mock_http_client.stop()

    def test_betterstack_alert_body(self):
        """Validates expected betterstack template output"""
        expected = ""
        with open("testdata/notifications_betterstack_desc1.txt", "rt") as f:
            expected = f.read()
        data = Data(
            target_address="12.13.14.15",
            target_share="alphashare",
            target_domain="example.com",
            latencies={"login": 1, "read": 2, "write": 3, "ls_dir": 5, "unlink": 4},
            failed_ops=dict(login=1, read=2, write=3, unlink=4, ls_dir=5),
        )

        actual = betterstack_alert_body(data)
        self.assertEqual(actual, expected)

    def test_url_with_subs(self):
        """Validates proper url template rendering"""
        expected_repr = "URL(https://notavaliddomain/{alpha}/{beta}/{gamma}, subs={'alpha': 'first', 'beta': 'second', 'gamma': 'third'})"
        expected_str = "https://notavaliddomain/first/second/third"
        u = URL(
            "https://notavaliddomain/{alpha}/{beta}/{gamma}",
            subs=dict(alpha="first", beta="second", gamma="third"),
        )
        self.assertEqual(u.__str__(), expected_str)
        self.assertEqual(u.__repr__(), expected_repr)

    def test_url_with_missing_subs_raises_key_error(self):
        """Validates that a missing key in the subs causes a KeyError"""
        expected_error_msg = "Missing substitution key: alpha"
        u = URL(
            "https://notavaliddomain/{alpha}/{beta}/{gamma}",
            subs=dict(alphaX="first", beta="second", gamma="third"),
        )
        with self.assertRaises(KeyError) as ctx:
            u.__str__()
        actual_error_msg = ctx.exception.args[0]
        self.assertEqual(actual_error_msg, expected_error_msg)

    def test_better_stack_event_dest_success(self):
        """Validates that a successful response from betterstack is treated as a success"""
        mock_response: requests.Response = requests.Response()

        mock_response.raw = io.BytesIO(
            b'{"data":{"id":"470400461","type":"incident","attributes":{"name":"API request","url":null,"http_method":null,"cause":"Periodic SMB check on {data.target_address}/{data.target_share} experienced a problem","incident_group_id":null,"started_at":"2023-10-22T19:05:28.416Z","acknowledged_at":null,"acknowledged_by":null,"resolved_at":null,"resolved_by":null,"response_content":null,"response_options":null,"regions":null,"response_url":null,"screenshot_url":null,"origin_url":null,"escalation_policy_id":null,"call":false,"sms":false,"email":false,"push":false},"relationships":{}}}'
        )
        mock_response.status_code = 201

        mock_requests = Mock(spec=requests)
        mock_requests.post.return_value = mock_response

        dest = Notification(
            integration_key="not-a-valid-api-key",
            source_email="incident-report@example.com",
            target="better-stack",
        )

        result = betterstack_event_dest(self.MOCK_DATA, dest, http_client=mock_requests)

        self.assertTrue(result.success)
        self.assertEqual(result.resp_code, 201)

    def test_better_stack_event_dest_api_access_failure(self):
        """Validates that a successful response from betterstack is treated as a success"""
        mock_response: requests.Response = requests.Response()

        mock_response.raw = io.BytesIO(
            b'{"errors":"Invalid Team API token. How to find your Team API token: https://betterstack.com/docs/uptime/api/getting-started-with-better-uptime-api#obtaining-a-better-uptime-api-token"}'
        )
        mock_response.status_code = 401

        mock_requests = Mock(spec=requests)
        mock_requests.post.return_value = mock_response

        dest = Notification(
            integration_key="not-a-valid-api-key",
            source_email="incident-report@example.com",
            target="better-stack",
        )

        result = betterstack_event_dest(self.MOCK_DATA, dest, http_client=mock_requests)

        self.assertFalse(result.success)
        self.assertEqual(result.resp_code, 401)

    def test_target_to_callable(self):
        """Validates that the correct callable is returned for a given target"""
        cases = (
            {
                "name": "better-stack",
                "expected": betterstack_event_dest,
            },
            {
                "name": "pager-duty",
                "expected": pagerduty_event_dest,
            },
            {
                "name": "not-existent",
                "expected": requestbin_event_dest,
            },
        )
        for case in cases:
            expected = case["expected"]
            actual = target_to_callable(case["name"])
            self.assertEqual(expected, actual)
