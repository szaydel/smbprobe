import unittest

from io import BytesIO
import requests

from unittest.mock import Mock

from notifications import (
    betterstack_alert_body,
    betterstack_event_dest,
    Data,
    Notification,
    URL,
)


class TestNotifications(unittest.TestCase):
    MOCK_DATA = Data(
        target_address="12.13.14.15",
        target_share="alphashare",
        target_domain="example.com",
        latencies={"login": 1, "read": 2, "write": 3, "ls_dir": 5, "unlink": 4},
        failed_ops=dict(login=1, read=2, write=3, unlink=4, ls_dir=5),
    )

    def test_betterstack_alert_body(self):
        """Validates expected betterstack template output"""
        expected = ""
        with open("../testdata/notifications_betterstack_desc1.txt", "rt") as f:
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

        mock_response.raw = BytesIO(
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

        mock_response.raw = BytesIO(
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
