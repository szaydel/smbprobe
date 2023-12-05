import os
import sys
import unittest

import requests_mock

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from classes import ProbeHealth, Data  # noqa: E402

from common.notifications.classes import Notification, Result  # noqa: E402

from .notifier import (  # noqa: E402
    post_and_update_if_necessary,
    probe_state_notification_needed,
)


class TestNotifier(unittest.TestCase):
    PAGER_DUTY_EVENT_DEST = Notification(
        url="https://events.pagerduty.com/v2/enqueue",
        integration_key="alphabetagammadelta",
        headers=None,
        severity="error",
        target="pager-duty",
    )

    def test_post_and_update_if_necessary_different_event_id(self):
        key = ("alpha", "beta", "gamma")
        incident_event_ids = {key: "test-event-12"}

        test_probe = ProbeHealth(max_failed_intervals=2)
        test_probe._event_id = "test-event-1"
        test_probe._latest_data = Data(
            target_address="1.2.3.4",
            target_share="share",
            target_domain="test.example.com",
            latencies={
                "login": [],
                "read": [],
                "write": [],
                "ls_dir": [],
                "unlink": [],
            },
            failed_ops={
                "login": 0,
                "read": 10,
                "write": 10,
                "ls_dir": 10,
                "unlink": 10,
            },
        )

        probes_health = {
            key: test_probe,
        }

        notifications = [
            self.PAGER_DUTY_EVENT_DEST,
        ]

        mock_http_client = requests_mock.Mocker()

        try:
            mock_http_client.start()
            mock_http_client.post(
                self.PAGER_DUTY_EVENT_DEST.url,
                status_code=202,
                json={
                    "status": "success",
                    "message": "Event processed",
                    "dedup_key": "test-event-12",
                },
            )
            actual = post_and_update_if_necessary(
                key, probes_health, incident_event_ids, notifications
            )

            expected = [
                Result(
                    success=True,
                    resp_code=202,
                    resp_body='{"status": "success", "message": "Event processed", "dedup_key": "test-event-12"}',
                    resp_dict={
                        "status": "success",
                        "message": "Event processed",
                        "dedup_key": "test-event-12",
                    },
                )
            ]

            self.assertEqual(expected, actual)

        finally:
            mock_http_client.stop()

    def test_post_and_update_if_necessary_same_event_id(self):
        key = ("alpha", "beta", "gamma")
        event_id = "test-event-1"
        incident_event_ids = {key: event_id}

        test_probe = ProbeHealth(max_failed_intervals=2)
        test_probe._event_id = event_id
        test_probe._latest_data = Data(
            target_address="1.2.3.4",
            target_share="share",
            target_domain="test.example.com",
            latencies={
                "login": [],
                "read": [],
                "write": [],
                "ls_dir": [],
                "unlink": [],
            },
            failed_ops={
                "login": 0,
                "read": 10,
                "write": 10,
                "ls_dir": 10,
                "unlink": 10,
            },
        )

        probes_health = {
            key: test_probe,
        }

        notifications = []

        actual = post_and_update_if_necessary(
            key, probes_health, incident_event_ids, notifications
        )

        self.assertIsNone(actual)

    def test_post_and_update_if_necessary_missing_key(self):
        key = ("alpha", "beta", "gamma")
        incident_event_ids = {key: "test-event-1"}

        test_probe = ProbeHealth(max_failed_intervals=2)
        test_probe._event_id = "test-event-1"
        test_probe._latest_data = Data(
            target_address="1.2.3.4",
            target_share="share",
            target_domain="test.example.com",
            latencies={
                "login": [],
                "read": [],
                "write": [],
                "ls_dir": [],
                "unlink": [],
            },
            failed_ops={
                "login": 0,
                "read": 10,
                "write": 10,
                "ls_dir": 10,
                "unlink": 10,
            },
        )

        probes_health = {
            key + key: test_probe,
        }

        notifications = []

        actual = post_and_update_if_necessary(
            key, probes_health, incident_event_ids, notifications
        )

        self.assertIsNone(actual)

    def test_probe_state_notification_needed(self):
        key = ("alpha", "beta", "gamma")
        event_id = "test-event-1"
        incident_event_ids = {key: event_id}

        test_probe = ProbeHealth(max_failed_intervals=2)
        test_probe._event_id = event_id
        test_probe._latest_data = Data(
            target_address="1.2.3.4",
            target_share="share",
            target_domain="test.example.com",
            latencies={
                "login": [],
                "read": [],
                "write": [],
                "ls_dir": [],
                "unlink": [],
            },
            failed_ops={
                "login": 0,
                "read": 10,
                "write": 10,
                "ls_dir": 10,
                "unlink": 10,
            },
        )

        probes_health = {
            key: test_probe,
        }

        actual = probe_state_notification_needed(key, probes_health, incident_event_ids)

        self.assertFalse(actual)

    def test_probe_state_notification_needed_probe_is_unhealthy(self):
        key = ("alpha", "beta", "gamma")
        event_id = "test-event-1"
        incident_event_ids = {}

        data = Data(
            target_address="1.2.3.4",
            target_share="share",
            target_domain="test.example.com",
            latencies={
                "login": [],
                "read": [],
                "write": [],
                "ls_dir": [],
                "unlink": [],
            },
            failed_ops={
                "login": 0,
                "read": 0,
                "write": 10,
                "ls_dir": 0,
                "unlink": 0,
            },
        )

        cases = {
            "unhealthy failure count not reached": (
                ProbeHealth(max_failed_intervals=2),
                False,
            ),
            "unhealthy failure count reached": (
                ProbeHealth(max_failed_intervals=2),
                True,
            ),
        }

        # This case should not require notification, because the failure count
        # hasn't yet been reached.
        cases["unhealthy failure count not reached"][0]._event_id = event_id
        cases["unhealthy failure count not reached"][0]._latest_data = data

        # This case should require notification, because the failure count
        # has been reached.
        cases["unhealthy failure count reached"][0]._event_id = event_id
        cases["unhealthy failure count reached"][0]._latest_data = data
        cases["unhealthy failure count reached"][0]._failed_count = 2

        for name, case in cases.items():
            probes_health = {
                key: case[0],
            }

            expected = case[1]

            actual = probe_state_notification_needed(
                key, probes_health, incident_event_ids
            )

            self.assertEqual(
                expected,
                actual,
                msg=f"Test case: '{name}' failed to produce expected result",
            )

    def test_probe_state_notification_needed_missing_key(self):
        key = ("alpha", "beta", "gamma")
        event_id = "test-event-1"
        incident_event_ids = {key: event_id}

        test_probe = ProbeHealth(max_failed_intervals=2)
        test_probe._event_id = event_id
        test_probe._latest_data = Data(
            target_address="1.2.3.4",
            target_share="share",
            target_domain="test.example.com",
            latencies={
                "login": [],
                "read": [],
                "write": [],
                "ls_dir": [],
                "unlink": [],
            },
            failed_ops={
                "login": 0,
                "read": 10,
                "write": 10,
                "ls_dir": 10,
                "unlink": 10,
            },
        )

        probes_health = {
            key + key: test_probe,
        }

        actual = probe_state_notification_needed(key, probes_health, incident_event_ids)

        self.assertFalse(actual)
