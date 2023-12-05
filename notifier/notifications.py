import requests

from enum import Enum
from collections.abc import Callable
from typing import Any, Dict, List

from classes import URL
from common.notifications.classes import Data, Notification, Result

BETTERSTACK_INCIDENTS_URL = "https://uptime.betterstack.com/api/v2/incidents"
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
REQUESTBIN_TEST_BUCKET_URL = "https://enslrjfpu5yha.x.pipedream.net"


def generate_summary(data: Data) -> str:
    """Generates a summary line for use in notifications.

    Args:
        data (Data): Probe data from which the summary will be generated.

    Returns:
        str: Formatted summary line with details from the data
    if data.is_unhealthy:
    """
    is_healthy = not data.is_unhealthy

    if is_healthy:
        return f"Periodic SMB probing on {data.target_address}/{data.target_share} which previously detected a problem is now healthy"
    return f"Periodic SMB probing on {data.target_address}/{data.target_share} detected a problem"


def msft_teams_alert_body_generator(data: Data) -> Dict:
    """Generates a dictionary body suitable for posting to Microsoft Teams via a webhook.

    Args:
        data (Data): Data with which to build the payload.

    Returns:
        Dict: Complete payload to be POSTed to the incoming webhook of some MSFT teams channel.
    """

    def heading(text: str) -> Dict:
        return {
            "text": text,
            "type": "TextBlock",
            "size": "extraLarge",
            "style": "heading",
            "weight": "bolder",
            "wrap": True,
        }

    summary = generate_summary(data)

    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "type": "AdaptiveCard",
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version": "1.6",
                    "body": [
                        heading("Summary"),
                        {
                            "type": "TextBlock",
                            "text": summary,
                            "wrap": True,
                        },
                        heading("Probe Details"),
                        {
                            "type": "FactSet",
                            "facts": [
                                {
                                    "title": "Target Address",
                                    "value": data.target_address,
                                },
                                {
                                    "title": "Target Share",
                                    "value": data.target_share,
                                },
                                {
                                    "title": "Target Domain",
                                    "value": data.target_domain,
                                },
                            ],
                        },
                        heading("Latencies"),
                        {
                            "type": "TextBlock",
                            "text": data.latencies_as_str,
                            "wrap": True,
                            "fontType": "Monospace",
                        },
                        heading("Failed Operations"),
                        {
                            "type": "TextBlock",
                            "text": data.failed_ops_as_str,
                            "wrap": True,
                            "fontType": "Monospace",
                        },
                    ],
                },
            }
        ],
    }


def betterstack_alert_body(data: Data) -> str:
    """Generates a string representation of the alert data suitable for use in the description field of the betterstack body.

    Args:
        data (Data): Native representation of the details to be communicated via the alert.

    Returns:
        str: Rendered template filled with the supplied data.
    """
    return (
        f"_target address_ => `{data.target_address}`\n"
        f"_target share_ => `{data.target_share}`\n"
        f"_target domain_ => `{data.target_domain}`\n"
        f"_latencies_ => `({data.latencies_as_str})`\n"
        f"_failed ops_ => `({data.failed_ops_as_str})`\n"
    )


WebhookPostFunc = Callable[[Dict[str, Any], Dict[str, str], Any], Result]


def betterstack_event_dest(
    data: Data,
    dest: Notification,
    url=URL(BETTERSTACK_INCIDENTS_URL),
    http_client=requests,
) -> Result:
    """Generates an emits an event to betterstack.

    Args:
        data (Data): Data with which to build the payload.
        dest (Notification): Destination to which the event will be sent.
        url (URL, optional): The URL to which the event will be POSTed. Defaults to URL(BETTERSTACK_INCIDENTS_URL).
        http_client (requests.Request, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    url = dest.url if dest.url else url
    headers = dest.headers if dest.headers else dict()
    integration_key = dest.integration_key

    if not integration_key:
        return Result(
            success=False,
            resp_code=-1,
            resp_dict=dict(),
        )

    summary = generate_summary(data)

    if headers.get("Authorization") is None:
        headers["Authorization"] = "Bearer " + integration_key

    body = {
        "summary": dest.summary if dest.summary else summary,
        "description": betterstack_alert_body(data),
        "requester_email": dest.source_email,
    }

    resp = http_client.post(url, json=body, headers=headers)
    return Result(
        success=resp.status_code == 201,
        resp_code=resp.status_code,
        resp_dict=resp.json(),
    )


def _generic_event_common_impl(
    data: Data,
    dest: Notification,
    url=URL(REQUESTBIN_TEST_BUCKET_URL),
    http_client=requests,
) -> Result:
    url = dest.url if dest.url else url

    summary = generate_summary(data)

    payload = {
        "probe_metrics": data.as_dict,
        "summary": summary,
    }

    resp = http_client.post(url, json=payload, headers=dest.headers)

    return Result(
        success=resp.status_code == 200,
        resp_code=resp.status_code,
        resp_dict=resp.json(),
    )


def generic_event_dest(
    data: Data,
    dest: Notification,
    url=None,
    http_client=requests,
) -> Result:
    """Generates and emits an event to requestbin.

    Args:
        data (Data): Data with which to build the payload.
        dest (Notification): Destination to which the event will be sent.
        url (URL, optional): The URL to which the event will be POSTed. Defaults to URL(REQUESTBIN_TEST_BUCKET_URL).
        http_client (requests, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    url = dest.url

    if not url:
        return Result(
            success=False,
            resp_code=-1,
            resp_dict=dict(),
        )

    return _generic_event_common_impl(data, dest, url, http_client)


def requestbin_event_dest(
    data: Data,
    dest: Notification,
    url=URL(REQUESTBIN_TEST_BUCKET_URL),
    http_client=requests,
) -> Result:
    """Generates and emits an event to requestbin.

    Args:
        data (Data): Data with which to build the payload.
        dest (Notification): Destination to which the event will be sent.
        url (URL, optional): The URL to which the event will be POSTed. Defaults to URL(REQUESTBIN_TEST_BUCKET_URL).
        http_client (requests, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    return _generic_event_common_impl(data, dest, url, http_client)


def pagerduty_event_dest(
    data: Data,
    dest: Notification,
    url=URL(PAGERDUTY_EVENTS_URL),
    http_client=requests,
) -> Result:
    """Generates and emits an event to pagerduty.

    Args:
        data (Data): Data with which to build the payload.
        dest (Notification): Destination to which the event will be sent.
        url (URL, optional): The URL to which the event will be POSTed. Defaults to URL(PAGERDUTY_EVENTS_URL).
        http_client (requests, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """

    summary = generate_summary(data)

    pager_duty_data = {
        "payload": {
            "summary": dest.summary if dest.summary else summary,
            "severity": dest.severity if dest.severity is not None else "error",
            "source": f"{data.target_address}/{data.target_share}",
            "custom_details": data.as_dict,
        },
        "dedup_key": data.correlation_id,
        "event_action": "trigger" if data.is_unhealthy else "resolve",
        "routing_key": dest.integration_key,
    }

    url = dest.url if dest.url else url
    resp = http_client.post(url, json=pager_duty_data, headers=dest.headers)

    return Result(
        success=resp.status_code == 202,
        resp_code=resp.status_code,
        resp_body=resp.text,
        resp_dict=resp.json() if resp.status_code == 202 else {},
    )


def msft_teams_event_dest(
    data: Data,
    dest: Notification,
    url=None,
    http_client=requests,
) -> Result:
    """Generates and emits an event to a Microsoft Teams Channel via Inbound Webhooks.

    Args:
        data (Data): Data with which to build the payload.
        dest (Notification): Destination to which the event will be sent.
        url (URL, optional): The URL to which the event will be POSTed.
        http_client (requests, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    url = dest.url

    if not url:
        return Result(
            success=False,
            resp_code=-1,
            resp_dict=dict(),
        )

    adaptive_card = msft_teams_alert_body_generator(data)
    resp = http_client.post(url, json=adaptive_card, headers=dest.headers)

    return Result(
        success=resp.status_code == 200,
        resp_code=resp.status_code,
        resp_dict=resp.json() if resp.status_code == 200 else None,
    )


class Targets(Enum):
    """Enumeration mapping destinations to callables used to POST to the destination."""

    REQUEST_BIN = requestbin_event_dest
    PAGER_DUTY = pagerduty_event_dest
    BETTER_STACK = betterstack_event_dest
    GENERIC_POST = generic_event_dest
    MSFT_TEAMS = msft_teams_event_dest


def target_to_callable(name: str, default=Targets.REQUEST_BIN) -> WebhookPostFunc:
    """Returns a callable for the specified target name, if known, fallback to the default callable.

    Args:
        name (str): Named the Webhook receiver; i.e. pager-duty.
        default (Callable[[dict, str], Result], optional): Callable to return when no match for given name is found. Defaults to Targets.REQUEST_BIN.

    Returns:
        WebhookPostFunc: Callable used to deliver content to the target Webhook listener.
    """
    return {
        "request-bin": Targets.REQUEST_BIN,
        "pager-duty": Targets.PAGER_DUTY,
        "better-stack": Targets.BETTER_STACK,
        "generic-post": Targets.GENERIC_POST,
        "msft-teams": Targets.MSFT_TEAMS,
    }.get(name, default)


def post_notification(
    data: Data,
    notification: Notification,
    callable: WebhookPostFunc = target_to_callable,
) -> Result:
    return callable(data, notification)


def post_all_notifications(
    data: Data, destinations: List[Notification]
) -> List[Result]:
    notification_results = []
    for dest in destinations:
        callable: WebhookPostFunc = target_to_callable(dest.target)
        result = post_notification(data, dest, callable=callable)
        notification_results.append(result)
    return notification_results


test_notifications = [
    Notification(
        headers={"header-alpha": "a", "header-beta": "b"},
        target="request-bin",
    ),
    Notification(
        url="https://events.pagerduty.com/v2/enqueue",
        integration_key="3cb139901e21460cd09b61b9339d52d9",
        headers=None,
        severity="error",
        target="pager-duty",
    ),
    Notification(
        integration_key="wickH1EbeAaHNq1EpMsH6Qc3",
        source_email="incident-report@example.com",
        target="better-stack",
    )
    # Notification(
    #     url="https://events.pagerduty.com/v2/enqueue",
    #     integration_key="3cb139901e21460cd09b61b9339d52d9",
    #     headers=None,
    #     severity="error",
    #     target="pager-duty",
    # ),
]

test_data = Data(
    target_address="12.13.14.15",
    target_share="alphashare",
    target_domain="example.com",
    latencies={"login": 1, "read": 2, "write": 3, "ls_dir": 5, "unlink": 4},
    failed_ops=dict(login=1, read=2, write=3, unlink=4, ls_dir=5),
    correlation_id="fake-correlation-id",
)
