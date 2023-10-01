import requests

from enum import Enum
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Dict, List

from classes import FailureCounts, Latencies, Notification


BETTERSTACK_INCIDENTS_URL = "https://uptime.betterstack.com/api/v2/incidents"
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
REQUESTBIN_TEST_BUCKET_URL = "https://enslrjfpu5yha.x.pipedream.net"


def failure_counts_to_dict(fails: FailureCounts) -> Dict[str, List[float]]:
    return {
        "login": fails.login,
        "read": fails.read,
        "write": fails.write,
        "ls_dir": fails.ls_dir,
        "unlink": fails.unlink,
    }


def latencies_to_dict(latencies: Latencies) -> Dict[str, float]:
    return {
        "login": latencies.login_lat,
        "read": latencies.read_lat,
        "write": latencies.write_lat,
        "ls_dir": latencies.lsdir_lat,
        "unlink": latencies.unlink_lat,
    }


@dataclass(frozen=True)
class Data:
    target_address: str
    target_share: str
    target_domain: str

    latencies: Dict[str, List[float]]
    failed_ops: Dict[str, bool]

    @property
    def as_dict(self):
        return self.__dict__

    @property
    def latencies_as_str(self):
        tokens: List[str] = []
        for op, value in self.latencies.items():
            tokens.append(op + "=" + value.__str__())
        return " ".join(tokens)

    @property
    def failed_ops_as_str(self):
        tokens: List[str] = []
        for op, value in self.failed_ops.items():
            tokens.append(op + "=" + value.__str__())
        return " ".join(tokens)


def betterstack_description(data: Data) -> str:
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


class URL:
    """URL is a class that enables manipulation and representation of URLs with dynamic elements."""

    def __init__(self, url: str, subs: Dict[str, str] = None) -> None:
        self._subs = subs
        self._url_template = None
        self._url = None
        if subs:
            self._url_template = url
        else:
            self._url = url

    def __str__(self) -> str:
        if not self._subs:
            return self._url
        return self._url_template.format(**self._subs)

    def __repr__(self) -> str:
        if not self._subs:
            return "URL({url})".format(url=self._url)
        return "URL({url}, subs={subs})".format(url=self._url_template, subs=self._subs)


@dataclass(frozen=True)
class Result:
    """Result represents the outcome of an HTTP POST"""

    success: bool
    resp_code: int
    resp_body: str | None = None
    resp_dict: Dict[str, Any] | None = None


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
        url (_type_, optional): The URL to which the event will be POSTed. Defaults to URL(BETTERSTACK_INCIDENTS_URL).
        http_client (_type_, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    url = dest.url if dest.url else url
    headers = dest.headers if dest.headers else dict()
    if headers.get("Authorization") is None:
        headers["Authorization"] = "Bearer " + dest.integration_key

    fallback_summary = "Periodic SMB check on {data.target_address}/{data.target_share} experienced a problem"
    body = {
        "summary": dest.summary if dest.summary else fallback_summary,
        "description": betterstack_description(data),
        "requester_email": dest.source_email,
    }

    resp = http_client.post(url, json=body, headers=headers)
    return Result(
        success=resp.status_code == 201,
        resp_code=resp.status_code,
        resp_dict=resp.json(),
    )


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
        url (_type_, optional): The URL to which the event will be POSTed. Defaults to URL(REQUESTBIN_TEST_BUCKET_URL).
        http_client (_type_, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    url = dest.url if dest.url else url
    resp = http_client.post(url, json=data.as_dict, headers=dest.headers)

    return Result(
        success=resp.status_code == 200,
        resp_code=resp.status_code,
        resp_dict=resp.json(),
    )


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
        url (_type_, optional): The URL to which the event will be POSTed. Defaults to URL(PAGERDUTY_EVENTS_URL).
        http_client (_type_, optional): HTTP requests compatible http client. Defaults to requests.

    Returns:
        Result: The outcome of POSTing an event.
    """
    fallback_summary = "Periodic SMB check on {data.target_address}/{data.target_share} experienced a problem"
    pager_duty_data = {
        "payload": {
            "summary": dest.summary if dest.summary else fallback_summary,
            "severity": dest.severity if dest.severity is not None else "error",
            "source": f"{data.target_address}/{data.target_share}",
            "custom_details": data.as_dict,
        },
        "event_action": "trigger",
        "routing_key": dest.integration_key,
    }

    url = dest.url if dest.url else url
    resp = http_client.post(url, json=pager_duty_data, headers=dest.headers)

    return Result(
        success=resp.status_code == 202,
        resp_code=resp.status_code,
        resp_dict=resp.json(),
    )


class Targets(Enum):
    """Enumeration mapping destinations to callables used to POST to the destination."""

    REQUEST_BIN = requestbin_event_dest
    PAGER_DUTY = pagerduty_event_dest
    BETTER_STACK = betterstack_event_dest


def target_to_callable(name: str, default=Targets.REQUEST_BIN) -> WebhookPostFunc:
    """Returns a callable for the specified target name, if known, fallback to the default callable.

    Args:
        name (str): Named the Webhook receiver; i.e. pager-duty.
        default (Callable[[dict, str], Result], optional): Callable to return when no match for given name is found. Defaults to Targets.REQUEST_BIN.

    Returns:
        WebhookPostFunc: Callable used to deliver content to the target Webhook listener.
    """
    return {
        "request-bin": requestbin_event_dest,
        "pager-duty": pagerduty_event_dest,
        "better-stack": betterstack_event_dest,
    }.get(name, default)


def post_notification(
    data: Dict, dest: Notification, callable: WebhookPostFunc = target_to_callable
) -> Result:
    callable = callable(dest.target)
    result = callable(data, dest)
    return result


def post_all_notifications(data: Data, destinations: List[Notification]):
    for dest in destinations:
        callable: WebhookPostFunc = target_to_callable(dest.target)
        result = post_notification(data, dest)
        print(callable, result)


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
)
