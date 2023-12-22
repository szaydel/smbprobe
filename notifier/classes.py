import random
import string

from typing import Dict

from common.notifications.classes import Data  # , Notification, Result


def random_event_id() -> str:
    """Generates a random event alphanumeric event id, downcased.

    Returns:
        str: 32 character id
    """
    return "".join(
        random.choice(string.ascii_lowercase + string.digits) for _ in range(32)
    )


class ProbeHealth:
    def __init__(self, max_failed_intervals: int) -> None:
        self._failed_count = 0
        self._max_failed_intervals = max_failed_intervals
        self._need_aggregation = max_failed_intervals > 0
        self._aggregated_failures = {}
        self._aggregated_latencies = {}
        self._event_id = None
        self._previous_event_id = None
        self._latest_data = None

    @property
    def data(self) -> Data:
        event_id = self._event_id if self._event_id else self._previous_event_id
        if self._need_aggregation:
            return Data(
                target_address=self._latest_data.target_address,
                target_share=self._latest_data.target_share,
                target_domain=self._latest_data.target_domain,
                correlation_id=event_id,
                latencies=self._aggregated_latencies,
                failed_ops=self._aggregated_failures,
                high_latency=self._latest_data.high_latency,
            )
        return self._latest_data.copy_with_correlation_id(event_id)

    @property
    def event_id(self):
        return self._event_id

    @property
    def failed_count(self):
        return self._failed_count

    @property
    def is_unhealthy(self) -> bool:
        return self._latest_data.is_unhealthy or self._failed_count > 0

    @property
    def should_notify(self) -> bool:
        return self._failed_count >= self._max_failed_intervals

    def incr(self):
        self._failed_count += 1

    def reset(self):
        self._previous_event_id = self._event_id
        self._event_id = None
        self._failed_count = 0
        for op in self._aggregated_failures:
            self._aggregated_failures[op] = 0
        for op in self._aggregated_latencies:
            self._aggregated_latencies[op] = []

    def collect_failures(self, data: Data):
        for op, failed in data.failed_ops.items():
            if failed:
                self._aggregated_failures[op] = self._aggregated_failures.get(op, 0) + 1

    def collect_latencies(self, data: Data):
        for op, latencies in data.latencies.items():
            if op not in self._aggregated_latencies:
                self._aggregated_latencies[op] = []
            self._aggregated_latencies[op].extend(latencies)

    def update_health(self, data: Data):
        self._latest_data = data
        if not data.is_unhealthy:
            self.reset()
            return
        # Handle probe "unhealthy" state
        self.incr()
        if self._event_id is None:
            self._event_id = random_event_id()
        if not self._need_aggregation:
            return
        # If we need to aggregate data, do that now.
        self.collect_failures(data)
        self.collect_latencies(data)


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
        try:
            return self._url_template.format(**self._subs)
        except KeyError as err:
            missing_key = err.args[0]
            raise KeyError(f"Missing substitution key: {missing_key}") from err

    def __repr__(self) -> str:
        if not self._subs:
            return "URL({url})".format(url=self._url)

        try:
            return "URL({url}, subs={subs})".format(
                url=self._url_template, subs=self._subs
            )
        except KeyError as err:
            missing_key = err.args[0]
            raise KeyError(f"Missing substitution key: {missing_key}") from err
