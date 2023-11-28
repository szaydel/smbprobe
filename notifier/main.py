#!/usr/bin/env python3
import os
import logging
import pickle
import redis
import sys

import dynaconf

from collections import Counter
from dataclasses import dataclass
from logfmter import Logfmter
from typing import List, Tuple

from cli import parser

from common.configuration import (
    display_parsed_config_new,
    initialize_configuration,
)

from common.constants import DEFAULT_NOTIFICATIONS_LIST_NAME

from common.notifications.classes import Data, Notification, Result

from log import LOGGER, DEFAULT_LOG_LEVEL

from notifications import post_all_notifications


@dataclass(frozen=True)
class NotificationFailure:
    err: Exception | str
    exception: bool = False
    result: Result = None


def rpop_from_list_and_decode(
    db: redis.Redis,
) -> Tuple[Data, None] | Tuple[None, Exception]:
    data = None
    try:
        _, item = db.brpop(DEFAULT_NOTIFICATIONS_LIST_NAME)
        data: Data = pickle.loads(item)
    except redis.exceptions.ConnectionError as err:
        return None, err
    return data, None


def update_aggregated_failures_dict(aggregated_failures: dict, data: Data):
    key = data.id
    for k, v in data.failed_ops.items():
        if key not in aggregated_failures:
            aggregated_failures[key] = dict()
        if k not in aggregated_failures[key]:
            aggregated_failures[key][k] = 0
        aggregated_failures[key][k] += v
    return


def update_aggregated_latencies_dict(aggregated_latencies: dict, data: Data):
    key = data.id
    for k, v in data.latencies.items():
        if key not in aggregated_latencies:
            aggregated_latencies[key] = dict()
        if k not in aggregated_latencies[key]:
            aggregated_latencies[key][k] = []
        aggregated_latencies[key][k].extend(v)
    return


def pop_from_queue_and_process_forever(
    db: redis.Redis, notifications: List[Notification], max_failed_intervals=0
) -> Exception | None:
    counter = Counter()
    # Popping from Redis will block the loop until there is data to pop-off of
    # the list. By default blocking is indefinite, i.e. no timeout is set.
    aggregated_latencies = {}
    aggregated_failures = {}

    while True:
        data, err = rpop_from_list_and_decode(db)
        if not data:
            return err
        # If we don't have any notification destinations, just make sure to
        # pop the elements pushed into Redis and do nothing. We don't want to
        # let the list grow unbounded.
        if not notifications:
            continue

        key = data.id
        if max_failed_intervals > 0:
            update_aggregated_latencies_dict(aggregated_latencies, data)
            # for k, v in data.latencies.items():
            #     if key not in aggregated_latencies:
            #         aggregated_latencies[key] = dict()
            #     if k not in aggregated_latencies[key]:
            #         aggregated_latencies[key][k] = []
            #     aggregated_latencies[key][k].extend(v)

            update_aggregated_failures_dict(aggregated_failures, data)
            # for k, v in data.failed_ops.items():
            #     if key not in aggregated_failures:
            #         aggregated_failures[key] = dict()
            #     if k not in aggregated_failures[key]:
            #         aggregated_failures[key][k] = 0
            #     aggregated_failures[key][k] += v

        counter[key] += 1

        # print(aggregated_failures, file=sys.stderr)
        # print(aggregated_latencies, file=sys.stderr)

        if counter[key] >= max_failed_intervals:
            if max_failed_intervals > 0:
                tmp_data = Data(
                    target_address=data.target_address,
                    target_domain=data.target_domain,
                    target_share=data.target_share,
                    latencies=aggregated_latencies[key],
                    failed_ops=aggregated_failures[key],
                )
            data = tmp_data
            print("WILL LOG", data, file=sys.stderr)
            # Reset the counter, so that we don't repeatedly post notifications.
            # Rather, we want to reach the same threshold for failures again,
            # before any further notifications are posted.
            counter[data.id] = 0
            LOGGER.debug("Will post notifications at this point")
            results: List[Result] = []

            results = post_all_notifications(data, notifications)
            del aggregated_failures[key]
            del aggregated_latencies[key]

            for res in results:
                if not res.success:
                    LOGGER.error(
                        "Failed posting notification",
                        extra={
                            "body": res.resp_body,
                            "resp_dict": res.resp_dict,
                            "status_code": res.resp_code,
                        },
                    )
        else:
            counter[key] += 1
    return None  # Never reached


def main():
    # Load arguments passed via the command line.
    parsed_args = parser.parse_args()

    # Setup logging configuration
    log_timestamp = parsed_args.log_timestamp
    if log_timestamp:
        formatter = Logfmter(
            keys=["level", "ts"],
            mapping={"level": "levelname", "ts": "asctime"},
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    else:
        formatter = Logfmter(
            keys=["level"],
            mapping={"level": "levelname"},
        )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logging.basicConfig(
        handlers=[handler],
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=DEFAULT_LOG_LEVEL,
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    alert_on_first_failure = parsed_args.alert_on_first_failure

    max_failed_intervals = 0
    if not alert_on_first_failure:
        max_failed_intervals = parsed_args.consecutive_fails_limit

    config_file_path = os.environ.get(
        "SMB_MONITOR_PROBE_CONFIGFILE", parsed_args.config_file
    )

    redis_server: str = parsed_args.redis_server
    redis_port: int = parsed_args.redis_port
    redis_decode_responses: bool = parsed_args.redis_decode_responses

    settings: dynaconf.Dynaconf = initialize_configuration(config_file_path)
    display_parsed_config_new(settings)

    notifications: List[Notification] = []

    for item in settings.notifications:
        notifications.append(
            Notification(
                url=item.get("url"),
                integration_key=item.get("integration_key"),
                headers=item.get("headers"),
                severity=item.get("severity"),
                source_email=item.get("source_email"),
                summary=item.get("summary"),
                description=item.get("description"),
                target=item.get("target"),
            )
        )

    db = redis.Redis(
        host=redis_server, port=redis_port, decode_responses=redis_decode_responses
    )
    err = pop_from_queue_and_process_forever(db, notifications, max_failed_intervals)

    if err:
        LOGGER.critical(err)
        return 1

    return 0  # Never reached


if __name__ == "__main__":

    sys.exit(main())
