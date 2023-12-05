#!/usr/bin/env python3
import os
import logging
import redis
import sys

import dynaconf

# from collections import Counter
from dataclasses import dataclass
from logfmter import Logfmter
from typing import List

from cli import parser

from common.configuration import (
    display_parsed_config_new,
    initialize_configuration,
)

from common.notifications.classes import Notification, Result

from log import LOGGER, DEFAULT_LOG_LEVEL

from notifier import pop_from_queue_and_process_forever


@dataclass(frozen=True)
class NotificationFailure:
    err: Exception | str
    exception: bool = False
    result: Result = None


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

    post_all_events = parsed_args.post_all_events
    only_post_failures = not post_all_events

    max_failed_intervals = 0
    if not post_all_events:
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
    err = pop_from_queue_and_process_forever(
        db, notifications, only_post_failures, max_failed_intervals
    )

    if err:
        LOGGER.critical(err)
        return 1

    return 0  # Never reached


if __name__ == "__main__":
    sys.exit(main())
