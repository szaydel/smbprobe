import argparse

from common.constants import (
    DEFAULT_ALERT_ON_FIRST_FAILURE,
    DEFAULT_CONFIG_FILE,
    DEFAULT_CONSECUTIVE_FAILS_LIMIT,
)

parser = argparse.ArgumentParser(
    description="A notification service responsible for posting notifications from the probe service",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)

parser.add_argument(
    "--config-file",
    default=DEFAULT_CONFIG_FILE,
    help="Location of the SMB probe's configuration file",
)

parser.add_argument(
    "--log-timestamp",
    action=argparse.BooleanOptionalAction,
    dest="log_timestamp",
    type=bool,
    default=True,
    required=False,
    help="Whether or not to prefix log lines with an ISO8601 timestamp",
)

parser.add_argument(
    "--consecutive-fails-limit",
    type=int,
    default=DEFAULT_CONSECUTIVE_FAILS_LIMIT,
    required=False,
    help=f"Number of consecutive failures allowed before reporting probing failure for the given share. Default is {DEFAULT_CONSECUTIVE_FAILS_LIMIT}.",
)

parser.add_argument(
    "--alert-on-first-failure",
    type=bool,
    default=DEFAULT_ALERT_ON_FIRST_FAILURE,
    required=False,
    help=f"Whether to emit notifications immediately after a failure or to use the threshold value. Default is {DEFAULT_ALERT_ON_FIRST_FAILURE}.",
)

parser.add_argument(
    "--redis-server",
    type=str,
    default="redis",
    required=False,
    help="Address (or DNS name) of the redis server / container",
)

parser.add_argument(
    "--redis-port",
    type=int,
    default=6379,
    required=False,
    help="Port on which to bind to the Redis server / container",
)

parser.add_argument(
    "--redis-decode-responses",
    type=bool,
    default=False,
    required=False,
    help="Whether or not responses from the Redis server should be auto-decoded.",
)
