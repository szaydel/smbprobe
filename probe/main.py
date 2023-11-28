#!/usr/bin/env python3
import logging
import os
import sys

from threading import Thread
from typing import List

from logfmter import Logfmter

from prometheus_client import start_http_server

from cli import parser

from common.configuration import (
    config_to_share_info_list2,
    display_parsed_config_new,
    initialize_configuration,
)

from log import LOGGER, DEFAULT_LOG_LEVEL

from metrics import SMB_HIGH_OP_LATENCY, SMB_OP_FAILED

from probe import repeat_forever, run_probe_and_alert


if __name__ == "__main__":
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

    config_file_path = os.environ.get(
        "SMB_MONITOR_PROBE_CONFIGFILE", parsed_args.config_file
    )

    settings = initialize_configuration(config_file_path)
    si_list = config_to_share_info_list2(settings)
    display_parsed_config_new(settings)
    # sys.exit(0)

    # config, msg = load_config(config_file_path)
    # if not config:
    #     err_msg = f"Unable to load configuration from '{config_file_path}': {msg}"
    #     LOGGER.critical(err_msg)
    #     sys.exit(1)

    # display_parsed_config(config)
    # si_list = config_to_share_info_list(config)
    if not si_list:
        LOGGER.critical("No shares specified in the configuration; exiting")
        sys.exit(1)

    # notifications = config["notifications"]

    # Thresholds from args
    login_threshold = parsed_args.login_threshold
    read_threshold = parsed_args.read_threshold
    write_threshold = parsed_args.write_threshold
    ls_dir_threshold = parsed_args.ls_dir_threshold
    unlink_threshold = parsed_args.unlink_threshold

    # We set certain counters to zero here as a way of pre-creating them so
    # that we always see them in the output of the metric queries, even if
    # there were no events that led to them becoming non-zero.
    for si in si_list:
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "login").inc(0)
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "read").inc(0)
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "write").inc(0)
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "ls_dir").inc(0)
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "unlink").inc(0)
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "login").inc(0)
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "read").inc(0)
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "write").inc(0)
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "ls_dir").inc(0)
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "unlink").inc(0)

    # Start up the server to expose the metrics.
    start_http_server(8000)

    threads: List[Thread] = []
    for idx, si in enumerate(si_list):
        threads.append(
            Thread(
                target=repeat_forever,
                args=(
                    run_probe_and_alert,
                    si,
                    ".",
                    login_threshold,
                    read_threshold,
                    write_threshold,
                    ls_dir_threshold,
                    unlink_threshold,
                ),
                kwargs=dict(interval=si.interval),
            )
        )

    # Start all threads, do not wait on them here, instead join below.
    for t in threads:
        t.start()

    # Wait for threads to terminate. Currently, there is no path leading to
    # threads exiting thus allowing them to be join()ed. Therefore, this will
    # just block forever. When we implement more sophistication and actually
    # have a way for the thread to exit on its own, we will be ready for it
    # here.
    for t in threads:
        t.join()
