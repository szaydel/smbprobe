#!/usr/bin/env python3
import logging
import random
import os

# import subprocess
import sys
import tempfile
import time

from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import Callable, List, Tuple

import pexpect
import pexpect.replwrap

from logfmter import Logfmter
from prometheus_client import (
    Gauge,
    start_http_server,
    Counter,
    Histogram,
    # write_to_textfile,
)

from cli_arg_parse import parser
from classes import ShareInfo, FailureCounts, Latencies, RandomDataFile
from constants import DEFAULT_LOOP_INTERVAL, DEFAULT_NUM_FILES, IOSIZE


EvalLineCallable = Callable[[pexpect.replwrap.REPLWrapper, str], Tuple[bool, str]]

FilePutGetCallable = Callable[
    [object, str, str, pexpect.replwrap.REPLWrapper, EvalLineCallable],
    Tuple[bool, str],
]


SMB_STATUS = Gauge(
    "smb_service_state", "Current state of SMB service based on results of the probe"
)

SMB_OP_LATENCY = Histogram(
    "smb_operation_latency_seconds",
    "Time it takes to complete a given SMB operation, such as read, write, lsdir, unlink",
    labelnames=["address", "operation"],
)

SMB_HIGH_OP_LATENCY = Counter(
    "smb_latency_above_threshold_total",
    "Count of times the probe detected high operation latency during a read, write, lsdir, unlink",
    labelnames=["address", "operation"],
)

SMB_OP_FAILED = Counter(
    "smb_operation_failed_total",
    "Number of times a particular probe operation did not succeed",
    labelnames=["address", "operation"],
)

DEFAULT_LOG_LEVEL = logging.DEBUG  # Change level to adjust output verbosity

LOGGER = logging.getLogger("smb-probe")

PUT = object()
GET = object()
SHARE_ROOT = object()


def timeit(func):
    """Decorator which collects timing of whatever callable it wraps.

    Args:
        func (Any): Function to decorate with the timer.
    """

    def wrapper(*args, **kwargs):
        before = time.perf_counter()
        result = func(*args, **kwargs)
        return result, time.perf_counter() - before

    return wrapper


@timeit
def login_and_get_repl(
    si: ShareInfo,
) -> Tuple[pexpect.replwrap.REPLWrapper | None, str | None]:
    """Logs into the remote SMB server and initializes a REPL class for further interaction with the probe.

    Args:
        si (ShareInfo): Share description class.

    Returns:
        Tuple[pexpect.replwrap.REPLWrapper | None, str | None]: Initialized REPL wrapper class or None on failure.
    """
    addr = si.addr
    share = si.share
    domain = si.domain
    user = si.user
    passwd = si.passwd

    cmd_str = f"smbclient -E //{addr}/{share} -W {domain} -U {user}%{passwd}"
    try:
        child = pexpect.spawn(cmd_str, encoding="utf8", echo=False)
        replw = pexpect.replwrap.REPLWrapper(
            child, orig_prompt=r"smb: \>", prompt_change=None
        )
        return replw, None
    except pexpect.exceptions.EOF as err:
        prefix = "before (last 100 chars): "
        for token in err.value.split("\n"):
            if token.startswith(prefix):
                err_msg = token[len(prefix) + 1 : -5]
        return None, f"login failed with message: {err_msg}"


def close_connection(repl: pexpect.replwrap.REPLWrapper) -> Tuple[bool, str]:
    """Logs off and closes the REPL.

    Args:
        repl (pexpect.replwrap.REPLWrapper): Initialized class connected with the smbclient shell.

    Returns:
        Tuple[bool, str]: True, None if succeeded, else False and error message.
    """
    ok, msg = eval_line_in_repl(repl, "logoff")
    if not ok:
        return ok, msg
    ok, msg = eval_line_in_repl(repl, "quit")
    if not ok:
        return ok, msg


def eval_line_in_repl(
    replw: pexpect.replwrap.REPLWrapper, cmd_line: str
) -> Tuple[bool, str | None]:
    """Passes a command to the subprocess which is assumed to be running a REPL.

    Args:
        replw (pexpect.replwrap.REPLWrapper): REPL running as our child process.
        cmd_line (str): Command which the REPL must execute and give results from.

    Returns:
        Tuple[bool, str]: True, None if succeeded, else False and error message.
    """
    try:
        resp = replw.run_command(cmd_line)
        if "NT_STATUS" in resp:
            tokens = resp.split()
            error_msg = f"smbclient failed evaluating: '{cmd_line}';  error: {' '.join(tokens[1:-1])}"
            return False, error_msg
    except pexpect.exceptions.TIMEOUT:
        error_msg = f"smbclient timed out evaluating: '{cmd_line}'"
        return False, error_msg
    except pexpect.exceptions.EOF:
        # There shouldn't be anything else to read, but if there is, read it
        # and discard it, to make sure that we are not blocked in wait().
        if replw.child.stdout.readable():
            _ = replw.child.stdout.read()
        if replw.child.stderr.readable():
            _ = replw.child.stderr.read()
        retcode = replw.child.wait()
        succeeded = retcode == 0
        return (
            succeeded,
            None if succeeded else f"Command exited with non-zero error: {retcode}",
        )
    return True, None


@timeit
def list_directory(
    remote_dir: str,
    repl: pexpect.replwrap.REPLWrapper = None,
    eval_line_func: EvalLineCallable = eval_line_in_repl,
) -> Tuple[bool, str | None]:
    """Lists contents of the directory on the SMB share.

    Args:
        remote_dir (str): Path to the directory on the SMB share.
        repl (pexpect.replwrap.REPLWrapper): Initialized class connected with the smbclient shell.
        eval_line_func (EvalLineCallable, optional): Function with which to evaluate the REPL command. Defaults to eval_line_in_repl.

    Returns:
        Tuple[bool, str|None]: True and no message on success, False and a message on failure.
    """
    if remote_dir == SHARE_ROOT:
        repl_cmd = "ls"
    else:
        repl_cmd = f"ls {remote_dir}"

    return eval_line_func(repl, repl_cmd)


@timeit
def remove_file(
    remote_file: str,
    repl: pexpect.replwrap.REPLWrapper = None,
    eval_line_func: EvalLineCallable = eval_line_in_repl,
) -> Tuple[bool, str | None]:

    """Removes file on the SMB share.

    Args:
        remote_file (str): Path to the file on the SMB share.
        repl (pexpect.replwrap.REPLWrapper): Initialized class connected with the smbclient shell.
        eval_line_func (EvalLineCallable, optional): Function with which to evaluate the REPL command. Defaults to eval_line_in_repl.

    Returns:
        Tuple[bool, str|None]: True and no message on success, False and a message on failure.
    """
    repl_cmd = f"rm {remote_file}"
    return eval_line_func(repl, repl_cmd)


def file_put_get_impl(
    direction: object,
    src_file,
    dst_file,
    repl: pexpect.replwrap.REPLWrapper = None,
    eval_line_func: EvalLineCallable = eval_line_in_repl,
) -> Tuple[bool, str | None]:
    """Implements the steps to place the file on the SMB share or retrieve the
    file from the SMB share.

    Args:
        direction (object): Whether this is a read or a write.
        src_file (str): Path to the source of the file.
        dst_file (str): Path to the destination of the file.
        repl (pexpect.replwrap.REPLWrapper): Initialized class connected with the smbclient shell.
        eval_line_func(EvalLineCallable, optional): Callable used to execute the 'smbclient' command. Defaults to eval_line_in_repl.

    Returns:
        Tuple[bool, str|None]: True and no message on success, False and a message on failure.
    """
    cmds = {
        GET: "get",
        PUT: "put",
    }
    repl_cmd = f"{cmds[direction]} {src_file} {dst_file}"
    return eval_line_func(repl, repl_cmd)


@timeit
def get_file(
    src_file: str,
    dst_file: str,
    repl: pexpect.replwrap.REPLWrapper = None,
    file_put_get_func: FilePutGetCallable = file_put_get_impl,
) -> Tuple[bool, str]:
    """Write a given file from the local filesystem into a file on the share.

    Args:
        src_file (str): Path to the source of the file.
        dst_file (str): Path to the destination of the file.
        repl (pexpect.replwrap.REPLWrapper): Initialized class connected with the smbclient shell.
        file_put_get_func (FilePutGetCallable, optional): Callable implementing get and put support. Defaults to file_put_get_impl.

    Returns:
        Tuple[bool, str]: True and no message on success, False and message on failure.
    """
    return file_put_get_func(GET, src_file, dst_file, repl=repl)


@timeit
def put_file(
    src_file: str,
    dst_file: str,
    repl: pexpect.replwrap.REPLWrapper = None,
    file_put_get_func: FilePutGetCallable = file_put_get_impl,
) -> Tuple[bool, str | None]:
    """Write a given file from the local filesystem into a file on the share.

    Args:
        src_file (str): Path to the source of the file.
        dst_file (str): Path to the destination of the file.
        repl (pexpect.replwrap.REPLWrapper): Initialized class connected with the smbclient shell.
        file_put_get_func (FilePutGetCallable, optional): Callable implementing get and put support. Defaults to file_put_get_impl.

    Returns:
        Tuple[bool, str|None]: True and no message on success, False and a message on failure.
    """
    return file_put_get_func(PUT, src_file, dst_file, repl=repl)


def generate_random_name(n: int) -> str:
    """Generates a random string used as filename.

    Args:
        n (int): Length of the random string to generate.

    Returns:
        str: Random string of length n.
    """
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.sample(chars, n))


def probe(
    remote_base,
    si: ShareInfo,
    nrfiles=DEFAULT_NUM_FILES,
    size=4 * IOSIZE,
    read_back=True,  # Deprecated, no-longer used
    unlink=True,  # Deprecated, no-longer used
) -> Tuple[bool, Latencies, FailureCounts]:
    """Probes the SMB share by performing a number of basic file operations and collecting basic latency stats from these operations.

    Args:
        remote_base (str): Path to the directory (optionally root ".") on the SMB share.
        si (ShareInfo): Share description class.
        nrfiles (int, optional): Number of files to write, read and remove. Defaults to DEFAULT_NUM_FILES.
        size (int, optional): Size of the file(s) with which to operate. Defaults to 4*IOSIZE.
        read_back (bool, optional): Should the files be read back after having been written. Defaults to True.
        unlink (bool, optional): Should the files be removed after having been written. Defaults to True.

    Raises:
        AssertionError: Raised if local file is not written out properly.

    Returns:
        Tuple[bool, Latencies, FailureCounts]: First parameter includes overall success or failure of probe, second includes latencies of performed operations and third includes counts of failed operations.
    """
    remote_prefix = Path(remote_base) / generate_random_name(10)
    remote_path = Path(remote_prefix)  # This path is relative to the SMB share
    remote_dir = remote_path.parent
    succeeded = True
    read_latencies = []
    write_latencies = []
    unlink_latencies = []
    lsdir_latencies = []
    login_latencies = []
    fails = FailureCounts(0, 0, 0, 0, 0)

    with tempfile.TemporaryDirectory() as td:  # Will be deleted on close
        workdir = Path(td)
        # Create a temporary working file in the temporary working directory.
        local_file = workdir.joinpath("temp.data")
        # Setup mappings between local file and remote file.
        working_set = [
            (
                local_file,
                remote_prefix.with_suffix("." + str(n)),
            )
            for n in range(0, nrfiles)
        ]

        with RandomDataFile(size) as buffer:
            nwritten = local_file.write_bytes(buffer.read())
            if nwritten != size:
                raise AssertionError("Did not write all bytes")

            (replw, msg), delta = login_and_get_repl(si)
            if not replw:
                fails.login += 1
                LOGGER.critical(msg)
                succeeded = False
                return (
                    succeeded,
                    Latencies(
                        login_latencies,
                        read_latencies,
                        write_latencies,
                        unlink_latencies,
                        lsdir_latencies,
                    ),
                    fails,
                )
            login_latencies.append(delta)

        # Put files onto SMB share.
        for local, remote in working_set:
            (ok, msg), delta = put_file(local, remote, repl=replw)
            if not ok:
                fails.write += 1
                err_msg = f"failed to write //{si.addr}/{si.share}/{remote} after {delta} seconds: {msg}"
                LOGGER.error(err_msg)
                succeeded = False
            else:
                info_msg = f"wrote {size} bytes to //{si.addr}/{si.share}/{remote} in {delta} seconds"
                LOGGER.info(info_msg)
            write_latencies.append(delta)

        # List the contents of the directory after putting the files there.
        if remote_dir.as_posix() == ".":
            remote_path = f"//{si.addr}/{si.share}"
        else:
            remote_path = f"//{si.addr}/{si.share}/{remote_dir}"

        (ok, msg), delta = list_directory(SHARE_ROOT, repl=replw)
        if not ok:
            fails.ls_dir += 1
            err_msg = (
                f"failed to list contents of {remote_path} after {delta} seconds: {msg}"
            )
            LOGGER.error(err_msg)
            succeeded = False
        else:
            info_msg = f"listed contents {remote_path} in {delta} seconds"
            LOGGER.info(info_msg)
        lsdir_latencies.append(delta)

        for local, remote in working_set:
            (ok, msg), delta = get_file(remote, local, repl=replw)
            if not ok:
                fails.read += 1
                err_msg = f"failed to read //{si.addr}/{si.share}/{remote} after {delta} seconds: {msg}"
                LOGGER.error(err_msg)
                succeeded = False
            else:
                info_msg = f"read {size} bytes from //{si.addr}/{si.share}/{remote} in {delta} seconds"
                LOGGER.info(info_msg)
                os.unlink(local)
            read_latencies.append(delta)

        for local, remote in working_set:
            (ok, msg), delta = remove_file(remote, repl=replw)
            if not ok:
                fails.unlink += 1
                err_msg = f"failed to remove //{si.addr}/{si.share}/{remote} after {delta} seconds: {msg}"
                LOGGER.error(err_msg)
                succeeded = False
            else:
                info_msg = f"removed {size} byte file //{si.addr}/{si.share}/{remote} in {delta} seconds"
                LOGGER.info(info_msg)
            unlink_latencies.append(delta)

    close_connection(repl=replw)
    return (
        succeeded,
        Latencies(
            login_latencies,
            read_latencies,
            write_latencies,
            unlink_latencies,
            lsdir_latencies,
        ),
        fails,
    )


def run_probe_and_alert(
    si: ShareInfo,
    remote_file: str,
    login_thresh=2.0,
    read_thresh=1.0,
    write_thresh=1.0,
    ls_dir_thresh=1.0,
    unlink_thresh=1.0,
):
    """Runs the probe and generates an alert if the probe fails or latencies are above threshold values.

    Args:
        si (ShareInfo): Share description class.
        remote_file (str): Path to the file on the SMB share.
        read_thresh (float, optional): Latency threshold for read(s). Defaults to 1.0.
        write_thresh (float, optional): Latency threshold for write(s). Defaults to 1.0.
        ls_dir_thresh (float, optional): Latency threshold for lsdir(s). Defaults to 1.0.
        unlink_thresh (float, optional): Latency threshold for unlink. Defaults to 1.0.
    """
    ok, latencies, fails = probe(remote_file, si)
    healthy = ok

    for o in latencies.login_lat:
        SMB_OP_LATENCY.labels(si.addr, "login").observe(o)

    for o in latencies.read_lat:
        SMB_OP_LATENCY.labels(si.addr, "read").observe(o)

    for o in latencies.write_lat:
        SMB_OP_LATENCY.labels(si.addr, "write").observe(o)

    for o in latencies.lsdir_lat:
        SMB_OP_LATENCY.labels(si.addr, "ls_dir").observe(o)

    for o in latencies.unlink_lat:
        SMB_OP_LATENCY.labels(si.addr, "unlink").observe(o)

    if latencies.read_lat_above_threshold(read_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, "read").inc()
        LOGGER.error("median read latency is above threshold")

    if latencies.login_lat_above_threshold(login_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, "read").inc()
        LOGGER.error("median read latency is above threshold")

    if latencies.write_lat_above_threshold(write_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, "write").inc()
        LOGGER.error("median write latency is above threshold")

    if latencies.lsdir_lat_above_threshold(ls_dir_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, "ls_dir").inc()
        LOGGER.error("median list directory latency is above threshold")

    if latencies.unlink_lat_above_threshold(unlink_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, "unlink").inc()
        LOGGER.error("median unlink latency is above threshold")

    if not healthy:
        # Raise a notification
        SMB_STATUS.set(1)
    else:
        SMB_STATUS.set(0)

    # Check if any commands had failures and if so, increment the failure
    # counters.
    if fails.login > 0:
        SMB_OP_FAILED.labels(si.addr, "login").inc(1)  # Always one-count
    if fails.read > 0:
        SMB_OP_FAILED.labels(si.addr, "read").inc(fails.read)

    if fails.write > 0:
        SMB_OP_FAILED.labels(si.addr, "write").inc(fails.write)

    if fails.ls_dir > 0:
        SMB_OP_FAILED.labels(si.addr, "ls_dir").inc(fails.ls_dir)

    if fails.unlink > 0:
        SMB_OP_FAILED.labels(si.addr, "unlink").inc(fails.unlink)

    # write_to_textfile("raid.prom", #include registry parameter#)


def parse_config_file(config: str) -> Tuple[bool, List[str]]:
    """Parses configuration from file and produces a list of amounts to command line arguments.

    Args:
        config (str): Path to the configuration file.

    Returns:
        Tuple[bool, List[str]]: True if OK, False otherwise and argparse configuration parameters suitable for ingestion in parse_args.
    """
    conf_lines = []
    try:
        with open(config, "rb") as fp:
            for line in fp.readlines():
                if line.startswith(b"#"):  # Skip comment lines
                    continue
                tokens = line.decode("utf-8").strip().split()
                conf_lines += tokens
    except FileNotFoundError:
        return False, []
    return True, conf_lines


def display_parsed_config(conf_lines: List[str]):
    """Prints out the configuration with which we are running.

    Args:
        conf_lines (List[str]): Parsed command line args as a list of arguments and values.
    """
    i = 0
    while i < len(conf_lines):
        if conf_lines[i] == "--password":
            print(f"{conf_lines[i]:<20}\t=> ***SANITIZED***", file=sys.stderr)
            i += 2
        else:
            # We are either at the end, or next elem is actually an argument,
            # i.e. --foo as opposed to a paramater to this argument.
            if i + 1 == len(conf_lines) or conf_lines[i + 1][0:2] == "--":
                print(f"{conf_lines[i]:<20}", file=sys.stderr)
                i += 1
            else:
                print(f"{conf_lines[i]:<20}\t=> {conf_lines[i+1]}", file=sys.stderr)
                i += 2


def repeat_forever(*func_with_args, **kwargs):
    """Runs a callable which is in the 'func_with_args' forever in a loop."""
    interval = DEFAULT_LOOP_INTERVAL
    if "interval" in kwargs:
        interval = kwargs["interval"]
    func, *args = func_with_args
    while True:
        func(*args)
        time.sleep(interval)


if __name__ == "__main__":
    if "SMB_MONITOR_PROBE_CONFIGFILE" in os.environ:
        ok, from_config = parse_config_file(os.environ["SMB_MONITOR_PROBE_CONFIGFILE"])
        if ok:
            print("Running SMB probe with the following parameters:", file=sys.stderr)
            display_parsed_config(from_config)
            args = parser.parse_args(from_config)
            # print(args, file=sys.stderr)
        else:
            print(
                f"Could not read arguments from {os.environ['SMB_MONITOR_PROBE_CONFIGFILE']}",
                file=sys.stderr,
            )
            sys.exit(1)
    else:  # Configuration file environment variable is not set
        args = parser.parse_args()
    # print(args, file=sys.stderr)

    addresses: List[str] = args.addresses
    domain = args.domain
    share = args.share
    username = args.username
    password = args.password
    remote_basedir = args.remote_basedir
    interval = args.interval
    log_timestamp = args.log_timestamp

    # Thresholds from args
    login_threshold = args.login_threshold
    read_threshold = args.read_threshold
    write_threshold = args.write_threshold
    ls_dir_threshold = args.ls_dir_threshold
    unlink_threshold = args.unlink_threshold

    # Setup logging configuration
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

    # Get the password out of the environment instead of the `--password`
    # parameter to the program. This should be done typically in any production
    # setting so as to avoid having a password in cleartext in program
    # arguments which could be inspected with tools like `ps`.
    if not password:
        if not "SMB_MONITOR_PROBE_PASSWD" in os.environ:
            raise RuntimeError("No password for the probe service account")
        password = os.environ["SMB_MONITOR_PROBE_PASSWD"]

    si_list: List[ShareInfo] = []
    for addr in addresses:
        SMB_HIGH_OP_LATENCY.labels(addr, "login").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "read").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "write").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "ls_dir").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "unlink").inc(0)
        SMB_OP_FAILED.labels(addr, "login").inc(0)
        SMB_OP_FAILED.labels(addr, "read").inc(0)
        SMB_OP_FAILED.labels(addr, "write").inc(0)
        SMB_OP_FAILED.labels(addr, "ls_dir").inc(0)
        SMB_OP_FAILED.labels(addr, "unlink").inc(0)
        si_list.append(ShareInfo(addr, share, domain, username, password))

    # Start up the server to expose the metrics.
    start_http_server(8000)

    threads: List[Thread] = []
    for idx, si in enumerate(si_list):
        print(si)
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
                kwargs=dict(interval=interval),
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
