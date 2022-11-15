#!/usr/bin/env python3
import argparse
import io
import logging
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple
from threading import Lock, Thread

from prometheus_client import (
    Gauge,
    start_http_server,
    Counter,
    Histogram,
    # write_to_textfile,
)

SMB_STATUS = Gauge(
    "smb_service_state", "Current state of SMB service based on results of the probe"
)

SMB_OP_LATENCY = Histogram(
    "smb_operation_latency",
    "Time it takes to complete a particular SMB operation",
    labelnames=["address", "operation"],
)

SMB_HIGH_OP_LATENCY = Counter(
    "smb_latency_above_threshold_total",
    "Count of times the probe detected high operation latency",
    labelnames=["address", "operation"],
)

SMB_OP_FAILED = Counter(
    "smb_operation_failed_total",
    "Number of times a particular probe operation did not succeed",
    labelnames=["address", "operation"],
)

DEFAULT_LOG_LEVEL = logging.DEBUG  # Change level to adjust output verbosity

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=DEFAULT_LOG_LEVEL,
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)

LOGGER = logging.getLogger("smb-probe")

PUT = object()
GET = object()
SHARE_ROOT = object()

IOSIZE = 1 << 10

DEFAULT_LOOP_INTERVAL = 5.0  # seconds

DEFAULT_NUM_FILES = 5


@dataclass
class ShareInfo:
    addr: str
    share: str
    domain: str
    user: str
    passwd: str


@dataclass
class FailureCounts:
    read: int
    write: int
    unlink: int
    ls_dir: int


@dataclass
class Latencies:
    read_lat: List[float]
    write_lat: List[float]
    unlink_lat: List[float]
    lsdir_lat: List[float]

    def _median_lat(self, l):
        # Even length of list case
        if len(l) % 2 == 0:
            two = l[len(l) // 2 - 1 : len(l) // 2 + 1]
            return sum(two) / 2
        # Odd length of list case
        return l[len(l) // 2]

    @property
    def read_lat_median(self):
        return self._median_lat(sorted(self.read_lat))

    @property
    def write_lat_median(self):
        return self._median_lat(sorted(self.write_lat))

    @property
    def unlink_lat_median(self):
        return self._median_lat(sorted(self.unlink_lat))

    @property
    def lsdir_lat_median(self):
        return self._median_lat(sorted(self.lsdir_lat))

    def read_lat_above_threshold(self, threshold: float) -> bool:
        return self.read_lat_median > threshold

    def write_lat_above_threshold(self, threshold: float) -> bool:
        return self.write_lat_median > threshold

    def unlink_lat_above_threshold(self, threshold: float) -> bool:
        return self.unlink_lat_median > threshold

    def lsdir_lat_above_threshold(self, threshold: float) -> bool:
        return self.lsdir_lat_median > threshold


class RandomDataFileError(Exception):
    pass


class RandomDataFile:
    def __init__(self, size=10 * IOSIZE):
        self._size = size
        self._buffer = io.BytesIO()
        self._lock = Lock()
        self.initialized = False
        self._init_random()

    def __enter__(self):
        if not self.initialized:
            raise RandomDataFileError("random bytes buffer uninitialized")
        return self.buffer

    def __exit__(self, exc_type, exc_value, exc_traceback):
        with self._lock:
            self._buffer.close()
            self._buffer = None
            self.initialized = False

    @property
    def buffer(self):
        return self._buffer

    @property
    def current_pos(self):
        return self._buffer.seek(0, os.SEEK_CUR)

    @property
    def size(self):
        return self._size

    def rewind(self) -> int:
        return self._buffer.seek(0)

    def _init_random(self):
        with self._lock:
            if self.initialized:
                return
            iosize = IOSIZE if self.size > IOSIZE else self.size
            rbytes = 0
            try:
                with open("/dev/urandom", "rb") as f:
                    while rbytes < self.size:
                        data = f.read(iosize)
                        self._buffer.write(data)
                        rbytes += len(data)
            except IOError as err:
                raise RandomDataFile(err.args)
            self.rewind()
            self.initialized = True


def eval_error(output: bytes) -> Tuple[bool, str]:
    """Evaluates output produced by the smbclient command and determines if the command failed.

    Args:
        output (bytes): Bytes from the smbclient command output.

    Returns:
        Tuple[bool, str]: True and no message on success, False and message on failure.
    """
    if not output:
        return False, "expected at least one line in output"
    lines = output.split(b"\n")[1:]
    lines = [i for i in lines if i != b""]
    # Check if an error message is present in the output.
    if not lines:
        return True, None
    for line in lines:
        if line.startswith(b"NT_STATUS"):  # This is an error message
            return False, str(lines[0], "utf-8")
    return True, None


def list_directory(
    remote_dir: str, si: ShareInfo, exec_func=subprocess.run
) -> Tuple[bool, str]:
    """Lists contents of the directory on the SMB share.

    Args:
        remote_dir (str): Path to the directory on the SMB share.
        si (ShareInfo): Share description class.
        exec_func(Callable, optional): Callable used to execute the 'smbclient' command. Defaults to subprocess.run.

    Returns:
        Tuple[bool, str]: True and no message on success, False and message on failure.
    """
    addr = si.addr
    share = si.share
    domain = si.domain
    user = si.user
    passwd = si.passwd
    if remote_dir == SHARE_ROOT:
        arg = "ls"
    else:
        arg = f"ls {remote_dir}"
    result = exec_func(
        f"smbclient -E //{addr}/{share} -W {domain} -U {user}%{passwd}".split(),
        input=bytes(arg, "utf-8"),
        capture_output=True,
    )
    if result.returncode != 0:
        return (
            False,
            f"failed to exec smbclient: {result.stderr.decode('utf-8').strip()}",
        )
    ok, msg = eval_error(result.stderr)
    if not ok:
        return False, f"list_directory: {msg}"
    return True, None


def remove_file(
    remote_file: str, si: ShareInfo, exec_func=subprocess.run
) -> Tuple[bool, str]:
    """Removes file on the SMB share.

    Args:
        remote_file (str): Path to the file on the SMB share.
        si (ShareInfo): Share description class.
        exec_func(Callable, optional): Callable used to execute the 'smbclient' command. Defaults to subprocess.run.

    Returns:
        Tuple[bool, str]: True and no message on success, False and message on failure.
    """
    addr = si.addr
    share = si.share
    domain = si.domain
    user = si.user
    passwd = si.passwd
    arg = f"rm {remote_file}"
    result = exec_func(
        f"smbclient -E //{addr}/{share} -W {domain} -U {user}%{passwd}".split(),
        input=bytes(arg, "utf-8"),
        capture_output=True,
    )
    if result.returncode != 0:
        return (
            False,
            f"failed to exec smbclient: {result.stderr.decode('utf-8').strip()}",
        )
    ok, msg = eval_error(result.stderr)
    if not ok:
        return False, f"remove_file: {msg}"
    return True, None


def file_put_get_impl(
    direction: object, src_file, dst_file, si: ShareInfo, exec_func=subprocess.run
) -> Tuple[bool, str]:
    """Implements the steps to place the file on the SMB share or retrieve the
    file from the SMB share.

    Args:
        direction (object): Whether this is a read or a write.
        src_file (str): Path to the source of the file.
        dst_file (str): Path to the destination of the file.
        si (ShareInfo): Share description class.
        exec_func(Callable, optional): Callable used to execute the 'smbclient' command. Defaults to subprocess.run.

    Returns:
        Tuple[bool, str]: True and no message on success, False and message on failure.
    """
    addr = si.addr
    share = si.share
    domain = si.domain
    user = si.user
    passwd = si.passwd
    cmds = {
        GET: "get",
        PUT: "put",
    }
    arg = f"{cmds[direction]} {src_file} {dst_file}"
    result = exec_func(
        f"smbclient -E //{addr}/{share} -W {domain} -U {user}%{passwd}".split(),
        input=bytes(arg, "utf-8"),
        capture_output=True,
    )
    if result.returncode != 0:
        return False, result.stderr.decode("utf8").strip()
    ok, msg = eval_error(result.stderr)
    if not ok:
        return False, f"file_put_get_impl: {msg}"
    return True, None


def get_file(src_file, dst_file, si: ShareInfo) -> bool:
    """Read a given file from the share into a file on the local filesystem.

    Args:
        src_file (str): Path to the source of the file.
        dst_file (str): Path to the destination of the file.
        si (ShareInfo): Share description class.

    Returns:
        bool: True if getting the file from the share succeeded, False otherwise.
    """
    return file_put_get_impl(GET, src_file, dst_file, si)


def put_file(src_file, dst_file, si: ShareInfo) -> bool:
    """Write a given file from the local filesystem into a file on the share.

    Args:
        src_file (str): Path to the source of the file.
        dst_file (str): Path to the destination of the file.
        si (ShareInfo): Share description class.

    Returns:
        bool: True if putting the file onto the share succeeded, False otherwise.
    """
    return file_put_get_impl(PUT, src_file, dst_file, si)


def probe(
    remote_file,
    si: ShareInfo,
    nfiles=DEFAULT_NUM_FILES,
    size=4 * IOSIZE,
    read_back=True,
    unlink=True,
) -> Tuple[bool, Latencies, FailureCounts]:
    """Probes the SMB share by performing a number of basic file operations and collecting basic latency stats from these operations.

    Args:
        remote_file (str): Path to file on the SMB share.
        si (ShareInfo): Share description class.
        nfiles (int, optional): Number of files to write, read and remove. Defaults to DEFAULT_NUM_FILES.
        size (int, optional): Size of the file(s) with which to operate. Defaults to 4*IOSIZE.
        read_back (bool, optional): Should the files be read back after having been written. Defaults to True.
        unlink (bool, optional): Should the files be removed after having been written. Defaults to True.

    Raises:
        AssertionError: Raised if local file is not written out properly.

    Returns:
        Tuple[bool, Latencies, FailureCounts]: First parameter includes overall success or failure of probe, second includes latencies of performed operations and third includes counts of failed operations.
    """
    remote_path = Path(remote_file)
    remote_dir = remote_path.parent
    succeeded = True
    read_latencies = []
    write_latencies = []
    unlink_latencies = []
    lsdir_latencies = []
    fails = FailureCounts(0, 0, 0, 0)

    with tempfile.NamedTemporaryFile() as local_file:  # Will be deleted on close
        with RandomDataFile(size=size) as buffer:
            nwritten = local_file.write(buffer.read())
            if nwritten != size:
                raise AssertionError("Did not write all bytes")
            local_file.flush()  # flush the stream to make sure file had content
            # PUT FILES onto SMB share
            for i in range(nfiles):
                start = time.time()
                ok, msg = put_file(local_file.name, remote_file + f".{i}", si)
                delta = time.time() - start
                if not ok:
                    fails.write += 1
                    LOGGER.error(
                        f"failed to write //{si.addr}/{si.share}/{remote_file}.{i} after {delta} seconds: {msg}"
                    )
                    succeeded = False
                else:
                    LOGGER.info(
                        f"wrote {size} bytes to //{si.addr}/{si.share}/{remote_file}.{i} in {delta} seconds"
                    )
                write_latencies.append(delta)
    # List the contents of the directory after putting the files there.
    if remote_dir == ".":
        start = time.time()
        ok, msg = list_directory(SHARE_ROOT, si)
        delta = time.time() - start
        if not ok:
            fails.ls_dir += 1
            LOGGER.error(
                f"failed to list contents of //{si.addr}/{si.share} after {delta} seconds: {msg}"
            )
            succeeded = False
        else:
            LOGGER.info(
                f"listed contents //{si.addr}/{si.share} in {delta} seconds: {msg}"
            )
    else:
        start = time.time()
        ok, msg = list_directory(remote_dir, si)
        delta = time.time() - start
        if not ok:
            fails.ls_dir += 1
            LOGGER.error(
                f"failed to list contents of the remote directory //{si.addr}/{si.share}/{remote_dir} after {delta} seconds: {msg}"
            )
            succeeded = False
        else:
            LOGGER.info(
                f"listed contents of the remote directory //{si.addr}/{si.share}/{remote_dir} in {delta} seconds"
            )
    lsdir_latencies.append(delta)
    if read_back:
        for i in range(nfiles):
            start = time.time()
            ok, msg = get_file(remote_file + f".{i}", f"testfile.{i}", si)
            delta = time.time() - start
            if not ok:
                fails.read += 1
                LOGGER.error(
                    f"failed to read //{si.addr}/{si.share}/{remote_file}.{i} after {delta} seconds: {msg}"
                )
                succeeded = False
            else:
                LOGGER.info(
                    f"read {size} bytes from {remote_file}.{i} in {delta} seconds"
                )
                os.unlink(f"testfile.{i}")
            read_latencies.append(delta)
    if unlink:
        for i in range(nfiles):
            start = time.time()
            ok, msg = remove_file(remote_file + f".{i}", si)
            delta = time.time() - start
            if not ok:
                fails.unlink += 1
                LOGGER.error(
                    f"failed to remove //{si.addr}/{si.share}/{remote_file}.{i} after {delta} seconds: {msg}"
                )
                succeeded = False
            else:
                LOGGER.info(
                    f"removed {size} byte file //{si.addr}/{si.share}/{remote_file}.{i} in {delta} seconds"
                )
            unlink_latencies.append(delta)

    return (
        succeeded,
        Latencies(read_latencies, write_latencies, unlink_latencies, lsdir_latencies),
        fails,
    )


parser = argparse.ArgumentParser(
    description="A monitoring probe used to validate normal function of SMB server"
)
parser.add_argument(
    "--address",
    action="append",
    dest="addresses",
    required=True,
    help="One or more address(es)/host/DNS names of the SMB server",
)
parser.add_argument(
    "--share",
    dest="share",
    required=True,
    help="Connection will be made to this share on the SMB server",
)
parser.add_argument(
    "--domain",
    dest="domain",
    required=True,
    help="The name of the domain within which this SMB server resides",
)
parser.add_argument(
    "--username",
    dest="username",
    required=True,
    help="Name of service account with which to connect and perform routine tests",
)
parser.add_argument(
    "--password",
    dest="password",
    help="Password of service account with which to connect and perform routine tests (should probably come from the environment)",
)
parser.add_argument(
    "--remote-file-prefix",
    dest="remote_file",
    default="testfile",
    # required=True,
    help="Path on the remote, inclusing partial file name used to construct multiple files during the routine test",
)
parser.add_argument(
    "--interval",
    dest="interval",
    type=int,
    default=300,
    help="Probe execution interval in seconds",
)

parser.add_argument(
    "--read-latency-threshold",
    dest="read_threshold",
    type=float,
    default=1.0,
    help="Threshold for acceptable read latency in seconds",
)

parser.add_argument(
    "--write-latency-threshold",
    dest="write_threshold",
    type=float,
    default=1.0,
    help="Threshold for acceptable write latency in seconds",
)

parser.add_argument(
    "--ls_dir-latency-threshold",
    dest="ls_dir_threshold",
    type=float,
    default=1.0,
    help="Threshold for acceptable directory listing latency in seconds",
)

parser.add_argument(
    "--unlink-latency-threshold",
    dest="unlink_threshold",
    type=float,
    default=1.0,
    help="Threshold for acceptable unlink latency in seconds",
)


def run_probe_and_alert(
    si: ShareInfo,
    remote_file: str,
    read_thresh=1.0,
    write_thresh=1.0,
    ls_dir_thresh=1.0,
    unlink_thresh=1.0,
):
    """Runs the probe and generates an alert if the probe fails or latencies are above threshold values.

    Args:
        si (ShareInfo): Share description class.
        remote_file (str): Path to the file on the SMB share.
    """
    ok, latencies, fails = probe(remote_file, si)
    healthy = ok

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
    remote_file = args.remote_file
    interval = args.interval

    # Thresholds from args
    read_threshold = args.read_threshold
    write_threshold = args.write_threshold
    ls_dir_threshold = args.ls_dir_threshold
    unlink_threshold = args.unlink_threshold

    # Get the password out of the environment instead of the `--password`
    # parameter to the program. This should be done typically in any production
    # setting so as to avoid having a password in cleartext in program
    # arguments which could be inspected with tools like `ps`.
    if not password:
        if not "SMB_MONITOR_PROBE_PASSWD" in os.environ:
            raise RuntimeError("No password for the probe service account")
        password = os.environ["SMB_MONITOR_PROBE_PASSWD"]

    si_list: List[ShareInfo] = list()
    for addr in addresses:
        SMB_HIGH_OP_LATENCY.labels(addr, "read").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "write").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "ls_dir").inc(0)
        SMB_HIGH_OP_LATENCY.labels(addr, "unlink").inc(0)
        SMB_OP_FAILED.labels(addr, "read").inc(0)
        SMB_OP_FAILED.labels(addr, "write").inc(0)
        SMB_OP_FAILED.labels(addr, "ls_dir").inc(0)
        SMB_OP_FAILED.labels(addr, "unlink").inc(0)
        si_list.append(ShareInfo(addr, share, domain, username, password))

    # Start up the server to expose the metrics.
    start_http_server(8000)

    threads: List[Thread] = list()
    for si in si_list:
        print(si)
        threads.append(
            Thread(
                target=repeat_forever,
                args=(
                    run_probe_and_alert,
                    si,
                    remote_file,
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
