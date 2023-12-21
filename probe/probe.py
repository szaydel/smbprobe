import random
import os
import tempfile
import time

from pathlib import Path
import redis
import redis.exceptions
from typing import Callable, Tuple

import pexpect
import pexpect.replwrap

from common.classes import ShareInfo, FailureCounts, Latencies, RandomDataFile

from common.constants import (
    DEFAULT_LOOP_INTERVAL,
    DEFAULT_NUM_FILES,
    DEFAULT_NOTIFICATIONS_LIST_NAME,
    IOSIZE,
)

from common.notifications.classes import Data

from log import LOGGER

from metrics import SMB_HIGH_OP_LATENCY, SMB_OP_FAILED, SMB_OP_LATENCY, SMB_STATUS

EvalLineCallable = Callable[[pexpect.replwrap.REPLWrapper, str], Tuple[bool, str]]

FilePutGetCallable = Callable[
    [object, str, str, pexpect.replwrap.REPLWrapper, EvalLineCallable],
    Tuple[bool, str],
]

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
        return None, f"login failed: {err_msg}"


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
    return True, None


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


def generate_random_name(length: int) -> str:
    """Generates a random string used as filename.

    Args:
        length (int): Length of the random string to generate.

    Returns:
        str: Random string of length n.
    """
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.sample(chars, length))


def probe(
    remote_base,
    si: ShareInfo,
    nrfiles=DEFAULT_NUM_FILES,
    size=4 * IOSIZE,
    read_back=True,  # Deprecated, no-longer used #pylint: disable=unused-argument
    unlink=True,  # Deprecated, no-longer used #pylint: disable=unused-argument
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

    with tempfile.TemporaryDirectory() as tempdir:  # Will be deleted on close
        workdir = Path(tempdir)
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
                LOGGER.critical(
                    msg, extra=dict(address=si.addr, domain=si.domain, share=si.share)
                )
                succeeded = False
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
    **kwargs,
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
    conf = kwargs.get("conf")
    if conf:
        notifications = conf.get("notifications")
        notifications_enabled = 0 if not notifications else len(notifications) > 0
    else:
        notifications_enabled = False

    ok, latencies, fails = probe(remote_file, si)
    healthy = ok
    high_latency = False

    for sample in latencies.login_lat:
        SMB_OP_LATENCY.labels(si.addr, si.share, si.domain, "login").observe(sample)

    for sample in latencies.read_lat:
        SMB_OP_LATENCY.labels(si.addr, si.share, si.domain, "read").observe(sample)

    for sample in latencies.write_lat:
        SMB_OP_LATENCY.labels(si.addr, si.share, si.domain, "write").observe(sample)

    for sample in latencies.lsdir_lat:
        SMB_OP_LATENCY.labels(si.addr, si.share, si.domain, "ls_dir").observe(sample)

    for sample in latencies.unlink_lat:
        SMB_OP_LATENCY.labels(si.addr, si.share, si.domain, "unlink").observe(sample)

    if latencies.login_lat_above_threshold(login_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "login").inc()
        LOGGER.error(
            "login latency in one or more samples is above threshold; latencies: '{0}'".format(
                latencies.login_lat
            )
        )

    if latencies.read_lat_above_threshold(read_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "read").inc()
        LOGGER.error(
            "median read latency: '{0}' is above threshold".format(
                latencies.read_lat_median
            )
        )

    if latencies.write_lat_above_threshold(write_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "write").inc()
        LOGGER.error(
            "median write latency: '{0}' is above threshold".format(
                latencies.write_lat_median
            )
        )

    if latencies.lsdir_lat_above_threshold(ls_dir_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "ls_dir").inc()
        LOGGER.error(
            "median list directory latency: '{0}' is above threshold".format(
                latencies.lsdir_lat_median
            )
        )

    if latencies.unlink_lat_above_threshold(unlink_thresh):
        healthy = False
        # Raise a notification
        SMB_HIGH_OP_LATENCY.labels(si.addr, si.share, si.domain, "unlink").inc()
        LOGGER.error(
            "median unlink latency: '{0}' is above threshold".format(
                latencies.unlink_lat_median
            )
        )

    high_latency = not healthy

    # Check if any commands had failures and if so, increment the failure
    # counters.
    if fails.login > 0:
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "login").inc(
            1
        )  # Always one-count
    if fails.read > 0:
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "read").inc(fails.read)

    if fails.write > 0:
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "write").inc(fails.write)

    if fails.ls_dir > 0:
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "ls_dir").inc(fails.ls_dir)

    if fails.unlink > 0:
        SMB_OP_FAILED.labels(si.addr, si.share, si.domain, "unlink").inc(fails.unlink)

    if not healthy:
        LOGGER.error(
            "share is unhealthy",
            extra={"addr": si.addr, "domain": si.domain, "share": si.share},
        )
        # Raise a notification
        SMB_STATUS.labels(si.addr, si.share, si.domain).set(1)
    else:
        SMB_STATUS.labels(si.addr, si.share, si.domain).set(0)

    # If notifications are configured, we assume them to be enabled. We will
    # post notification whether or not there is an issue with the probe.
    if notifications_enabled:
        data = Data(
            target_address=si.addr,
            target_share=si.share,
            target_domain=si.domain,
            latencies=latencies.as_dict(),
            failed_ops=fails.as_dict(),
            high_latency=high_latency,
        )

        r = redis.Redis(host="redis", port=6379, decode_responses=False)

        # FIXME: This is likely to raise some exceptions, but we aren't
        # handling any exceptions here at this point.
        try:
            _ = r.lpush(DEFAULT_NOTIFICATIONS_LIST_NAME, data.encode())
        except redis.exceptions.ConnectionError as err:
            LOGGER.critical(err)
    # write_to_textfile("raid.prom", #include registry parameter#)


def repeat_forever(*func_with_args, **kwargs):
    """Runs  the 'func_with_args' callable in a forever loop."""
    interval = kwargs.get("interval", DEFAULT_LOOP_INTERVAL)
    func, *args = func_with_args
    while True:
        func(*args, **kwargs)
        time.sleep(interval)
