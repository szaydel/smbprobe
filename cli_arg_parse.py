import argparse

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
    "--remote-basedir",
    dest="remote_basedir",
    default=".",
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
    "--log-timestamp",
    action=argparse.BooleanOptionalAction,
    dest="log_timestamp",
    type=bool,
    default=True,
    required=False,
    help="Connection will be made to this share on the SMB server",
)

parser.add_argument(
    "--login-latency-threshold",
    dest="login_threshold",
    type=float,
    default=2.0,
    help="Threshold for acceptable login latency in seconds",
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
