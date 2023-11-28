from prometheus_client import (
    Gauge,
    Counter,
    Histogram,
    # write_to_textfile,
)

SMB_STATUS = Gauge(
    "smb_service_state",
    "Current state of SMB service based on results of the probe",
    labelnames=["address", "share", "domain"],
)

SMB_OP_LATENCY = Histogram(
    "smb_operation_latency_seconds",
    "Time it takes to complete a given SMB operation, such as read, write, lsdir, unlink",
    labelnames=["address", "share", "domain", "operation"],
)

SMB_HIGH_OP_LATENCY = Counter(
    "smb_latency_above_threshold_total",
    "Count of times the probe detected high operation latency during a read, write, lsdir, unlink",
    labelnames=["address", "share", "domain", "operation"],
)

SMB_OP_FAILED = Counter(
    "smb_operation_failed_total",
    "Number of times a particular probe operation did not succeed",
    labelnames=["address", "share", "domain", "operation"],
)
