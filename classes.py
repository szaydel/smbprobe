import io
import os

from dataclasses import dataclass
from threading import Lock
from typing import List

from constants import IOSIZE

@dataclass
class ShareInfo:
    addr: str
    share: str
    domain: str
    user: str
    passwd: str


@dataclass
class FailureCounts:
    login: int
    read: int
    write: int
    unlink: int
    ls_dir: int


@dataclass
class Latencies:
    login_lat: List[float]
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
    def login_lat_median(self):
        return self._median_lat(sorted(self.login_lat))

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

    def login_lat_above_threshold(self, threshold: float = 2.0) -> bool:
        return self.login_lat_median > threshold

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
                raise RandomDataFileError(err.args) from err
            self.rewind()
            self.initialized = True
