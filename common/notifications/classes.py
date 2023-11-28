import pickle

from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass(frozen=True)
class Data:
    target_address: str
    target_share: str
    target_domain: str

    latencies: Dict[str, List[float]]
    failed_ops: Dict[str, bool]

    @property
    def as_dict(self):
        return self.__dict__

    @property
    def latencies_as_str(self):
        tokens: List[str] = []
        for op, value in self.latencies.items():
            tokens.append(op + "=" + value.__str__())
        return " ".join(tokens)

    @property
    def failed_ops_as_str(self):
        tokens: List[str] = []
        for op, value in self.failed_ops.items():
            tokens.append(op + "=" + value.__str__())
        return " ".join(tokens)

    @property
    def id(self):
        # return self.target_domain + "-" \
        #     + self.target_address + "-" \
        #     + self.target_share
        return (self.target_address, self.target_domain, self.target_share)

    def encode(self):
        """Returns this object serialized with the pickle module.

        Returns:
            bytes: Serialized representation of self.
        """
        return pickle.dumps(self)


@dataclass(frozen=True)
class Notification:
    url: str = None
    integration_key: str = None
    headers: Dict[str, str] = None
    severity: str = None
    source_email: str = None
    summary: str = None
    description: str = None
    target: str = None


@dataclass(frozen=True)
class Result:
    """Result represents the outcome of an HTTP POST"""

    success: bool
    resp_code: int
    resp_body: str | None = None
    resp_dict: Dict[str, Any] | None = None
