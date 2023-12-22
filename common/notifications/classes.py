import pickle

from dataclasses import dataclass
from typing import Any, Dict, List

@dataclass(frozen=True)
class Data:
    target_address: str
    target_share: str
    target_domain: str

    latencies: Dict[str, List[float]]
    failed_ops: Dict[str, int]
    high_latency: bool = False
    correlation_id: str = None

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
        return (self.target_address, self.target_domain, self.target_share)
    
    @property
    def is_unhealthy(self):
        for _, failed in self.failed_ops.items():
            if failed:
                return True
        return self.high_latency
    
    def copy_with_correlation_id(self, correlation_id: str):
        latencies_copy: Dict[str, List[float]]
        for k, v in self.latencies.items():
            latencies_copy[k] = v.copy()

        failed_ops_copy: Dict[str, bool]
        for k, v in self.failed_ops.items():
            failed_ops_copy[k] = v

        return Data(
            target_address=self.target_address,
            target_domain=self.target_domain,
            target_share=self.target_share,
            latencies=latencies_copy,
            failed_ops=failed_ops_copy,
            high_latency=self.high_latency,
            correlation_id=correlation_id,
        )

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
