import unittest

from typing import List
from probe import GET, PUT, ShareInfo, file_put_get_impl
from unittest.mock import Mock, call


from dataclasses import dataclass

@dataclass
class EvaluatedCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    input_cmd: str = None

class T(unittest.TestCase):
    def test_file_put_get_impl_successful(self):
        m = Mock()
        m.stdout = b"mock standard out"
        m.stderr = b"mock standard error"
        m.return_value = EvaluatedCommandResult(
            returncode=0,
            stdout=b"",
            stderr=b"this is mock output sent to stderr",
        )

        addr = "1.2.3.4"
        share = "testshare"
        domain = "mock.local"
        user = "mockuser"
        passwd = "mockpass"

        file_from = "alpha"
        file_to = "beta"

        res1 = file_put_get_impl(
            GET,
            file_from,
            file_to,
            ShareInfo(
                addr="1.2.3.4",
                share="testshare",
                domain="mock.local",
                user=user,
                passwd=passwd,
            ),
            exec_func=m,
        )

        expected_args = [
            "smbclient",
            "-E",
            f"//{addr}/{share}",
            "-W",
            f"{domain}",
            "-U",
            f"{user}%{passwd}",
        ]
        m.assert_called_once_with(
            expected_args,
            input=bytes(f"get {file_from} {file_to}", encoding="utf8"),
            capture_output=True,
        )

        m.reset_mock()

        res2 = file_put_get_impl(
            PUT,
            file_from,
            file_to,
            ShareInfo(
                addr="1.2.3.4",
                share="testshare",
                domain="mock.local",
                user=user,
                passwd=passwd,
            ),
            exec_func=m,
        )
        m.assert_called_once_with(
            expected_args,
            input=bytes(f"put {file_from} {file_to}", encoding="utf8"),
            capture_output=True,
        )
