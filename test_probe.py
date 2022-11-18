import unittest
from io import StringIO
from unittest.mock import Mock, patch
from dataclasses import dataclass
from probe import (
    GET,
    PUT,
    ShareInfo,
    display_parsed_config,
    eval_error,
    file_put_get_impl,
    list_directory,
    parse_config_file,
    remove_file,
)


@dataclass
class EvaluatedCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    input_cmd: str = None


@patch("sys.stderr", new_callable=StringIO)
def display_parsed_config_redirect_stderr(input, mock_stderr):
    display_parsed_config(input)
    return mock_stderr.getvalue()


class T(unittest.TestCase):
    def test_file_put_get_impl_is_successful(self):
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

        actual = file_put_get_impl(
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
        self.assertEqual((True, None), actual)

        m.reset_mock()

        actual = file_put_get_impl(
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
        self.assertEqual((True, None), actual)

    def test_list_directory_is_successful(self):
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

        remote_dir = "alpha"

        actual = list_directory(
            remote_dir,
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
            input=bytes(f"ls {remote_dir}", encoding="utf8"),
            capture_output=True,
        )
        self.assertEqual((True, None), actual)

    def test_remove_file_is_successful(self):
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

        remote_file = "alpha"

        actual = remove_file(
            remote_file,
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
            input=bytes(f"rm {remote_file}", encoding="utf8"),
            capture_output=True,
        )
        self.assertEqual((True, None), actual)

    def test_display_parsed_config(self):
        expected: str
        actual = display_parsed_config_redirect_stderr(
            ["--alpha", "a", "--beta", "b", "--gamma", "g", "--password", "secret"]
        )
        baseline = "testdata/baseline1"
        with open(baseline, "rt") as f:
            expected = f.read()
        self.assertEqual(expected, actual)

    def test_parse_config_file(self):
        expected = [
            "--alpha",
            "1",
            "--beta",
            "2",
            "--gamma",
            "3",
            "--delta",
            "4",
            "--epsilon",
        ]
        ok, actual = parse_config_file("testdata/test1.conf")
        self.assertTrue(ok)
        self.assertEqual(expected, actual)

    def test_eval_error(self):
        actual = eval_error(b"alpha beta gamma\nNT_STATUS_TEST_TEST")
        self.assertEqual((False, "NT_STATUS_TEST_TEST"), actual)
        actual = eval_error(b"alpha beta gamma\n")
        self.assertEqual((True, None), actual)
