import os
import sys
import unittest

from io import StringIO
from unittest.mock import Mock, patch, call
from dataclasses import dataclass

import pexpect.replwrap

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from common.configuration import display_parsed_config  # noqa: E402

from .probe import (  # noqa: E402
    GET,
    PUT,
    file_put_get_impl,
    get_file,
    put_file,
    list_directory,
    remove_file,
    timeit,
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
    def test_timeit_decorator(self):
        @timeit
        def test_nop_function():
            return None

        _, delta = test_nop_function()
        self.assertTrue(delta > 0 and delta < 0.1)

    def test_list_remove_repl_cmds_evaluate_correctly(self):
        def mock_eval_line_func(repl, cmd_line):
            repl.run_command(cmd_line)
            return True, None

        def mock_exec_func(repl, repl_cmd, eval_line_func=mock_eval_line_func):
            return eval_line_func(repl, repl_cmd)

        remote_file_or_dir = "alpha"
        mock_repl = Mock(spec=pexpect.replwrap.REPLWrapper)

        commands = {
            "ls": list_directory,
            "rm": remove_file,
        }

        for cmd, cmd_func in commands.items():
            mock_repl.reset_mock()
            mock_repl.run_command.return_value = "this is ok"
            _, delta = cmd_func(
                remote_file_or_dir,
                repl=mock_repl,
                eval_line_func=mock_exec_func,
            )

        self.assertLess(delta, 1)  # This should be nearly instant
        self.assertTrue(mock_repl.run_command.called)
        self.assertTrue(
            mock_repl.run_command.call_args == call(f"{cmd} {remote_file_or_dir}")
        )

    def test_file_put_get_impl(self):
        cmds = {
            GET: "get",
            PUT: "put",
        }

        local_file = remote_file = "alpha"
        mock_repl = Mock(spec=pexpect.replwrap.REPLWrapper)
        mock_repl.run_command.return_value = "this is ok"

        for direction, cmd in cmds.items():
            resp = file_put_get_impl(direction, local_file, remote_file, repl=mock_repl)
            self.assertEqual(resp, (True, None))
            self.assertTrue(mock_repl.run_command.called)
            self.assertTrue(
                mock_repl.run_command.call_args
                == call(f"{cmd} {local_file} {remote_file}")
            )

    def test_file_put_get_impl_gets_an_error(self):
        cmds = {
            GET: "get",
            PUT: "put",
        }

        local_file = remote_file = "alpha"
        mock_repl = Mock(spec=pexpect.replwrap.REPLWrapper)
        mock_repl.run_command.return_value = (
            "XX NT_STATUS_CONNECTION_DISCONNECTED this is a mock failure XX"
        )

        for direction, cmd in cmds.items():
            resp = file_put_get_impl(direction, local_file, remote_file, repl=mock_repl)
            self.assertEqual(
                resp,
                (
                    False,
                    f"smbclient failed evaluating: '{cmd} {local_file} {remote_file}';  error: NT_STATUS_CONNECTION_DISCONNECTED this is a mock failure",
                ),
            )
            self.assertTrue(mock_repl.run_command.called)
            self.assertTrue(
                mock_repl.run_command.call_args
                == call(f"{cmd} {local_file} {remote_file}")
            )

    def test_put_get_repl_cmds_evaluate_correctly(self):
        def mock_eval_line_func(repl, cmd_line):
            repl.run_command(cmd_line)
            return True, None

        def mock_exec_func(
            direction, src_file, dst_file, repl, eval_line_func=mock_eval_line_func
        ):
            cmds = {
                PUT: "put",
                GET: "get",
            }
            repl_cmd = f"{cmds[direction]} {src_file} {dst_file}"
            return eval_line_func(repl, repl_cmd)

        local_file = remote_file = "alpha"
        mock_repl = Mock(spec=pexpect.replwrap.REPLWrapper)

        commands = {
            "get": get_file,
            "put": put_file,
        }

        for cmd, cmd_func in commands.items():
            mock_repl.reset_mock()
            mock_repl.run_command.return_value = "this is ok"
            _, delta = cmd_func(
                local_file,
                remote_file,
                repl=mock_repl,
                file_put_get_func=mock_exec_func,
            )

        self.assertLess(delta, 1)  # This should be nearly instant
        self.assertTrue(mock_repl.run_command.called)
        self.assertTrue(
            mock_repl.run_command.call_args == call(f"{cmd} {local_file} {remote_file}")
        )

    def test_remove_file_is_successful(self):
        def mock_exec_func(repl, repl_cmd):
            repl.run_command(repl_cmd)
            return True, None

        remote_file = "alpha"
        mock_repl = Mock(spec=pexpect.replwrap.REPLWrapper)

        _, delta = remove_file(
            remote_file,
            repl=mock_repl,
            eval_line_func=mock_exec_func,
        )

        self.assertLess(delta, 1)  # This should be nearly instant
        self.assertTrue(mock_repl.run_command.called)
        self.assertTrue(mock_repl.run_command.call_args == call(f"rm {remote_file}"))
