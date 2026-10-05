"""Exercise exit statuses and bounded I/O with inert in-memory streams."""

from io import BytesIO, StringIO
import json
import sys
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from acl_lab.__main__ import main
from acl_lab.core import MAX_INPUT_BYTES
from acl_lab.fixtures import request
def make_input(group=4):
    return json.dumps(request(group=group)).encode("utf-8")


class CliTests(TestCase):
    def invoke(self, raw=b"", command="analyze", output=None, input_stream=None, errors=None):
        output = BytesIO() if output is None else output
        errors = StringIO() if errors is None else errors
        with patch("sys.argv", ["acl_lab", command]), \
             patch("sys.stdin", SimpleNamespace(buffer=input_stream or BytesIO(raw))), \
             patch("sys.stdout", SimpleNamespace(buffer=output)), patch("sys.stderr", errors):
            code = main()
        return code, output, errors.getvalue()

    def test_exit_outcomes(self):
        for raw, expected in ((make_input(), 0), (make_input(0), 1),
                              (b"invalid", 2), (b"x" * (MAX_INPUT_BYTES + 1), 2)):
            with self.subTest(expected=expected):
                code, output, errors = self.invoke(raw)
                self.assertEqual(code, expected)
                self.assertIsInstance(json.loads(output.getvalue()), dict)
                self.assertFalse(errors)

    def test_demo(self):
        code, output, _ = self.invoke(command="demo")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())["passed"])

    def test_unsupported_and_failed_demo_exits(self):
        fixture = request()
        fixture["context"]["acl_kind"] = "unknown"
        code, output, _ = self.invoke(json.dumps(fixture).encode())
        self.assertEqual(code, 2)
        self.assertNotIn("model_permits", json.loads(output.getvalue()))
        with patch("acl_lab.__main__.evaluate", return_value={"inert": "wrong"}):
            code, output, _ = self.invoke(command="demo")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(output.getvalue())["passed"])

    def test_input_read_is_bounded(self):
        class Reader:
            def read(self, size):
                self.requested = size
                return b"x" * size
        stream = Reader()
        self.assertEqual(self.invoke(input_stream=stream)[0], 2)
        self.assertEqual(stream.requested, MAX_INPUT_BYTES + 1)

    def test_failed_read_write_flush_and_short_write(self):
        class FailedRead:
            def read(self, size):
                raise OSError("inert")
        class FailedWrite(BytesIO):
            def write(self, data):
                raise BrokenPipeError("inert")
        class FailedFlush(BytesIO):
            def flush(self):
                raise OSError("inert")
        class ShortWrite(BytesIO):
            def write(self, data):
                return 0
        self.assertEqual(self.invoke(input_stream=FailedRead())[0], 3)
        for output in (FailedWrite(), FailedFlush(), ShortWrite()):
            code, _, errors = self.invoke(make_input(), output=output)
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(errors), {"error": "input_or_output_failure"})

    def test_output_limit_is_incomplete_exit_even_in_demo(self):
        payload = b'{"status":"over_limit","complete":false}\n'
        with patch("acl_lab.__main__.serialize_report", return_value=payload):
            self.assertEqual(self.invoke(make_input())[0], 2)
            self.assertEqual(self.invoke(command="demo")[0], 2)

    def test_failed_error_delivery(self):
        class FailedRead:
            def read(self, size):
                raise OSError("inert")
        class FailedErrors(StringIO):
            def write(self, text):
                raise OSError("inert")
        self.assertEqual(self.invoke(input_stream=FailedRead(), errors=FailedErrors())[0], 3)

    def test_short_and_failed_flush_diagnostics_detach_sinks(self):
        class FailedRead:
            def read(self, size):
                raise OSError("inert")
        class ShortErrors(StringIO):
            def write(self, text):
                return 0
        class FailedFlush(StringIO):
            def flush(self):
                raise OSError("inert")
        for errors in (ShortErrors(), FailedFlush()):
            self.assertEqual(self.invoke(input_stream=FailedRead(), errors=errors)[0], 3)

    def test_help_short_write_and_failed_flush(self):
        class ShortHelp(StringIO):
            def write(self, text):
                return 0
        class FailedFlush(StringIO):
            def flush(self):
                raise OSError("inert")
        for sink in (ShortHelp(), FailedFlush()):
            errors = StringIO()
            with patch("sys.argv", ["acl_lab", "--help"]), patch("sys.stdout", sink), patch("sys.stderr", errors):
                self.assertEqual(main(), 3)
                self.assertIsNone(sys.stdout)
                self.assertIsNone(sys.stderr)
            self.assertEqual(json.loads(errors.getvalue()), {"error": "input_or_output_failure"})
