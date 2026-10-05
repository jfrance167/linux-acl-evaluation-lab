"""Bounded stdin JSON and hand-fixed demos; no real ACL operations."""

import argparse
import json
import sys

from .core import MAX_INPUT_BYTES, analyze_json, evaluate, serialize_report
from .fixtures import oracles


class _CheckedParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        # argparse's default implementation swallows write failures, which can
        # leave buffered help/diagnostics to fail again at interpreter shutdown.
        if message:
            destination = sys.stderr if file is None else file
            if destination.write(message) != len(message):
                raise OSError("short parser output write")
            destination.flush()


def _io_failure() -> int:
    diagnostic = sys.stderr
    # Detach both public sinks before diagnostic delivery. Even a write that
    # appears to succeed may fail on flush; a dirty sink must not replace exit3
    # with CPython's shutdown-flush exit120.
    sys.stdout = sys.stderr = None
    message = '{"error":"input_or_output_failure"}\n'
    try:
        if diagnostic.write(message) != len(message):
            raise OSError("short diagnostic write")
        diagnostic.flush()
    except OSError:
        pass
    return 3


def main() -> int:
    parser = _CheckedParser(description="Invented access ACL model; actual host access unverified")
    parser.add_argument("command", choices=("analyze", "demo"))
    try:
        args = parser.parse_args()
        if args.command == "analyze":
            report = analyze_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        else:
            results = []
            for name, request, expected in oracles():
                actual = evaluate(request)
                results.append({"id": name, "report": actual, "expected": expected, "passed": actual == expected})
            report = {"mode": "invented_access_acl", "actual_access": "unverified", "actual_acl": "unverified",
                      "cases": results, "passed": all(item["passed"] for item in results)}
        payload = serialize_report(report)
        emitted = json.loads(payload)
        if sys.stdout.buffer.write(payload) != len(payload):
            raise OSError("short output write")
        sys.stdout.buffer.flush()
    except OSError:
        return _io_failure()
    if emitted.get("status") == "over_limit":
        return 2
    if args.command == "demo":
        return 0 if report["passed"] else 1
    if not report["complete"]:
        return 2
    return 0 if report["model_permits"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
