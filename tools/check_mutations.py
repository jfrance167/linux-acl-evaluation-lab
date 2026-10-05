"""Require assertion failures for three injected faults, then restored passes.

Usage: python tools/check_mutations.py
No source edits/external commands/network. A test error does not count as a caught
mutation. JSON evidence reports assertions/errors separately. Not a coverage score.
"""

from io import StringIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from acl_lab import core
from test_core import CoreTests


def run_case(name: str) -> dict:
    result = unittest.TextTestRunner(stream=StringIO()).run(unittest.TestSuite([CoreTests(name)]))
    return {"passed": result.wasSuccessful(), "assertion_failures": len(result.failures),
            "errors": len(result.errors), "tests_run": result.testsRun}


def union_fault(checks, bits, other):
    pooled = 0
    for check in checks:
        pooled |= check["effective_bits"]
    return pooled & bits == bits


def fallback_fault(checks, bits, other):
    return any(check["covers_request"] for check in checks) or other & bits == bits


def main() -> int:
    mutations = []
    pairs = (("group_union", "_group_permits", union_fault, "test_split_regression"),
             ("ignored_mask", "_effective", lambda raw, mask: raw, "test_mask_regression"),
             ("other_fallback", "_group_permits", fallback_fault, "test_no_fallback_regression"))
    for name, target, fault, test in pairs:
        with patch.object(core, target, fault):
            result = run_case(test)
        mutations.append({"mutation": name, **result,
                          "detected": result["assertion_failures"] > 0 and result["errors"] == 0})
    restored = [run_case(test) for _, _, _, test in pairs]
    print(json.dumps({"mutations": mutations, "restored": restored,
                      "scope": "three in-memory logic faults; no source mutation"}, indent=2))
    return 0 if all(item["detected"] for item in mutations) and all(item["passed"] for item in restored) else 1


if __name__ == "__main__":
    raise SystemExit(main())
