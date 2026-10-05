"""Fixed full-report and independent bit-set oracles; no host ACL tests."""

from copy import deepcopy
from contextlib import ExitStack
import builtins
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from acl_lab import core
from acl_lab.fixtures import oracles, request


def positions(bits):
    return {index for index in range(3) if (bits // (2 ** index)) % 2}


class CoreTests(unittest.TestCase):
    def incomplete(self, value, status="rejected", reason=None):
        result = core.evaluate(value)
        self.assertEqual(result["status"], status)
        self.assertIs(result["complete"], False)
        if reason:
            self.assertEqual(result["reason"], reason)
        for forbidden in ("branch", "checks", "model_permits"):
            self.assertNotIn(forbidden, result)
        return result

    def test_frozen_full_oracles(self):
        root = Path(__file__).resolve().parents[1]
        frozen = (root / "fixtures/oracles.json").read_bytes()
        receipt = json.loads((root / "research/oracle-freeze.json").read_bytes())
        self.assertFalse(receipt["core_exists"])
        self.assertEqual(hashlib.sha256(frozen).hexdigest(), receipt["sha256"])
        fixtures = json.loads(frozen)
        self.assertEqual(fixtures, [{"id": n, "request": r, "expected": e} for n, r, e in oracles()])
        self.assertEqual(len(fixtures), 13)
        for item in fixtures:
            with self.subTest(case=item["id"]):
                self.assertEqual(core.evaluate(item["request"]), item["expected"])
                self.assertEqual(core.analyze_json(json.dumps(item["request"]).encode()), item["expected"])

    def test_split_regression(self):
        value = request(303, 20, (30,), groups=((20, 4), (30, 2)), mask=6, bits=6)
        self.assertFalse(core.evaluate(value)["model_permits"])
        value["object"]["acl"]["groups"][0]["permissions"] = 6
        self.assertTrue(core.evaluate(value)["model_permits"])

    def test_mask_regression(self):
        value = request(202, 20, users=((202, 6),), mask=4, bits=6)
        self.assertFalse(core.evaluate(value)["model_permits"])
        value["object"]["acl"]["mask"] = 6
        self.assertTrue(core.evaluate(value)["model_permits"])

    def test_no_fallback_regression(self):
        self.assertFalse(core.evaluate(request(group=0, other=7))["model_permits"])

    def test_later_group_and_distinct_same_gid(self):
        result = core.evaluate(request(group=4, groups=((10, 6),), mask=6, bits=6))
        self.assertTrue(result["model_permits"])
        self.assertEqual([c["entry_type"] for c in result["checks"]], ["owning_group", "named_group"])
        self.assertEqual([c["covers_request"] for c in result["checks"]], [False, True])

    def test_independent_named_domain_448(self):
        count = 0
        for raw in range(8):
            for mask in range(8):
                for bits in range(1, 8):
                    value = request(202, 20, users=((202, raw),), mask=mask, bits=bits)
                    expected = positions(bits) <= (positions(raw) & positions(mask))
                    self.assertEqual(core.evaluate(value)["model_permits"], expected)
                    count += 1
        self.assertEqual(count, 448)

    def test_independent_group_domain_3584(self):
        count = 0
        for left in range(8):
            for right in range(8):
                for mask in range(8):
                    for bits in range(1, 8):
                        value = request(303, 20, (30,), groups=((20, left), (30, right)), mask=mask, bits=bits)
                        required = positions(bits)
                        expected = any(required <= (positions(raw) & positions(mask)) for raw in (left, right))
                        self.assertEqual(core.evaluate(value)["model_permits"], expected)
                        count += 1
        self.assertEqual(count, 3584)

    def test_mask_tightening_1512(self):
        count = 0
        for wide in range(8):
            for narrow in range(8):
                if not positions(narrow) <= positions(wide):
                    continue
                for raw in range(8):
                    for bits in range(1, 8):
                        value = request(202, 20, users=((202, raw),), mask=wide, bits=bits)
                        broad = core.evaluate(value)["model_permits"]
                        value["object"]["acl"]["mask"] = narrow
                        tight = core.evaluate(value)["model_permits"]
                        self.assertFalse(tight and not broad)
                        count += 1
        self.assertEqual(count, 1512)

    def test_order_immutability_membership(self):
        value = request(303, 20, (30, 20), groups=((30, 6), (20, 4)), mask=6, bits=6)
        before = deepcopy(value)
        actual = core.evaluate(value)
        self.assertEqual(value, before)
        value["object"]["acl"]["groups"].reverse()
        self.assertEqual(actual, core.evaluate(value))
        self.assertEqual([c["qualifier"] for c in actual["checks"]], [20, 30])
        value["subject"]["supplementary_gids"] = []
        self.assertFalse(core.evaluate(value)["model_permits"])

    def test_basic_classes_and_directory(self):
        for uid, gid, branch, expected in ((101, 99, "owner", True), (303, 10, "group_entries", False),
                                           (303, 99, "other", True)):
            value = request(uid, gid, owner=4, group=2, other=4)
            result = core.evaluate(value)
            self.assertEqual((result["branch"], result["model_permits"]), (branch, expected))
        value = request(101, 99, owner=1, bits=1)
        value["object"]["kind"] = "directory"
        self.assertEqual(core.evaluate(value)["bit1_semantics"], "search_bit")
        self.assertTrue(core.evaluate(value)["model_permits"])

    def test_required_optional_masks_duplicates(self):
        self.incomplete(request(users=((202, 4),)), reason="required_mask")
        self.incomplete(request(groups=((20, 4),)), reason="required_mask")
        for kwargs in ({"users": ((202, 4), (202, 2))}, {"groups": ((20, 4), (20, 2))}):
            self.incomplete(request(mask=7, **kwargs), reason="duplicate_id")
        value = request()
        value["subject"]["supplementary_gids"] = [20, 20]
        self.incomplete(value, reason="duplicate_id")

    def test_all_validation_before_exclusions_or_owner(self):
        for mode in ("owner", "root", "version", "profile", "context"):
            value = request(101, 10, owner=7, groups=((20, 7), (30, 7)), mask=7)
            if mode == "root":
                value["subject"]["fsuid"] = 0
            elif mode in ("version", "profile"):
                value[mode] = 2 if mode == "version" else "Future"
            elif mode == "context":
                value["context"]["dialect"] = "unknown"
            value["object"]["acl"]["groups"][-1]["permissions"] = True
            self.incomplete(value, reason="integer_range")

    def test_unsupported_reasons_and_common_schema(self):
        value = request(0, 0)
        value["version"], value["profile"] = 2, "Future"
        value["context"] = {"acl_kind": "default", "dialect": "nfsv4", "excluded_features": ["lsm", "idmap"]}
        result = self.incomplete(value, "unsupported", "outside_subset")
        self.assertEqual(result["unsupported_reasons"], ["acl_kind_default", "dialect_nfsv4", "feature_idmap",
                                                       "feature_lsm", "fsuid_zero", "profile", "version"])
        del value["object"]["acl"]["mask"]
        self.incomplete(value)
        for feature in core.FEATURES:
            value = request()
            value["context"]["excluded_features"] = [feature]
            self.incomplete(value, "unsupported")
        for field, values in (("acl_kind", ("default", "unknown")), ("dialect", ("windows", "nfsv4", "unknown"))):
            for declaration in values:
                value = request()
                value["context"][field] = declaration
                self.incomplete(value, "unsupported")

    def test_exact_types_scalars_and_shapes(self):
        class Number(int):
            pass
        class Mapping(dict):
            pass
        class Sequence(list):
            pass
        class Text(str):
            pass
        self.incomplete(Mapping(request()))
        for bad in (True, -1, 1_000_000_000, Number(1), "1", 1.0, None):
            value = request()
            value["version"] = bad
            self.incomplete(value)
            value = request()
            value["subject"]["fsuid"] = bad
            self.incomplete(value)
        for bad in (0, 8, True, "4"):
            value = request()
            value["request_bits"] = bad
            self.incomplete(value)
        for bad in (Text("Invented"), "x" * 33, "\ud800", "Bad\n", "é"):
            value = request()
            value["object"]["id"] = bad
            self.incomplete(value, reason="identifier")
        value = request()
        value["subject"]["supplementary_gids"] = Sequence([20])
        self.incomplete(value)
        for field in ("owner", "group", "mask", "other"):
            for bad in (True, -1, 8, Number(4)):
                value = request()
                value["object"]["acl"][field] = bad
                self.incomplete(value)
        for bad in ({}, [], object(), None):
            self.incomplete(bad)

    def test_context_errors_and_caps(self):
        for field, bad in (("acl_kind", "invalid"), ("dialect", "invalid"),
                           ("excluded_features", ["invalid"]), ("excluded_features", ["lsm", "lsm"]),
                           ("excluded_features", ["x" * 10000]),
                           ("excluded_features", [object()])):
            value = request()
            value["context"][field] = bad
            self.incomplete(value)
        for field in ("users", "groups"):
            key = "uid" if field == "users" else "gid"
            value = request(mask=7)
            value["object"]["acl"][field] = [{key: n, "permissions": 7} for n in range(8)]
            self.assertTrue(core.evaluate(value)["complete"])
            value["object"]["acl"][field].append({key: 9, "permissions": 7})
            self.incomplete(value, "over_limit")
        value = request(supplementary=range(16))
        self.assertTrue(core.evaluate(value)["complete"])
        value["subject"]["supplementary_gids"].append(16)
        self.incomplete(value, "over_limit")
        value = request()
        value["context"]["excluded_features"] = ["lsm"] * 17
        self.incomplete(value, "over_limit")

    def test_custom_hooks_and_cycles_rejected(self):
        class Key(str):
            def __hash__(self):
                return str.__hash__(self)
            def __eq__(self, other):
                raise AssertionError("custom equality invoked")
        value = request()
        value[Key("custom")] = value.pop("profile")
        self.incomplete(value)
        value = request()
        value["subject"]["supplementary_gids"].append(value)
        self.incomplete(value)
        value = request(mask=7)
        value["object"]["acl"]["groups"].append(value["object"]["acl"])
        self.incomplete(value)
        value = request()
        value["object"] = value
        self.incomplete(value)

    def test_raw_bounds_and_strict_json(self):
        raw = json.dumps(request()).encode()
        self.assertTrue(core.analyze_json(raw + b" " * (core.MAX_INPUT_BYTES-len(raw)))["complete"])
        self.assertEqual(core.analyze_json(raw + b" " * (core.MAX_INPUT_BYTES-len(raw)+1))["reason"], "input_limit")
        cases = ((b"["*7+b"0"+b"]"*7, "depth_limit"),
                 (b'{"a":10000000000}', "numeric_token_limit"),
                 (b'{"a":-9999999999}', "numeric_token_limit"),
                 (b'{"a":1.5}', "non_integer_number"),
                 (b'{"a":NaN}', "non_integer_number"),
                 (b'{"a":1,"a":2}', "duplicate_key"),
                 (b'\xff', "invalid_json_or_utf8"),
                 (b'{', "invalid_json_or_utf8"))
        for raw, reason in cases:
            self.assertEqual(core.analyze_json(raw)["reason"], reason)
        for value in (bytearray(b"{}"), "{}", memoryview(b"{}")):
            self.assertEqual(core.analyze_json(value)["reason"], "input_type")
        # Valid depth-six and ten-character negative integer parser seams: schema
        # rejection rather than limits, not accepted normalized ACL inputs.
        self.assertEqual(core.analyze_json(b"["*6+b"0"+b"]"*6)["reason"], "object_shape")
        self.assertEqual(core.analyze_json(b'{"a":-999999999}')["reason"], "object_shape")
        self.assertEqual(core.analyze_json(b'{"a":"[[[[[[[\\\""}')["reason"], "object_shape")

    def test_formatter_trusted_seams(self):
        self.assertLess(len(core.serialize_report(core.evaluate(request()))), core.MAX_OUTPUT_BYTES)
        # Trusted payloads, impossible through accepted input schema.
        prefix = len(core.serialize_report({"x": ""}))
        exact = core.serialize_report({"x": "a" * (core.MAX_OUTPUT_BYTES-prefix)})
        self.assertEqual(len(exact), core.MAX_OUTPUT_BYTES)
        result = json.loads(core.serialize_report({"x": "a" * (core.MAX_OUTPUT_BYTES-prefix+1)}))
        self.assertEqual((result["status"], result["complete"], result["reason"]), ("over_limit", False, "output_limit"))
        self.assertNotIn("model_permits", result)
        self.assertIn(b"\\u001b", core.serialize_report({"trusted": "\x1b"}))
        with patch.object(core, "MAX_OUTPUT_BYTES", 1):
            with self.assertRaises(ValueError):
                core.serialize_report({"x": "y"})

    def test_core_forbidden_capabilities(self):
        value = request(202, 20, users=((202, 6),), mask=6, bits=6)
        with ExitStack() as guards:
            for module, name in ((builtins, "open"), (builtins, "eval"), (builtins, "exec"),
                                 (os, "stat"), (os, "chmod"), (os, "system"),
                                 (subprocess, "Popen"), (socket, "socket")):
                guards.enter_context(patch.object(module, name, side_effect=AssertionError("forbidden host capability")))
            for name in ("getuid", "geteuid", "getgid", "getegid", "getgroups", "chown", "getxattr", "setxattr"):
                if hasattr(os, name):
                    guards.enter_context(patch.object(os, name, side_effect=AssertionError("forbidden identity/ACL")))
            self.assertTrue(core.evaluate(value)["model_permits"])
            self.assertTrue(core.analyze_json(json.dumps(value).encode())["model_permits"])
            self.assertTrue(core.serialize_report(core.evaluate(value)).endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
