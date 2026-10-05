"""Pure normalized access-ACL predicates; no host access or identity operations."""

import json
import re

MAX_INPUT_BYTES = 16_384
MAX_OUTPUT_BYTES = 65_536
MAX_DEPTH = 6
MAX_NUMERIC_CHARS = 10
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}", re.ASCII)
FEATURES = frozenset(("capabilities", "lsm", "mount", "idmap", "namespace", "symlink",
                      "race", "default_inheritance", "sticky", "descriptor", "unknown_context"))
ASSUMPTIONS = ("invented_filesystem_ids", "identity_mapping_assumed",
               "declared_context_only", "normalized_access_acl")
NOT_VERIFIED = ("actual_access", "actual_acl", "context_truth", "identity_mapping",
                "ancestor_search", "full_system_policy")


class _Invalid(ValueError):
    def __init__(self, reason: str, status: str = "rejected"):
        self.reason, self.status = reason, status


def _outcome(status: str, reason: str) -> dict:
    return {"status": status, "complete": status == "model_complete", "reason": reason,
            "actual_access": "unverified", "actual_acl": "unverified",
            "assumptions": list(ASSUMPTIONS), "not_verified": list(NOT_VERIFIED)}


def _keys(value: object, expected: set[str]) -> dict:
    if type(value) is not dict or len(value) != len(expected):
        raise _Invalid("object_shape")
    # Inspect exact string types before input-key hashing/equality can invoke hooks.
    if any(type(key) is not str for key in value) or set(value) != expected:
        raise _Invalid("object_shape")
    return value


def _integer_value(value: object, minimum=0, maximum=999_999_999) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _Invalid("integer_range")
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or len(value) > 32 or IDENTIFIER.fullmatch(value) is None:
        raise _Invalid("identifier")
    return value


def _list(value: object, maximum: int) -> list:
    if type(value) is not list:
        raise _Invalid("list_shape")
    if len(value) > maximum:
        raise _Invalid("list_limit", "over_limit")
    return value


def _entries(value: object, qualifier: str) -> tuple:
    entries = []
    for item in _list(value, 8):
        record = _keys(item, {qualifier, "permissions"})
        entries.append((_integer_value(record[qualifier]), _integer_value(record["permissions"], 0, 7)))
    if len({q for q, _ in entries}) != len(entries):
        raise _Invalid("duplicate_id")
    return tuple(sorted(entries))


def _validated(value: object) -> tuple:
    record = _keys(value, {"version", "profile", "subject", "object", "request_bits", "context"})
    version = _integer_value(record["version"])
    profile = _identifier(record["profile"])
    subject = _keys(record["subject"], {"fsuid", "fsgid", "supplementary_gids"})
    fsuid, fsgid = _integer_value(subject["fsuid"]), _integer_value(subject["fsgid"])
    supplementary = tuple(_integer_value(gid) for gid in _list(subject["supplementary_gids"], 16))
    if len(set(supplementary)) != len(supplementary):
        raise _Invalid("duplicate_id")
    obj = _keys(record["object"], {"id", "kind", "owner_uid", "owning_gid", "acl"})
    object_id = _identifier(obj["id"])
    kind = obj["kind"]
    if type(kind) is not str or kind not in ("regular", "directory"):
        raise _Invalid("kind")
    owner_uid, owning_gid = _integer_value(obj["owner_uid"]), _integer_value(obj["owning_gid"])
    acl = _keys(obj["acl"], {"owner", "users", "group", "groups", "mask", "other"})
    owner = _integer_value(acl["owner"], 0, 7)
    users = _entries(acl["users"], "uid")
    group = _integer_value(acl["group"], 0, 7)
    groups = _entries(acl["groups"], "gid")
    mask = None if acl["mask"] is None else _integer_value(acl["mask"], 0, 7)
    other = _integer_value(acl["other"], 0, 7)
    if (users or groups) and mask is None:
        raise _Invalid("required_mask")
    bits = _integer_value(record["request_bits"], 1, 7)
    context = _keys(record["context"], {"acl_kind", "dialect", "excluded_features"})
    declarations = []
    for field, supported, allowed in (("acl_kind", "access", ("access", "default", "unknown")),
                                      ("dialect", "linux_posix", ("linux_posix", "windows", "nfsv4", "unknown"))):
        declaration = context[field]
        if type(declaration) is not str or declaration not in allowed:
            raise _Invalid("context_enum")
        if declaration != supported:
            declarations.append(f"{field}_{declaration}")
    features = _list(context["excluded_features"], 16)
    for feature in features:
        if type(feature) is not str or len(feature) > 32 or feature not in FEATURES:
            raise _Invalid("context_enum")
    if len(set(features)) != len(features):
        raise _Invalid("duplicate_feature")
    # Only after the complete common schema validates may any exclusion win.
    declarations.extend(f"feature_{feature}" for feature in features)
    for reason, condition in (("version", version != 1), ("profile", profile != "linux_access_acl_v1"),
                              ("fsuid_zero", fsuid == 0)):
        if condition:
            declarations.append(reason)
    return (object_id, kind, fsuid, frozenset((fsgid, *supplementary)), owner_uid, owning_gid,
            owner, users, group, groups, mask, other, bits), sorted(declarations)


def _effective(raw: int, mask: int | None) -> int:
    return raw if mask is None else raw & mask


def _check(entry_type: str, qualifier: int | None, raw: int, mask: int | None, bits: int) -> dict:
    effective = _effective(raw, mask)
    return {"entry_type": entry_type, "qualifier": qualifier, "raw_bits": raw,
            "mask_bits": mask, "effective_bits": effective, "covers_request": effective & bits == bits}


def _group_permits(checks: list[dict], bits: int, other: int) -> bool:
    # A complete matching entry can succeed even when an earlier one failed.
    # `other` is deliberately unavailable as fallback once any group matches.
    return any(check["covers_request"] for check in checks)


def _decide(data: tuple) -> dict:
    object_id, kind, fsuid, gids, owner_uid, owning_gid, owner, users, group, groups, mask, other, bits = data
    if fsuid == owner_uid:
        branch, checks = "owner", [_check("owner", None, owner, None, bits)]
    else:
        named = next((permissions for uid, permissions in users if uid == fsuid), None)
        if named is not None:
            branch, checks = "named_user", [_check("named_user", fsuid, named, mask, bits)]
        else:
            checks = []
            if owning_gid in gids:
                checks.append(_check("owning_group", owning_gid, group, mask, bits))
            checks.extend(_check("named_group", gid, permissions, mask, bits)
                          for gid, permissions in groups if gid in gids)
            if checks:
                branch = "group_entries"
            else:
                branch, checks = "other", [_check("other", None, other, None, bits)]
    permits = _group_permits(checks, bits, other) if branch == "group_entries" else checks[0]["covers_request"]
    return {"object_id": object_id, "branch": branch, "request_bits": bits,
            "bit1_semantics": "execute_bit" if kind == "regular" else "search_bit",
            "model_permits": permits, "checks": checks}


def evaluate(request: object) -> dict:
    """Validate supplied builtin records and explain ACL predicates, never host access.

    Current common fields validate before unknown profile/version/root/context
    exclusions. A complete denial is still a completed model; no caller mutation.
    """
    try:
        data, unsupported = _validated(request)
        if unsupported:
            return {**_outcome("unsupported", "outside_subset"), "unsupported_reasons": unsupported}
        return {**_outcome("model_complete", "normalized_acl_predicates_only"), **_decide(data)}
    except _Invalid as error:
        return _outcome(error.status, error.reason)


def _depth(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise _Invalid("depth_limit", "over_limit")
        elif char in "]}":
            depth -= 1


def _unique(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Invalid("duplicate_key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > MAX_NUMERIC_CHARS:
        raise _Invalid("numeric_token_limit", "over_limit")
    return int(token)


def _reject_number(token: str) -> None:
    if len(token) > MAX_NUMERIC_CHARS:
        raise _Invalid("numeric_token_limit", "over_limit")
    raise _Invalid("non_integer_number")


def analyze_json(raw: object) -> dict:
    """Strict UTF8 exact bytes, capped before JSON decoding, to bounded model report."""
    if type(raw) is not bytes:
        return _outcome("rejected", "input_type")
    if len(raw) > MAX_INPUT_BYTES:
        return _outcome("over_limit", "input_limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        _depth(text)
        return evaluate(json.loads(text, object_pairs_hook=_unique, parse_int=_integer,
                                   parse_float=_reject_number, parse_constant=_reject_number))
    except _Invalid as error:
        return _outcome(error.status, error.reason)
    except (UnicodeError, ValueError, RecursionError):
        return _outcome("rejected", "invalid_json_or_utf8")


def serialize_report(report: dict) -> bytes:
    """Serialize trusted internally constructed reports; oversized fallback is incomplete.

    This is not an arbitrary-object public ingestion API. Accepted bounded reports
    cannot reach the cap; tests use labeled trusted oversized formatter seams.
    """
    def encode(value):
        return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8") + b"\n"
    encoded = encode(report)
    if len(encoded) > MAX_OUTPUT_BYTES:
        encoded = encode(_outcome("over_limit", "output_limit"))
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ValueError("trusted output budget smaller than fallback")
    return encoded
