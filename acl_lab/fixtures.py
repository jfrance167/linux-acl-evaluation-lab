"""Hand-fixed independent thirteen full-report oracles; no model imports.

Rows explicitly record raw, mask, effective and Boolean values. Tuple expansion
only labels fixed data; it never computes permissions or selects a branch.
"""

from copy import deepcopy

ASSUMPTIONS = ["invented_filesystem_ids", "identity_mapping_assumed",
               "declared_context_only", "normalized_access_acl"]
NOT_VERIFIED = ["actual_access", "actual_acl", "context_truth", "identity_mapping",
                "ancestor_search", "full_system_policy"]


def request(fsuid=303, fsgid=10, supplementary=(), *, owner=0, users=(),
            group=0, groups=(), mask=None, other=0, bits=4, owning_gid=10):
    """Make an invented record, never infer defaults from a real host."""
    return {"version": 1, "profile": "linux_access_acl_v1",
            "subject": {"fsuid": fsuid, "fsgid": fsgid,
                        "supplementary_gids": list(supplementary)},
            "object": {"id": "Invented", "kind": "regular", "owner_uid": 101,
                       "owning_gid": owning_gid,
                       "acl": {"owner": owner, "users": [{"uid": u, "permissions": p} for u, p in users],
                               "group": group, "groups": [{"gid": g, "permissions": p} for g, p in groups],
                               "mask": mask, "other": other}}, "request_bits": bits,
            "context": {"acl_kind": "access", "dialect": "linux_posix", "excluded_features": []}}


def expected(branch, bits, permits, rows):
    return {"status": "model_complete", "complete": True, "reason": "normalized_acl_predicates_only",
            "actual_access": "unverified", "actual_acl": "unverified",
            "assumptions": deepcopy(ASSUMPTIONS), "not_verified": deepcopy(NOT_VERIFIED),
            "object_id": "Invented", "branch": branch, "request_bits": bits,
            "bit1_semantics": "execute_bit", "model_permits": permits,
            "checks": [dict(zip(("entry_type", "qualifier", "raw_bits", "mask_bits",
                                 "effective_bits", "covers_request"), row)) for row in rows]}


def oracles():
    """Thirteen independently hand-derived reports, frozen before core code."""
    return [
        ("owner_unmasked", request(101, 20, owner=4, users=((101, 7),), group=7, other=7, mask=0),
         expected("owner", 4, True, [("owner", None, 4, None, 4, True)])),
        ("owner_no_fallback", request(101, 10, users=((101, 7),), group=7, other=7, mask=7),
         expected("owner", 4, False, [("owner", None, 0, None, 0, False)])),
        ("named_masked", request(202, 10, users=((202, 6),), group=7, other=7, mask=4, bits=6),
         expected("named_user", 6, False, [("named_user", 202, 6, 4, 4, False)])),
        ("named_complete", request(202, 20, users=((202, 6),), mask=6, bits=6),
         expected("named_user", 6, True, [("named_user", 202, 6, 6, 6, True)])),
        ("named_no_group_fallback", request(202, 20, (30,), users=((202, 0),), groups=((20, 7), (30, 7)), other=7, mask=7),
         expected("named_user", 4, False, [("named_user", 202, 0, 7, 0, False)])),
        ("split_groups", request(303, 20, (30,), groups=((20, 4), (30, 2)), other=7, mask=6, bits=6),
         expected("group_entries", 6, False, [("named_group", 20, 4, 6, 4, False), ("named_group", 30, 2, 6, 2, False)])),
        ("split_read", request(303, 20, (30,), groups=((20, 4), (30, 2)), mask=6),
         expected("group_entries", 4, True, [("named_group", 20, 4, 6, 4, True), ("named_group", 30, 2, 6, 2, False)])),
        ("later_same_gid", request(303, 10, group=4, groups=((10, 6),), mask=6, bits=6),
         expected("group_entries", 6, True, [("owning_group", 10, 4, 6, 4, False), ("named_group", 10, 6, 6, 6, True)])),
        ("group_no_other_fallback", request(group=0, other=7),
         expected("group_entries", 4, False, [("owning_group", 10, 0, None, 0, False)])),
        ("other_unmasked", request(303, 99, groups=((20, 7),), other=7, mask=0, bits=6),
         expected("other", 6, True, [("other", None, 7, None, 7, True)])),
        ("basic_no_mask", request(group=6, bits=6),
         expected("group_entries", 6, True, [("owning_group", 10, 6, None, 6, True)])),
        ("basic_with_mask", request(group=6, mask=4, bits=6),
         expected("group_entries", 6, False, [("owning_group", 10, 6, 4, 4, False)])),
        ("gid_zero_ordinary", request(303, 0, owning_gid=0, other=7),
         expected("group_entries", 4, False, [("owning_group", 0, 0, None, 0, False)])),
    ]
