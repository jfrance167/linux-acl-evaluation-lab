# Frozen implementation contract

October 5, 2026: coordinator 03:19 approved PLAN stages 1–3 under Jake's
previously verified successor mandate. Addendum requires thirteen full independent
oracles before core code, strict common validation, independent group containment,
mask provenance, property domains, mutation checks, ECC review and vault milestone.
An isolated local Git repository/codex branch and prepared CI are authorized.
No host identity/path/ACL queries or changes, native installations, live experiments,
new chats, publication, pushes, merges, deployment or spending are authorized.

PLAN's schema and limits are frozen. Validation order is root keys, version,
profile, subject (IDs then supplementary GIDs), object (ID, kind, IDs, ACL),
request bits, context. ACL validation is owner, users, group, groups, mask, other,
then required-mask presence. Every entry is validated before exclusion decisions.
API cycles cannot satisfy this finite tree schema: they are rejected at the first
field requiring a scalar or exact-key record; no recursive arbitrary-object walk
or custom hooks. Shared acyclic records are allowed; no input mutation.

Reports always contain status, complete, reason, actual_access="unverified",
actual_acl="unverified", assumptions=["invented_filesystem_ids",
"identity_mapping_assumed", "declared_context_only", "normalized_access_acl"],
not_verified=["actual_access", "actual_acl", "context_truth", "identity_mapping",
"ancestor_search", "full_system_policy"].

Complete includes object_id, branch, request_bits, bit1_semantics
(execute_bit/search_bit), model_permits and checks. Reason is
normalized_acl_predicates_only, even for a complete denial. Check ordering is
owner alone; named user alone; owning group first then named groups by GID; or
other alone. Every matching group appears even after a success. Check fields:
entry_type, qualifier, raw_bits, mask_bits, effective_bits, covers_request.
Owner/other qualifier and mask_bits are null; owning_group qualifier is owning GID.
Named qualifiers are their UID/GID. Group mask_bits is null only for a basic ACL
with null mask. Owner/other null means unmasked even if a mask exists.

Valid exclusions use status=unsupported, complete=false, reason=outside_subset,
unsupported_reasons as sorted strings: version, profile, fsuid_zero,
acl_kind_default/acl_kind_unknown, dialect_windows/dialect_nfsv4/dialect_unknown,
and feature_<fixed feature name>. No branch/check/model_permits is returned.
Rejected and over_limit have complete=false and fixed first-error reason; no partial
decision. Fixed reasons are object_shape, integer_range, identifier, list_shape,
list_limit, duplicate_id, kind, required_mask, context_enum, duplicate_feature,
input_type, input_limit, depth_limit, numeric_token_limit, non_integer_number,
duplicate_key, invalid_json_or_utf8, output_limit. No reflected user text.

Independent fixture values are fixed in acl_lab/fixtures.py and expanded into
fixtures/oracles.json before core.py exists. All thirteen full expected reports
include every field/check. Do not derive expected bits/decisions from the evaluator.

Property domains frozen before implementation:
- Named user: raw 0..7 × mask 0..7 × request 1..7 = 448 comparisons against
  independently constructed bit-position sets.
- Two matching named groups: each raw 0..7 × common mask 0..7 × request 1..7 =
  3584 comparisons. Require one individual intersected set to contain the request;
  never use the union as oracle.
- Tightening mask: all 8×8 subset pairs, raw 0..7 and request 1..7 = 1512
  implications (27 subset pairs); tightening cannot repair a denial. No accuracy
  or exhaustive system-policy claim; these finite domains total 5544 comparisons.
- Fixed reverse-order check invariance, basic ACL class comparisons, paired
  split-group repair and directory bit1 semantics complement these properties.

Raw input limit 16384 bytes; JSON depth 6; numeric token limit 10 characters;
IDs 0..999999999; 16 supplementary GIDs; 8 each named users/groups; 16 unique
features from PLAN's eleven allowed names. Exact builtins; booleans/subclasses,
floats, duplicate keys and nonfinite constants rejected. Output compact ASCII-escaped
JSON plus LF ≤65536 bytes. Valid reports cannot reach this cap; oversized internal
payload and patched/reduced CLI seams are labeled, never claimed as accepted input.
Formatter fallback itself must fit; tiny patched budgets raise a trusted formatter
error rather than recurse. CLI exit 0 permit/pass demo, 1 deny/fail demo, 2 incomplete,
3 I/O failure; partial output is possible. Trusted packaged fixtures only are used
by demo; evaluator imports only json/re and never accesses host state.
