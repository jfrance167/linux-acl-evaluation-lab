# Proposed Linux access-ACL evaluator — October 5, 2026

Tier3 learning/security-model project; RESEARCH/PLAN ONLY selected02:56 by coordinator
under Jake's verified direct successor mandate. Same existing chat sole writer,
separate linux-acl-evaluation-lab. Stages 1–3 approved at 03:19, continuation
reaffirmed at 03:32. CONTRACT.md records the approval and frozen refinements.
Cutoff new scope October6 08:00 Eastern.

## Problem, success and choice

Teach normalized supplied Linux access-ACL decisions, named-user precedence, mask
effects and why several matching groups cannot pool split bits for one combined
request. Success: source-backed fixed branch/check/Boolean examples, current exact
schema validation before exclusions/decision, honest actual-access limits, bounded
pure API/CLI and independently verified regression/property/mutation evidence.

Recommend original stdlib build. Kernel/LTP/native pylibacl reference comparison,
license/maintenance/dependency/CI limits in RESEARCH.md. Sticky-directory entry rules
alternate would revisit parent/ownership/capability authorization; ACLs fill a distinct
gap intentionally excluded from prior modes/creation. Default ACL inheritance,
mask construction/calculation and Windows/NFSv4 semantics remain non-goals.

## Proposed exact normalized contract

Root exact built-in dict keys version/profile/subject/object/request_bits/context.
Version exact integer0..999999999, bool invalid;1 supported, other bounded values
unsupported after current common structure/ACL validation. Profile exact ASCII
identifier [A-Za-z][A-Za-z0-9_-]{0,31}, linux_access_acl_v1 supported; other valid
labels unsupported after common validation, never unknown-schema acceptance.

Subject exact fsuid/fsgid/supplementary_gids. IDs exact ints0..999999999, bool invalid,
list0..16 unique supplementary GIDs; overlap with fsgid harmless/allowed. fsuid0
unsupported after all validation; fsgid0 ordinary group only. No account or process
identity lookup, no names/real/effective-ID inference. IDs are invented data.

Object exact id/kind/owner_uid/owning_gid/acl. ID same bounded ASCII grammar; kind
regular/directory only, IDs same range. No path/mode field, ancestor chain or access
to previously opened descriptors. bit1 means execute-bit predicate for regular,
search-bit predicate for directory, neither a syscall guarantee.

ACL exact dict owner/users/group/groups/mask/other. owner/group/other mandatory
permission integers0..7 (bool invalid). users/groups exact lists0..8 each; entries
exact {uid,permissions}/{gid,permissions}, numeric qualifier range above and bits0..7.
Named UIDs unique within users, GIDs unique within groups; owner UID may also appear
as named-user qualifier, owning GID as named-group qualifier (distinct entry types).
Both still subject to ordered evaluation. Lists may arrive any order; copy/sort by
qualifier after validation for deterministic explanations, never mutate input.
Mask field required: null means no mask; exact integer0..7 explicit mask. Named
entries require non-null mask; without named entries either null or explicit mask
valid. No auto mask union, no silently repaired missing mask, no text/xattr parser.

request_bits exact integer1..7, zero invalid to keep nonempty requests explicit.
All requested bits required in one selected entry and applicable mask. Labels/read/
write names/coercion/numeric flags outside low-three-bit grammar rejected.

Required exact context dict acl_kind/dialect/excluded_features:
- acl_kind access supported; default/unknown known unsupported, other values invalid.
- dialect linux_posix supported; windows/nfsv4/unknown known unsupported, other invalid.
- excluded_features exact list0..16 unique strings from fixed set capabilities,
  lsm,mount,idmap,namespace,symlink,race,default_inheritance,sticky,descriptor,
  unknown_context. Any present feature unsupported, unknown label invalid.
Empty exclusions are caller assumptions, not verified absence. No root/capability/
LSM/mount/idmap/namespace/sticky/descriptor or full-system policy claim.

Admission: validate every current common field and ACL entry (including missing
required mask/duplicate qualifiers/types/ranges) before unknown profile/version,
root/context unsupported or bit decision. Invalid yields rejected, resource limits
over_limit; neither emits a branch/check/calculation. All valid but known exclusion
yields unsupported with fixed sorted reasons, no decision. Otherwise model_complete,
model_permits Boolean, deterministic explanation/checks. First invalid reason follows
validation order; no claim to enumerate all defects in malformed input.

## Exact decision path and report proposal

1. fsuid equals owner_uid: owner branch, raw owner bits, no mask. No named-user/
   group/other fallback even if owner bits deny.
2. Otherwise matching named UID: named_user branch, raw entry AND mask; no group/
   other fallback even if deny.
3. Otherwise any owning or named group matches fsgid/supplementary set: group_entries
   branch, check each matching entry independently (owning first, then sorted named
   GIDs). Permit iff at least one single matching entry's raw bits and applicable
   mask contain every requested bit. Never union across entries, never stop at the
   first insufficient matching group, never other fallback after any group match.
4. Otherwise other branch, raw other bits, no mask.

No mask on a basic ACL behaves as unmasked owning-group permissions. A present
mask with no named entries still restricts owning group. Named mask is mandatory.
Matching entry checks all emitted even when an earlier entry already succeeds,
for explanation only; no claim to reproduce kernel instruction/call order.

Report always status/complete/reason, actual_access and actual_acl both unverified,
fixed assumptions/not_verified. Complete adds object_id/branch/request_bits/
bit1_semantics/model_permits/checks. A check includes entry_type, qualifier (null
for owner/other or numeric UID/GID as applicable), raw_bits/mask_bits (null when
unmasked)/effective_bits/covers_request. Do not call OR-of-multiple entries effective
permissions; no universal permission-mode/access/secure label. Unsupported adds
bounded fixed sorted reason names, never a partial model decision.

Bounds: input bytes<=16384 before strict UTF8 JSON; depth<=6 outside strings;
numeric token<=10 incl sign; floats/constants/duplicate keys invalid. Exact built-in
dict/list/int/str only, no custom key/coercion/iteration hooks, ID/profile<=32ASCII,
16supGIDs,8namedUIDs+8namedGIDs, fixed feature enums. API same semantic/cardinality
bounds. Internal report serializer ensure_ascii compactJSON+LF<=65536; fallback
incomplete output_limit. Accepted bounded reports cannot naturally hit64KiB; trusted
oversized formatter and patched CLI seams labeled. No mutation of callers.
CLI analyze/demo bounded read cap+1, exact write count/flush, fixed error stderr;
I/O failure may leave partial stdout, exit3 no atomic guarantee. Exit0 permits/
passing demo,1 denies/failed demo,2 rejected/unsupported/over_limit.

## Hand-derived proposed independent fixtures

All ordinary IDs fictional. Default ownerUID101/owningGID10; unspecified named
lists empty, mask null, owner/group/other0. Tuples are fixed expected branch/bits/
decision, not production-generated. Each named entry shown ID:bits.

| Case | Subject fsuid/fsgid/supp | ACL overrides | Request | Expected |
|---|---|---|---|---|
| Owner unmasked | 101/20/[] | owner4, users[101:7], group7, other7, mask0 | 4 | owner effective4, permit |
| Owner cannot fallback | 101/10/[] | owner0, users[101:7], group7, other7, mask7 | 4 | owner0, deny |
| Named-user masked | 202/10/[] | users[202:6], group7, other7, mask4 | 6 | named_user effective4, deny |
| Named-user complete | 202/20/[] | users[202:6], mask6 | 6 | named_user6, permit |
| Named-user no group fallback | 202/20/[30] | users[202:0], groups[20:7,30:7], other7, mask7 | 4 | named_user0, deny |
| Split groups cannot union | 303/20/[30] | groups[20:4,30:2], other7, mask6 | 6 | group_entries effective4,2, deny |
| One split entry covers read | 303/20/[30] | groups[20:4,30:2], mask6 | 4 | group_entries4,2, permit from20 |
| Later same-GID named group | 303/10/[] | group4, groups[10:6], mask6 | 6 | group_entries4,6, permit from named10 |
| Matching group cannot other-fallback | 303/10/[] | group0, other7 | 4 | group_entries0, deny |
| Other ignores mask | 303/99/[] | groups[20:7], other7, mask0 | 6 | other7, permit |
| Basic group without mask | 303/10/[] | group6 | 6 | group_entries6, permit |
| Basic group with mask | 303/10/[] | group6, mask4 | 6 | group_entries4, deny |
| Group zero is ordinary | 303/0/[] | owningGID0, group0, other7 | 4 | group_entries0, deny |

Paired controls: mask6 repairs named-user6/request6; group20:6 repairs split group
request6. Missing required mask/duplicate named UID/GID malformed, later malformed
entry must reject even when owner matches or context/root unsupported. Basic no-mask
case versus explicit mask proves optional does not mean ignored. Directory bit1
labels search predicate only; fsuid0 unsupported, never automatically permitted.
Freeze full exact checks and explanation fields independently before coding.

## Threat model, stages and verification

Assets: correct normalized selection/mask explanation, honest status, bounded input
and no ambient host actions. Adversary provides coercion objects, duplicate/conflicting
IDs, missing mask, unknown context, oversized parse/numeric/list data or assumes
grant applies to a real host. All-field validation, exact types, finite normalized
records, fixed unverified claims and single-entry request checks mitigate model
threats. None verifies record/context truth or richer real policy/actual access.

Stage1: freeze approved schema/status/complete check oracles; implement pure stdlib
normalization/evaluator/strict JSON API. Done: owner/named/group/other precedence,
mask placement, all-entry validation, no union/first-match/fallback, no host calls.
Stage2: bounded CLI/demo/tests. Done: hand-fixed results/checks, input immutability,
order invariance, mask subset properties/basic ACL comparison, absent/supplementary/
primary group rules, required/optional mask, duplicates/full-common unknown-profile
handling, raw/depth/token/string/cardinality/output limits, invalid UTF8/coercion/
custom keys, fixed stderr and short/failed write/flush. No live ACL permission tests.
Stage3: actual-change ECC self-review, assertion-detected isolated group-union/
ignored-mask/other-fallback mutations and restored checks, normal/optimized tests,
compile/Bandit/local pinned workflow verification. Done: corrected defects, source
bindings/exit receipts, README/security/license/AI disclosure/DECISIONS/LEARNING/
STATE and authorized Obsidian milestone; separate local codex branch/CI only if
approved. No remote repository/publication/merge or parent/shared-tool changes.

Tests use independent fixed oracles, not candidate output as expected truth. Kernel/
man-page combined-group algorithm source-verified; inspected LTP lacks a direct
split-group test, no upstream/live confirmation claim. Property scopes frozen before
implementation, no arbitrary coverage/accuracy promise. Guard host open/stat/access/
identity/ACL/permission/process/network capabilities; preimport trusted harness
before guards. Record unreachable formatter/malformed parser seams honestly.
Windows-only/hosted CodeQL/Linux/runtime/advisory/hash/dedicated-secret/history limits
remain; no scanner result proves security. Source/license attribution explicit.

Local-first ideas attempt completed but faulty grant/ignored-ACL suggestions rejected.
No remote draft with unverified free guardrails or excluded shared-tool refresh;
Codex performs judgments/plan, no new spending. No new chats/subagents/schedulers/
external messages, host changes/real targets/VMs/containers. Current AGENTS/app
approvals/cutoff apply. Next: implement the approved frozen contract and verify.
