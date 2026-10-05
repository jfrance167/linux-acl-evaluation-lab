# Research learning — October 5, 2026

Two matching groups with read4 and write2 cannot pool those permissions for one
read+write6 request. Linux checks full coverage in a single entry before the common
mask. A later matching entry with6 can permit even when the first matching entry4
is insufficient. Matching groups prevent falling back to other.

Owner and other bypass the ACL mask; named users and groups do not. A matching
named user denies without borrowing group/other bits. A mask calculated as a union
for ACL construction is not a request-time union of multiple group grants.

Actual kernel source and LTP mask/owner/other tests were inspected, not executed.
Direct upstream combined-group test coverage was not found in the bounded search.
The local draft's identity-match-implies-grant suggestions were rejected. Hand
oracles were frozen before approved implementation. Local verification now passes;
Linux runtime behavior remains unverified.

Thirty-two final tests pass normally and optimized. Independent bit-position sets provide
5544 finite property comparisons per suite; targeted union/mask/fallback mutations
each fail an assertion rather than crashing the harness. This supports those logic
boundaries; it does not prove complete system access control or universal correctness.

Complete means a valid supported model decision, including denial. Unsupported and
malformed records cannot emit a partial model grant. Mask-null in owner/other checks
means unmasked even when the ACL has a mask, while null in a basic group check means
the normalized ACL declares no mask. Supplying identical GIDs in two distinct entry
types does not authorize merging their permission bits.

Real buffering matters: a diagnostic write can apparently succeed yet fail later on
flush, causing CPython to replace an intended exit with120 during shutdown. Mocked
main() return values cannot establish process exit behavior. The confirmed CLI defect
was fixed by checked flush/delivery and detaching both dirty sinks, including help
and parser errors. Explicit stdin barriers make closed-pipe tests deterministic;
native pipes and synthetic short/flush child seams have separate evidential limits.
