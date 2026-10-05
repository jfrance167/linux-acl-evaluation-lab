# ECC actual-code self-review — October 5, 2026

## Delivery correction self-review

Coordinator03:51 identified a concrete medium CLI correctness defect in
acl_lab/__main__.py:35–40 at4d961c1: closed stdout/stderr pipes before stdin cause
the unchecked buffered diagnostic to survive until shutdown, replacing exit3 with
120. The coordinator reproduced it; original mock-only shutdown evidence and
initial zero-findings review below were insufficient for this boundary.

Reviewed the focused diff, full main/parser caller flow, installed argparse source,
in-memory short/flush paths and the new real-process harness. _io_failure detaches
both public sinks before diagnostic write/flush; _CheckedParser checks complete
write and flush rather than swallowing OSError. parse_args is inside the handler.
Healthy parser SystemExit behavior remains; model/schema/oracles are unchanged.
No dynamically supplied paths/programs or external commands are accepted by the
CLI. New subprocesses are trusted test-only Python children with fixed arguments,
explicit stdin barriers/closed OS pipe readers, timeout cleanup and captured exits.

32 tests normal/-O pass, including26 children per suite (14 native/control,
12 synthetic dirty-stream seams), preserving source-derived model properties.
All three original logic mutants/restored checks pass; compile and updated Bandit
app/tools pass (409LoC, no findings/errors/exclusions). Failed help/parser/error
delivery returns3 in normal/optimized real interpreters. Healthy help0 and unused
closed stderr2 controls confirm failures are not indiscriminately inferred.
Initial test-harness LF expectation was corrected to native Windows CRLF diagnostic
delivery; application contract/error text was not weakened. stdout JSON remains LF.

Final correction review: one medium defect fixed, zero unresolved actionable
findings. This remains implementing-agent ECC self-review, not an independent audit.
Old receipts retained; new current source/receipt and fresh vault correction bound
below. No Linux/live ACL/hosted checks, new scope or publication authorized.

## Original implementation self-review (historical)

Implementing Codex applied installed ecc-code-review/SKILL.md and pinned reviewer
reference. Native full ECC plugin remains unavailable; this is an implementing-agent
self-review, not an independent audit or a GitHub review. No merge/publication verdict.

Scope: full core and its API/CLI callers, thirteen independent fixed fixture reports,
normal/optimized test code, mutation/workflow tools, exact schema/limits, prepared
workflow files, installed scanner pins, public docs and new repository contents.
Baseline is the docs/oracle-only main commit 1875f5a. Only this project's changes
are reviewed; previous labs/parent/shared tooling are not modified or retested.

Reviewed precedence, UID/GID distinctions, mask-null provenance, required masks,
one-entry containment/later group success, full validation before exclusion/owner,
no fallback, exact-type/custom-key/cycle rejection and input immutability. Reviewed
strict decoding/depth/tokens, output escaping/caps, short writes/flush/error delivery,
finite loops, error reflection, imports/host capabilities and independent oracles.
Reused parser/CLI/workflow patterns were inspected before adaptation.

During implementation review an explicit feature-string length guard was added
before hash-set membership, keeping API enum validation bounded without hashing a
large arbitrary string. A 10000-character rejected-feature case exercises it.
Final tests include stderr delivery failure and a nonrecursive formatter fallback
for tiny trusted patched budgets. This is defensive implementation hardening, not
an identified real-host vulnerability. No additional actionable final defect found.

Final checks: 26 tests normal/-O pass; thirteen fixed reports; 5544 finite property
comparisons per suite; three targeted faults each fail by one assertion with zero
errors, restored checks pass; actual analyze exits 0/1/2 and optimized demo 0.
Bandit application/tools zero findings/errors, no suppressions; compile/workflow/
pip checks pass. See VERIFICATION.md and bound raw evidence.

Remaining limits are documented: Linux/live access/hosted execution unverified,
no complete upstream advisory or dedicated secret scan/hash-lock proof, no hard
resource sandbox, only finite synthetic evaluation and self-review. Review of
tracked content found no obvious private material/credentials; that is a limited
content check, not a credential scanner guarantee. Original generated drafts remain
separate and ignored; no external provider or authority was imported from them.

Final severity counts: critical 0, high 0, medium 0, low 0 unresolved actionable
findings. Local reviewed-scope acceptance only; Jake retains any external release,
merge or security-sensitive integration decision.
