# Local verification — October 5, 2026

## Final delivery correction

The original evidence below remains a historical pre-fix snapshot at4d961c1.
Coordinator03:51 matched its hashes, then independently reproduced analyze with
both output readers closed before stdin: actual exit120 instead of advertised3.
Original mocked failures had missed CPython's buffered shutdown behavior.

Focused fix checks parser/help writes and flushes, and detaches both public sinks
before attempting a checked fixed diagnostic. Installed argparse3.13 source was
inspected: default _print_message swallows OSError, so merely moving parse_args
inside the existing try would not fix help failures.

Post-fix evidence in evidence/cli-fix/: tests.txt and tests-optimized.txt each record
32 passed. processes.json/processes-optimized.json each retain 26 child outcomes:
14 native-pipe/healthy controls and12 labeled synthetic short/dirty-flush stream seams
in real child interpreters. Each set includes normal and optimized children; the
optimized parent suite repeats those same scenarios, not additional unique coverage.
Analyze with both pipes closed, stdout-only closed, and barrier-controlled help and
parser error delivery return3; healthy help returns0; an unused closed stderr does
not prevent ordinary rejected-input output/exit2. Closed readers are established
before releasing stdin; no timing sleep. Diagnostic text uses platform-native line
endings (CRLF on tested Windows); serialized stdout reports retain explicit LF.
Partial output remains possible, with no delivery/atomicity guarantee.

Short-write/flush mocks cover individual calls; labeled dirty-sink child seams test
actual interpreter finalization with synthetic streams, while closed pipes are
native OS pipes. Neither is represented as a Linux/ACL/host permission experiment.
32-test suites retain the same13 fixed oracles/5544 property comparisons. Mutations
again show three1-assertion/0-error caught faults with restored passes. Updated
compile/Bandit pass; Bandit app/tools409LoC, zero findings/errors/exclusions. No new
installation or unchanged-workflow/pip repeat was needed.

Current source hashes and final receipt are evidence/source-hashes.json and
evidence/final-receipt.json. Pre-fix copies live at evidence/cli-fix/pre-fix-*.json.
Original tests/scanner/demo/exit evidence stays unchanged. New reviewed code, tests,
docs and vault correction are recorded separately; all original platform/live/
hosted/advisory/secrets/supply-chain limits continue.

## Original stage evidence (historical)

Runtime: Windows CPython 3.13.7, installed Bandit 1.9.4/PyYAML 6.0.3; exact observed
versions in evidence/runtime.json. No installation, upgrade, remote worker, spending
or host identity/ACL/permission experiment occurred.

| Check | Observed result | Receipt |
|---|---|---|
| unittest discover -s tests -v | 26 passed | evidence/tests.txt |
| python -O same suite | 26 passed | evidence/tests-optimized.txt |
| Full hand-fixed oracles | 13 exact reports, pre-core byte digest matched | research/oracle-freeze.json; fixtures/oracles.json |
| Named-user bit-set domain | 448 comparisons per suite | test_independent_named_domain_448 |
| Two-group bit-set domain | 3584 comparisons per suite | test_independent_group_domain_3584 |
| Mask-subset monotonicity | 1512 implications per suite | test_mask_tightening_1512 |
| Targeted in-memory faults | 3 caught, 1 assertion failure each, 0 errors; restored pass | evidence/mutations.json |
| Normal/optimized demos | 13 passed each | evidence/demo.json; demo-optimized.json |
| Actual analyze CLI | permit 0, deny 1, unsupported 2 | evidence/cli-exits.json and cli-*.json |
| I/O test seams | bounded read, failed/short write/flush/stderr, exit 3 | tests/test_cli.py |
| Compilation | exit 0 | evidence/compile.txt; security-exits.json |
| Bandit app/tools | exit 0, 396 LoC, 0 findings/errors/skips/nosec | evidence/bandit.json; bandit-exit.json |
| Local workflow verifier normal/-O | PASS | evidence/workflows*.json; security-exits.json |
| Installed pip consistency | exit 0, no broken requirements | evidence/pip-check.txt |

Property counts total 5544 per suite (both suites repeat the same domains, not
11088 distinct states). Mask property has 27 subset pairs ×8 raw values ×7 requests.
The fixed oracle JSON was expanded with literal supplied data while core.py was
absent, then frozen with a byte SHA256 receipt. It is tracked with -text to preserve
original bytes across checkout platforms. Receipts establish local binding, not
trusted timestamp authentication. Source/test/verifier hashes are in evidence/source-hashes.json.

Cases cover later same-GID named-group success, split denial/repaired positive,
owner/named/group no fallback, mask requirements/optional basic mask, unmasked
owner/other, GID zero, primary/supplementary overlaps, reverse ordering and no input
mutation. Admission covers trailing malformed ACL behind owner/root/unknown gates,
strict builtin/cycle/custom-key/type/enum/duplicate/range/cardinality handling and
JSON bounds. Capability guards are executed after preimporting the trusted harness;
source inspection confirms core imports only json/re. They are focused checks,
not proof of an OS isolation boundary.

Accepted reports cannot naturally reach 64 KiB. Exact-cap/over-cap formatter tests
use trusted oversized synthetic internal dictionaries; output-limit CLI checks patch
the serializer. A tiny patched formatter budget raises a trusted error rather than
recursing. Depth-six wrong-schema and ten-character integer examples are parser
seams, not accepted ACL records. The feature list cap16 exceeds the eleven unique
valid labels; a 17-element case tests the cap before duplicate checking. No misleading
accepted-input/reachable-output-cap claim is made.

Local prepared CI includes main push/PR/manual tests and Bandit, and weekly/manual
CodeQL with full reviewed immutable SHA pins, minimal permissions and persisted
checkout credentials disabled. Reused same-day official release bindings from the
previous approved lab: checkout v7.0.1 / 3d3c42e5aac5ba805825da76410c181273ba90b1;
setup-python v7.0.0 / 5fda3b95a4ea91299a34e894583c3862153e4b97; CodeQL v4.38.2 /
2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 (peeled commit). The YAML verifier checks
pins/triggers/permissions, not GitHub execution or every possible workflow behavior.
Existing scanner pins are not a hash-verified lockfile or verified advisory inventory.

Unverified/outside scope: Linux/other runtimes, actual host access/ACLs/identity/context,
upstream test execution, direct upstream split-group test coverage, hosted checks,
CodeQL execution/eligibility, remote repo protections, secret scanning/push protection,
full supply-chain/advisory/security audit and hard process resource isolation. Existing
prior-project limits persist. No publication, push, merge or deployment was performed.
