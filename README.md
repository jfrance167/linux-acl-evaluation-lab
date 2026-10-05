# Linux Access ACL Evaluation Lab

Explain Linux access-ACL selection using invented filesystem IDs and normalized
records. The model shows why an owner or named-user match does not fall back,
why ACL masks affect named users and groups, and why matching groups cannot pool
split permission bits for one combined request. It reports a completed predicate
decision or an explicit rejected, unsupported or over-limit outcome.

**Actual host access and actual ACLs are always unverified.** This is an offline
learning model, with no host ACL, identity, file permission or path inspection.

## Run

Python 3.13, standard library only. From this project directory:

```powershell
python -m acl_lab demo
python -m unittest discover -s tests -v
python -O -m unittest discover -s tests -v
python tools/check_mutations.py
```

The demo checks thirteen independently fixed full reports. To analyze a supplied
record, pipe UTF8 JSON into `python -m acl_lab analyze`. For example:

```powershell
python -c "import json; from acl_lab.fixtures import request; print(json.dumps(request(group=4)))" | python -m acl_lab analyze
```

Exit codes: 0 model permit / passing demo; 1 model deny / failing demo;
2 rejected, unsupported or over limit; 3 input/output failure. Both permit and deny
are completed model decisions. Short writes and failed flushes are errors; stdout
delivery is not atomic. All output is escaped bounded JSON, never terminal prose
containing untrusted fields.

## Example

An invented subject matches group 20 with read (`4`) and group 30 with write (`2`).
With mask `6`, a read+write request (`6`) is denied: neither individual entry
contains both bits. Replacing group 20's permissions with `6` permits the model
request. A later matching entry with `6` also succeeds even if an earlier entry
only has `4`. These are hand-derived synthetic outcomes, not executed Linux calls.

## Architecture and contract

`acl_lab/core.py` validates exact builtin records, copies bounded normalized data,
evaluates precedence/masks and decodes strict bounded JSON. It imports only json
and re. `acl_lab/__main__.py` handles bounded stdin/stdout and trusted fixture demos.
`acl_lab/fixtures.py` contains the fixed independent data, also frozen as full
JSON in `fixtures/oracles.json` before core implementation. Tests never use the
evaluator to manufacture expected outputs.

The API is `evaluate(record) -> dict` or `analyze_json(raw_bytes) -> dict`.
`serialize_report` is for trusted internally constructed reports, not arbitrary
object ingestion. [CONTRACT.md](CONTRACT.md) defines exact schema, ordering, status,
mask-null provenance, finite property domains and error reasons; [PLAN.md](PLAN.md)
contains the research plan and approved scope.

Required root keys: version, profile, subject, object, request_bits, context.
The supported profile is version 1 / linux_access_acl_v1. Subject declares fsuid,
fsgid and supplementary_gids; object declares id, kind, owner_uid, owning_gid and
acl. ACL keys are owner, users, group, groups, mask, other. Permissions are integers
0..7; request_bits is 1..7. Named users/groups require an explicit non-null mask;
a basic ACL may omit its effect using mask=null or supply a restricting mask.
No mask is automatically calculated. Object IDs are labels, never paths.

Owner → named user → independently checked matching group entries → other.
Owner/other are unmasked; a matched but insufficient owner/named user/group denies
without falling back. Owning-group and named-group entries can share the same GID,
remaining distinct entries. All matching groups appear in deterministic explanations.
Bit 1 is an execute-bit predicate for regular files and a search-bit predicate for
directories. Root fsuid is unsupported; GID zero is an ordinary group.

Input cap 16 KiB; JSON depth 6; numeric tokens 10 characters; IDs 0..999999999;
16 supplementary GIDs; eight named entries per type. Identifiers are bounded ASCII.
Only finite declared context values are admitted. Duplicate keys/qualifiers, floats,
booleans, custom types, cycles and unknown fields are rejected. Every common field
is validated before exclusions, including trailing ACL entries after an owner match.
Output cap 64 KiB including LF. Accepted reports cannot naturally reach the output
cap; trusted oversized formatter and patched CLI tests are explicitly labeled seams.

## Security and limits

See [SECURITY.md](SECURITY.md). IDs and ACL/context records are caller declarations;
identity mapping and their truth are unverified. No root/capability/LSM/mount/idmap/
namespace/default ACL inheritance/Windows/NFSv4/sticky/descriptors/ancestor traversal
or full-system authorization is modeled. No native library, subprocess, network,
chmod/chown/getfacl/setfacl or user/permission experiment is performed by the model.
Resource admission bounds do not establish hard process memory/time isolation.

## Verified results

On Windows CPython 3.13.7: 32 tests pass normally and with `-O`; thirteen fixed demos
pass in both modes; 5544 finite property comparisons per suite; all three injected
logic faults produce assertion failures, zero harness errors and restored passes.
Compilation, installed-environment `pip check`, local YAML/pin/permission checks
and installed Bandit 1.9.4 pass. Bandit scanned application/tools: zero findings,
zero scan errors, zero exclusions. Native closed-pipe/help failures now exit 3,
with checked diagnostic flush and both dirty output sinks detached before shutdown.
Each suite includes 26 child processes: 14 native-pipe/healthy controls and 12 labeled
synthetic short-write/dirty-flush seams in real interpreters, normal and optimized.
[VERIFICATION.md](VERIFICATION.md) binds receipts
and limitations; [REVIEW.md](REVIEW.md) records the implementing agent's ECC self-review.
Linux, other runtimes and hosted Actions/CodeQL have not been run.

Prepared GitHub workflows pin reviewed full action commits, use minimal permissions,
disable persisted checkout credentials and include tests/Bandit and weekly/manual
CodeQL. No remote repository exists for this lab. Hosted eligibility, protections,
secret scanning, current advisory coverage and artifact-hash locks remain unverified;
no new dependencies were installed. Security-tool pins match the installed tested
environment and are not proof of supply-chain safety.

## Sources, license and learning

[acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html), actual
[Linux ACL evaluator](https://github.com/torvalds/linux/blob/master/fs/posix_acl.c),
[LTP ACL tests](https://github.com/linux-test-project/ltp/tree/master/testcases/kernel/fs/acl)
and [pylibacl](https://github.com/iustin/pylibacl) were inspected as references.
[RESEARCH.md](RESEARCH.md) records source blobs, licenses, maintenance, dependency/CI
assessment and retrieval gaps. Native upstream code/tests were neither copied nor
executed. The bounded search found no direct upstream split-group combined-request
test; that case is source-derived, locally tested and not live-confirmed.

Original code is MIT, copyright jfrance167. Reused same-author local JSON/CLI/workflow
patterns are attributed in DECISIONS.md. AI assistance: Codex researched, implemented,
self-reviewed and tested; one local Ollama ideas draft was rejected as a correctness
oracle. No remote worker inference or paid fallback. [LEARNING.md](LEARNING.md) captures
the main distinctions. Optional exercise: explain why changing only `other` cannot
repair a denial after a group match.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
