# Linux access-ACL research — October 5, 2026

Research/planning only, coordinator02:56 selection under Jake's verified direct
successor mandate. No implementation, host ACL/identity/path inspection, permission
experiments, upstream installation/execution, new repository or publication.

## Existing work and alternative

Read vault Home/Codex Integration/Linux File Modes and Directory Access and relevant
prior creation-mask/ordinary permission records. Focused local/vault filename and
content searches found deferred ACL references, not an implemented normalized Linux
access evaluator. Existing container policy/application RBAC use different contexts;
previous actual source comparison retained in permission-lab research. Bounded
searches are not an exhaustive inventory. Reuse strict input/report/CLI/workflow
harness patterns only after approval; leave prior projects/shared helpers unchanged.

Access ACL adds named identities and a mask distinct from ordinary triplets and
creation masks. Sticky-directory entry checks remain a valid alternate but need
parent write/search, owners and capability exceptions; more overlap with prior
access model and no direct lesson in ACL precedence. Recommend original stdlib
access-ACL evaluator, not native ACL manipulation or default-ACL inheritance.

## Primary semantics and key uncertainty

[acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html) requires owner/group/other
entries, unique named qualifiers, and a mask when named entries exist; mask is
optional otherwise. Owner/other are unmasked. Named-user/group classes are masked.
Access and default ACLs differ; Windows/NFSv4 ACL behavior is not this contract.
Combined requests must be contained by one matching group entry plus mask; a
matching group prevents falling back to other even if it cannot satisfy the request.

Actual [Linux posix_acl_permission](https://github.com/torvalds/linux/blob/master/fs/posix_acl.c)
read through connected source, blob18b302f941743bf5d22ee001d4f111f83936767c:
owner uses filesystemUID, then matching named user goes directly to mask. Group
matches set found; each entry individually checks all want bits before mask. ACL_OTHER
denies if any group matched. Thus split group permissions4 and2 cannot authorize
combined6. A later matching group entry that independently covers6 can succeed;
first-match denial is incorrect. Kernel uses mapped VFS IDs/current_fsuid/group
membership; use supplied fictional fsuid/fsgid/supplementary IDs under identity-map
assumption, not an assertion that effective/real IDs always equal them. Rich policy
and capability checks exist outside this helper. No real authorization claim.

The mask bounds group-class entries; it is not permission union for a request.
pylibacl's calc_mask creates a union mask for ACL construction, a different operation
from checking access with an explicitly supplied existing mask. Never auto-calculate
a missing mask in this evaluator. Named-user matches and owner matches deny without
falling back to groups/other. Owning group and named group with the same numeric GID
are separate entry types; named qualifiers are unique within their own types.

## Connected candidate/source review

**Linux**: actual permission helper above, SPDXGPL2-only and earlier same-day kernel
COPYING/syscall-note review. Observed relevant path history August17,2026 merge
1c3e8cef79ea5f1415cff0d3c507e2e07b71ade8, not whole-source snapshot attestation.
Kernel inode/group/ACL/idmap dependencies unsuitable for pure Python adoption;
no kernel code copied/compiled/run or broad kernel CI/security assessment.

**[LTP ACL tests](https://github.com/linux-test-project/ltp/tree/master/testcases/kernel/fs/acl)**:
connected inventory and full source inspected:
- acl_mask01.c db089d41ee3b612f343e26b90e09e44b805f7815: named user/named group/
  owning-group permissions granted with mask7 and denied with mask0.
- acl_other01.c129384d8952aeca7d8781ac58e311ba73db04e36: other unaffected by mask0.
- acl_user_obj01.c f2478520a94b38baf6fc3042aa4fbbfc53f75cb5: owner control independent
  of group/other and real ACL replacement after restrictive mode.
- acl_file_ops01.c e532a675f22c14a2b1439bc8b62007f1b4f546a4: real chmod/chown/ACL
  interaction, outside evaluation scope.
All GPL2-or-later headers. These create/change owners/ACLxattrs, mount filesystems,
require root and sometimes fork credentials; absolutely not run in this workspace.
Earlier same-day actual GPL COPYING/INSTALL/ci dependency and full Docker workflow
review in creation-mask-lab/RESEARCH applies: C/libc/kernel headers/autotools and
optional native libs, mutable Actions/container tags/privileged test containers.
No copying that execution/CI baseline. Latest observed repository commit October1
2026 dca9f0d272b2923256852fc37abd222b533d91e0. Relevant filesystem expansion issue1309
is a proposal, not executed coverage evidence. No direct split-permissions combined-
group case was found in inspected ACL directory/source/search results; do not claim
upstream test validation of that exact case. Kernel algorithm and man-page rule
support planned hand-derived counterexample; future synthetic tests are local only.

**[pylibacl](https://github.com/iustin/pylibacl)** strongest Python candidate:
connected README0.7.3 (1b85c1e4280dac9fdf4475d272d7e8e92e22b8ab), actual acl.c
9053f480105030a0c6af6ab91a9b3a683b11c0cd around valid/applyto/calc_mask, actual
test_acls.py3557b48c6e1139487f1518dc9741939226473f27 entry/duplicate validity and
expected-failure excerpts, setup6a2bbf6ae2d257326e526c1a50e808953fe42236, CI
4f1a5b519d2763233170bed34678cfeaec26ea80 and COPYING5ab7695ab8cabe0c5c8a814bb0ab1e8066578fbb
reviewed. C extension calls libacl for validation/calculated masks and real file/
descriptor ACL application. Linux requires native libacl development/build setup,
plus setuptools; CI pytest/Sphinx/docs and several Python/PyPy versions through3.14.
Mutable Actions and unpinned pip/apt packages; no reuse of that configuration.
LGPL2.1-or-later notices/library license require retention/assessment if adopted;
no native source adopted, built, installed or run. It is not the needed pure
supplied-subject evaluator, and Windows environment is not its intended Linux path.

History returned latest two commits September14,2025, latest434f4a1dc4cdb1e4e346bf51f996b42f9673c2e8,
doc fixes. Does not establish abandonment/safety. SECURITY.md provides private
reporting guidance but no guaranteed supported-version SLA. Open issue34 discusses
text syntax/upstream behavior; allegations not independently validated and not
a security finding. Other returned issues concern docs/IOError naming. No exhaustive
issue/advisory/Scorecard review or upstream CI success claim. Actual tests include
xfail entry-deletion/invalid-source behavior, not proof of evaluator correctness.

Primary upstream libacl permissions-test URL on Savannah was inaccessible through
web tool; discovered GitHub mirrors not assessed/adopted. This failure does not
invalidate successfully read kernel/LTP/pylibacl sources, but direct combined-group
test coverage remains unavailable. Connected GitHub searches/file/metadata calls
above succeeded; primary man-page/public source browsing corroborated.

Recommendation: **build** original bounded stdlib normalized model after approval.
No suitable adoption/fork in searches performed; original arithmetic/source-linked
oracles with explicit source credit, no borrowed upstream code or runtime dependency.

## Local-first and scope evidence

One installed loopback Ollama qwen3.5:2b bounded ideas draft30s/260tokens cap completed
~1.49s/144tokens, helperexit0/stop. Raw retained separately. Reject statements that
owner/group match grants immediately or defaultACL ignored; they omit requested bits
and exclusions. Correct multi-group/mask reminders merely repeat brief and are
source-corroborated independently; no raw draft/code adopted as correctness oracle.
Remote free OpenRouter considered but current startup degraded/unverified; refreshing
excluded shared tooling out of scope. No remote inference/paid fallback/retry or
new spending. Codex retains source judgment and plan drafting.
