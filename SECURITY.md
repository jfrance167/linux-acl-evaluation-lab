# Security model

This lab evaluates supplied normalized access-ACL predicates for invented subjects.
It does not grant or validate real access. Treat model_permits as a conditional
arithmetic/selection result; actual_access and actual_acl remain unverified.

Assets are correct selection/mask explanations, strict admission, honest incomplete
statuses and absence of ambient capabilities. Untrusted supplied bytes/objects may
be malformed, oversized, coercive, ambiguous or falsely claim ordinary context.
Exact builtin types, finite identifiers/context, scalar/cardinality/byte/depth/token
bounds, duplicate rejection and whole-common-record validation mitigate admission
and explanation errors. No reflected invalid values are included in error reports.
Owner/named-user/group precedence and one-entry containment prevent false model
grants caused by fallback/union errors. The fixed unverified claims avoid treating
declared inputs as verified host state.

The pure core uses json/re only. CLI reads stdin and writes escaped JSON stdout;
trusted demos use packaged data. There are no user-controlled file paths, network,
host identity/ACL lookups or permission changes. Forbidden-call tests complement
source review; they do not constitute an OS sandbox or exhaustive capability proof.
API records must be stable while evaluated; hostile concurrent mutation is outside
the model. Admission is bounded, not a hard RSS/time containment boundary.

Root fsuid, richer platform policies, default inheritance, descriptors, ancestor
traversal, races, filesystem semantics and real access tests are excluded. All
specified unsupported records still validate common fields before exclusions.
Unknown versions/profiles are unsupported current-schema records, not authorization
to interpret a future schema. Unsupported/malformed/over-limit results have no partial
grant/checks. CLI I/O failure may leave partial output; no atomic-delivery claim.

Evidence is local Windows CPython only; no Linux/live/upstream test execution, hosted
CI/CodeQL, full advisory audit, dedicated secret scanner or hash-verified dependency
installation. Before any integration into an enforcement system, independently
review the threat model, actual platform semantics, trusted identities and policy
boundaries. This release is a local teaching artifact, not such an integration.

Potential defects should be kept private until an appropriate reporting route is
established; this local-only project has no public security contact/SLA.
