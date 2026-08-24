# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://github.com/skv-se/dataweir/security/advisories/new)
on this repository. Do not open a public issue.

Include what you can: the version, a policy and statement that reproduce it, and
what an attacker gets out of it. You'll get an acknowledgement within 72 hours
and an assessment within a week. Once a fix ships you'll be credited in the
advisory unless you'd rather not be.

## What counts as a vulnerability here

dataweir is a security control, so the interesting bugs are the ones that make it
fail *open*:

- A statement that reaches data the policy denies — through a dialect quirk, a
  parser gap, an encoding trick, or a construct the analyzer does not model.
- A way to exceed a row ceiling or session budget without a finding.
- Audit records that can be altered, dropped or reordered without breaking the
  hash chain.
- A crash in the guardrail that leaves the underlying connection usable but
  unguarded.
- Sensitive data written into the audit log despite `redact_params: true`.

Please report those privately.

## What is a known limitation, not a vulnerability

These are documented properties of the design. Reports are still welcome as
issues — just not as security advisories:

- **The audit log is tamper-evident, not tamper-proof.** Someone who can rewrite
  the whole file can re-chain it. Ship records off-host if you need more.
- **Monitor mode does not block.** That is what it is for.
- **Post-execution controls report, they do not prevent.** Row counts, volume
  anomalies and content inspection are only knowable once rows exist. By then
  the database has produced them.
- **dataweir guards the connections you route through it.** An agent holding a
  second, unguarded handle to the same database is outside its reach. Enforce
  that at the database with a restricted role as well; dataweir is defence in
  depth, not a substitute for database permissions.
- **`inspect_results` is a heuristic.** Pattern matching on returned text catches
  the obvious cases. It will not catch a careful attacker, and it is not a
  content filter.

## Supported versions

While the project is pre-1.0, fixes land on the latest minor release only.

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |
