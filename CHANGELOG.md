# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-08-23

First release. The DB-API surface, the policy engine, and `dataweir scan`.

### Added

- `guard()` wraps any PEP 249 connection: policy is evaluated before each
  statement reaches the database, and rows are counted as they come back.
- Deny-by-default policy model — grants over tables, operations and columns,
  with per-grant row ceilings and per-session/per-minute budgets.
- Real SQL analysis via `sqlglot`: joins, subqueries, set operations, wildcard
  projections and stacked statements are all seen for what they are.
- Seventeen controls (`DW001`–`DW017`), each mapped to the OWASP Top 10 for
  Agentic Applications.
- Volume-anomaly detection against a per-query-shape baseline (Welford).
- Detection of instruction-shaped text in returned rows.
- Three modes: `monitor` (records only, changes nothing), `warn`, `enforce`
  (blocks, and caps oversized reads by injecting a `LIMIT`).
- Hash-chained JSONL audit log with `dataweir audit verify`.
- `dataweir scan` — twelve static policy checks and fourteen attack probes,
  offline and CI-friendly, with JSON output and severity-based exit codes.
- CLI: `scan`, `policy init|validate`, `audit verify|tail|summary`, `controls`.

[Unreleased]: https://github.com/skv-se/dataweir/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/skv-se/dataweir/releases/tag/v0.1.0
