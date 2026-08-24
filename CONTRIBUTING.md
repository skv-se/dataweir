# Contributing

Thanks for looking. This project is young, and the most useful contributions
right now are the unglamorous ones: real policies that break it, SQL dialects it
parses wrong, and controls that fire when they shouldn't.

## Setup

```bash
git clone https://github.com/skv-se/dataweir && cd dataweir
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest
ruff check .
ruff format .
mypy src/dataweir
```

## What's most wanted

**A statement dataweir gets wrong.** If a query is blocked that shouldn't be, or
sails through that shouldn't, that is the highest-value issue you can file.
Include the SQL, the dialect, the policy, and what you expected. A failing test
in `tests/test_analyze.py` or `tests/test_engine.py` is even better.

**A dialect we handle badly.** v0.1 is tested hardest against SQLite and
Postgres syntax. MySQL, SQL Server, Snowflake, BigQuery and Databricks all have
corners that will surprise the analyzer.

**A driver that doesn't wrap cleanly.** `guard()` aims to be a transparent PEP
249 proxy. If a driver's cursor does something the wrapper mishandles, that's a
bug worth reporting even without a fix.

**A probe we're missing.** `dataweir scan` should catch every plausible way an
agent over-reaches at the data layer. If you can think of one that isn't in
`src/dataweir/scan/probes.py`, open an issue — a probe with an expected control
code is a small, self-contained PR.

## Adding a control

Controls are a public interface: their codes appear in audit logs, scan reports
and people's alerting rules. So:

1. Add it to `CONTROLS` in `src/dataweir/controls.py` with a **new** code — never
   reuse or repurpose an existing one.
2. Map it to the relevant OWASP Agentic Top 10 item(s).
3. Write a remediation line that says what to change, not what went wrong.
4. Add tests for both the firing case and a near-miss that must *not* fire.
5. Add the row to the control table in `README.md`.

False positives are worse than misses here. A guardrail people mute is a
guardrail that protects nothing.

## Pull requests

- One change per PR.
- Tests for anything behavioural. `pytest --cov=dataweir` should not drop below 85%.
- `ruff check .` and `ruff format --check .` clean.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- Public functions get docstrings that explain *why*, not just *what*.

Don't worry about squashing or perfect commit messages — that gets sorted on
merge.

## Security issues

Please don't open a public issue for a vulnerability in dataweir itself. See
[SECURITY.md](SECURITY.md).

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Contributions are accepted under the Apache License 2.0, the same license as the
project.
