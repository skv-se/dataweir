"""`dataweir scan` — red-team your own policy before an agent does.

Two passes, both offline and both safe to run in CI:

* **static** reads the policy document and reports the ways it is too generous
  (wildcard grants, missing row ceilings, auditing switched off).
* **probes** submit a battery of data-access attacks through the real policy
  engine and check that it refuses them. Nothing touches a database — the
  probes exercise the decision path, which is the thing that has to be right.

Every finding carries a ``DW``/``DWS`` control code and a mapping to the OWASP
Top 10 for Agentic Applications.
"""

from __future__ import annotations

from .findings import ScanFinding, ScanReport
from .probes import PROBES, Probe, run_probes
from .runner import run_scan
from .static import STATIC_CHECKS, run_static

__all__ = [
    "PROBES",
    "STATIC_CHECKS",
    "Probe",
    "ScanFinding",
    "ScanReport",
    "run_probes",
    "run_scan",
    "run_static",
]
