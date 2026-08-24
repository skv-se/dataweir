"""Exceptions raised by dataweir."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .decision import Decision


class DataweirError(Exception):
    """Base class for every dataweir error."""


class AccessDenied(DataweirError):
    """A data operation was refused by policy.

    Carries the full :class:`~dataweir.decision.Decision` so callers can log the
    codes, tell the agent why, or surface remediation to a human.
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        codes = ", ".join(decision.codes) or "policy"
        super().__init__(f"dataweir blocked this operation [{codes}]: {decision.reason()}")


class BudgetExceeded(AccessDenied):
    """A cumulative session or rate budget was exhausted."""


class ResultTruncated(DataweirError):
    """A result set was cut short because it exceeded its row ceiling.

    Raised only when ``on_overflow="raise"``; the default is to truncate.
    """

    def __init__(self, limit: int, decision: Decision | None = None) -> None:
        self.limit = limit
        self.decision = decision
        super().__init__(f"result truncated at the {limit}-row ceiling")
