"""Quarantine for untrusted advisory text (prompt-injection defence). Owner: C.

Structural guarantee: raw advisory text is only ever seen by one LLM call with **no
tools**, whose output must parse as an ``Advisory`` (no free-text field). Downstream
agents receive the typed object, never the text. Then:

1. ``cross_check`` compares the extracted fields with the pinned feed record for the
   same CVE; any disagreement is flagged and the match needs human approval.
2. No ``Advisory`` field can change device or plan state; it can only trigger a re-score.

Detection of suspicious phrases is a UI nicety, not the defence.
"""

from __future__ import annotations

import hashlib

from urbanshield.schemas import Advisory

SUSPICIOUS_MARKERS = (
    "ignore previous",
    "ignore all",
    "system prompt",
    "you are now",
    "mark all",
    "disregard",
)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def flag_spans(raw_text: str) -> list[tuple[int, int]]:
    """Character spans that look like instructions to an AI (shown highlighted in the UI).
    Each span runs from a marker to the end of its sentence."""
    lowered = raw_text.lower()
    spans: list[tuple[int, int]] = []
    for marker in SUSPICIOUS_MARKERS:
        start = lowered.find(marker)
        while start != -1:
            end = min((i for i in (lowered.find(c, start) for c in ".\n") if i != -1), default=len(raw_text))
            spans.append((start, end))
            start = lowered.find(marker, end)
    return _merge(sorted(spans))


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    return merged


def quarantine_extract(raw_text: str) -> Advisory:
    """Single tool-less LLM call -> validated ``Advisory``. Raise ``ValueError`` if the
    model output does not validate."""
    raise NotImplementedError


def cross_check(advisory: Advisory) -> list[str]:
    """Human-readable discrepancies against the pinned feed (empty list = consistent)."""
    raise NotImplementedError
