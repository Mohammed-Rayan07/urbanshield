"""Sentinel agent: advisory -> quarantined ``Advisory`` -> matched devices. Owner: C.

The raw text is stored in the run under its SHA-256 and handed to exactly one tool,
``quarantine_extract`` (one tool-less LLM call). Everything after that works on the typed
``Advisory``: a cross-check against the pinned feed and a deterministic inventory match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from urbanshield.agents import tools
from urbanshield.agents.tools import RunContext
from urbanshield.guard.quarantine import flag_spans, sha256_text
from urbanshield.schemas import Advisory, AgentName, City, EventKind, Match

Decision = Literal["escalate", "monitor", "needs_approval"]
_VERSION = re.compile(r"^\d+(\.\d+)*$")


@dataclass(frozen=True)
class SentinelResult:
    advisory: Advisory
    matches: list[Match]
    discrepancies: list[str]
    decision: Decision


def parse_version(text: str) -> tuple[int, ...] | None:
    """``"4.1.3"`` -> ``(4, 1, 3)``; anything that is not dotted digits -> None."""
    text = text.strip()
    return tuple(int(p) for p in text.split(".")) if _VERSION.match(text) else None


def version_below(version: str, bound: str) -> bool:
    """Numeric dotted-version compare, missing parts count as 0 (``4.2 == 4.2.0``).
    Unparseable versions never match, so a malformed range cannot widen the match."""
    a, b = parse_version(version), parse_version(bound)
    if a is None or b is None:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) < b + (0,) * (width - len(b))


def match_inventory(city: City, advisory: Advisory) -> list[Match]:
    """Deterministic matcher: same firmware family and version below ``affected_below``,
    or the CVE already listed on the device."""
    family = advisory.firmware_family.casefold()
    matches = []
    for device in city.devices:
        dev_family, _, dev_version = device.firmware.partition("/")
        if dev_family.casefold() == family and version_below(dev_version, advisory.affected_below):
            matches.append(
                Match(device_id=device.id, cve_id=advisory.cve_id, reason="firmware_family_and_version")
            )
        elif any(v.cve_id == advisory.cve_id for v in device.vulns):
            matches.append(Match(device_id=device.id, cve_id=advisory.cve_id, reason="cve_listed"))
    return matches


def run_sentinel(ctx: RunContext, raw_text: str) -> SentinelResult | None:
    """Quarantine, cross-check and match one advisory; emit the Sentinel's events.
    Returns None (after an ERROR event) when the text cannot be reduced to an ``Advisory``."""
    sha = sha256_text(raw_text)
    ctx.untrusted[sha] = raw_text
    spans = flag_spans(raw_text)
    note = f"; {len(spans)} passage(s) look like instructions to an AI" if spans else ""
    ctx.event(
        AgentName.SENTINEL,
        EventKind.OBSERVE,
        f"Advisory received and quarantined (sha256 {sha[:12]}){note}",
        {"source_sha256": sha, "flagged_spans": spans, "chars": len(raw_text)},
    )
    try:
        extracted = tools.call(ctx, AgentName.SENTINEL, "quarantine_extract", {"text_sha256": sha})
    except ValueError as exc:
        ctx.event(
            AgentName.SENTINEL,
            EventKind.ERROR,
            f"Quarantine rejected the extractor output ({exc}); nothing was passed on",
            {"source_sha256": sha},
        )
        return None
    advisory = Advisory.model_validate(extracted.result["advisory"])
    fields = advisory.model_dump(exclude={"source_sha256"})
    checked = tools.call(ctx, AgentName.SENTINEL, "cross_check", fields)
    matched = tools.call(ctx, AgentName.SENTINEL, "match_inventory", fields)
    discrepancies: list[str] = checked.result["discrepancies"]
    matches = [Match.model_validate(m) for m in matched.result["matches"]]

    decision: Decision
    if discrepancies:
        decision = "needs_approval"
        summary = (
            f"{advisory.cve_id}: {len(discrepancies)} discrepancies with the pinned feed → needs approval"
        )
    elif matches:
        decision = "escalate"
        summary = f"{advisory.cve_id}: {len(matches)} devices affected → escalate to the Analyst"
    else:
        decision = "monitor"
        summary = f"{advisory.cve_id}: no device in the inventory is affected → monitor"
    ctx.event(
        AgentName.SENTINEL,
        EventKind.DECISION,
        summary,
        {
            "decision": decision,
            "advisory": advisory.model_dump(),
            "matches": [m.model_dump() for m in matches],
            "discrepancies": discrepancies,
            "cites": [extracted.id, checked.id, matched.id],
        },
        tool_call_id=matched.id,
    )
    return SentinelResult(advisory=advisory, matches=matches, discrepancies=discrepancies, decision=decision)
