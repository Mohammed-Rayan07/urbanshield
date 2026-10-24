"""Rule-based stand-in for the LLM (``LLM_MODE=mock``). Owner: C.

Each call site (``task``) has a deterministic responder written with regexes and simple
heuristics. Mock runs need no key and no network (CI uses them) and are labelled "mock"
everywhere they are shown. They are a stand-in for the plumbing, not evidence about agents:
agent numbers in EVALS.md come from live or replayed runs only.

Responders read only what the real model would see in ``messages``, so the prompts are
exercised too. Tool-call ids are ``call_<step>_<i>``; token counts are estimated as
characters / 4; latency is 0.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from urbanshield.agents.llm import LLMResponse, Tier, ToolCallRequest
from urbanshield.schemas import LLMUsage

Responder = Callable[[list[dict[str, Any]]], tuple[str | None, list[ToolCallRequest]]]


def _text(messages: list[dict[str, Any]], role: str) -> str:
    return "\n".join(str(m.get("content") or "") for m in messages if m.get("role") == role)


def _first(pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> str:
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else ""


# --------------------------------------------------------------------------- sentinel.extract


def _extract(messages: list[dict[str, Any]]) -> tuple[str | None, list[ToolCallRequest]]:
    """Advisory fields by regex. The first statement of each field wins, like a careful reader."""
    text = _first(r"<advisory>\n(.*)\n</advisory>", _text(messages, "user"), re.DOTALL)
    vendor = _first(r"^\s*(?:vendor|manufacturer)\s*:\s*([^\n.,;]+)", text)
    family = (
        _first(r"firmware family\s*:\s*([a-z][\w-]*)", text)
        or _first(r"affected firmware\s*:\s*([a-z][\w-]*)", text)
        or _first(r"\b([a-z][\w-]*) firmware\b", text)
        or vendor
    )
    fields = {
        "cve_id": _first(r"\b(CVE-\d{4}-\d{4,})\b", text),
        "vendor": vendor,
        "product": _first(r"^\s*(?:product|model)\s*:\s*([^\n.,;]+)", text),
        "firmware_family": family.lower(),
        "affected_below": _first(
            r"(?:prior to|before|below|earlier than|<)\s*(?:version\s*)?v?(\d+(?:\.\d+){0,3})", text
        ),
        "cvss": _first(
            r"CVSS(?:\s*v\d(?:\.\d)?)?(?:\s*base)?(?:\s*score)?\s*[:=]?\s*(\d{1,2}(?:\.\d)?)", text
        ),
    }
    return json.dumps(fields, sort_keys=True), []


# --------------------------------------------------------------------------- analyst.step


def _calls(messages: list[dict[str, Any]], wanted: list[tuple[str, dict[str, Any]]]) -> list[ToolCallRequest]:
    step = sum(1 for m in messages if m.get("role") == "assistant")
    return [ToolCallRequest(id=f"call_{step}_{i}", name=n, arguments=a) for i, (n, a) in enumerate(wanted)]


def _tool_results(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Successful tool results the loop sent back: ``{"tool", "tool_call_id", "result"}``."""
    out = []
    for m in messages:
        if m.get("role") == "tool":
            body = json.loads(m["content"])
            if "tool_call_id" in body:
                out.append(body)
    return out


def _user_json(messages: list[dict[str, Any]]) -> dict[str, Any]:
    text = next(str(m["content"]) for m in messages if m.get("role") == "user")
    return json.loads(text[text.index("{") :])


def _analyst(messages: list[dict[str, Any]]) -> tuple[str | None, list[ToolCallRequest]]:
    """Scripted investigation: blast radius + reachability, then one simulation, then decide."""
    affected = [a["device_id"] for a in _user_json(messages)["affected"]]
    results = _tool_results(messages)
    done = {r["tool"] for r in results}
    if not done:
        wanted = [("blast_radius", {"device_id": d}) for d in affected]
        return None, _calls(messages, [*wanted, ("bfs_reach", {"sources": affected})])
    if "simulate" not in done:
        return None, _calls(messages, [("simulate", {})])
    corridor = any(r["result"].get("corridor_reached") for r in results if r["tool"] == "bfs_reach")
    critical = any(r["result"].get("critical_lost") for r in results if r["tool"] == "blast_radius")
    recommendation = "replan" if corridor or critical else "contain" if affected else "monitor"
    answer = {"recommendation": recommendation, "tool_call_ids": [r["tool_call_id"] for r in results]}
    return json.dumps(answer, sort_keys=True), []


# --------------------------------------------------------------------------- planner


_KIND_WORDS = {
    "segment": ("segmentation", "segmenting", "segment"),
    "patch": ("patching", "patches"),
    "disable_remote": ("remote disable", "disabling remote access", "disable remote"),
    "rotate_creds": ("credential rotation", "rotating credentials", "rotate creds"),
    "virtual_patch": ("virtual patching", "virtual patches"),
}
_UNITS = {"lakh": 100_000, "lakhs": 100_000, "l": 100_000, "crore": 10_000_000, "k": 1_000, "": 1}


def _constraints(messages: list[dict[str, Any]]) -> tuple[str | None, list[ToolCallRequest]]:
    """Operator phrases by regex. Names are copied as written; validation is the code's job."""
    text = _first(r"<operator>\n(.*)\n</operator>", _text(messages, "user"), re.DOTALL)
    rows: list[dict[str, Any]] = []
    if re.search(r"\bno\b[\w -]{0,30}\bdowntime\b", text, re.IGNORECASE):
        zone = _first(r"downtime (?:in|for|across) ((?:zone )?[\w-]+(?: \d+)?)", text) or _first(
            r"((?:zone )?[\w-]+(?: \d+)?) (?:festival|event|parade|closure)", text
        )
        if zone:
            rows.append({"kind": "no_downtime_zone", "params": {"zone": zone}})
    for device in re.findall(r"must (?:fix|patch|protect) (d-\d+)", text, re.IGNORECASE):
        rows.append({"kind": "must_fix", "params": {"device_id": device}})
    lowered = text.lower()
    for kind, words in _KIND_WORDS.items():
        if any(f"no {w}" in lowered or f"don't use {w}" in lowered for w in words):
            rows.append({"kind": "forbid_control", "params": {"kind": kind}})
    budget = re.search(
        r"budget[^\d₹]{0,20}₹?\s*([\d,]+(?:\.\d+)?)\s*(lakhs?|l|crore|k)?\b", text, re.IGNORECASE
    )
    if budget:
        amount = float(budget.group(1).replace(",", "")) * _UNITS[(budget.group(2) or "").lower()]
        rows.append({"kind": "budget", "params": {"inr": int(amount)}})
    hours = _first(r"(\d+(?:\.\d+)?)\s*(?:h|hours?)\b(?: of)?(?: total)? downtime", text)
    if hours:
        rows.append({"kind": "downtime", "params": {"hours": float(hours)}})
    return json.dumps({"constraints": rows}, sort_keys=True), []


def _claims(messages: list[dict[str, Any]]) -> tuple[str | None, list[ToolCallRequest]]:
    """Exact claims copied from the compare result. The mock never invents a wrong number,
    so Auditor rejections in mock runs only come from the code paths, never staged."""
    source = _user_json(messages)
    result = source["result"]
    a, b = result["plans"][result["a"]], result["plans"][result["b"]]
    claims = [
        {
            "metric": m,
            "plan_a": a[m],
            "plan_b": b[m],
            "delta": b[m] - a[m],
            "tool_call_id": source["tool_call_id"],
        }
        for m in ("cvar", "mean_loss", "max_cascade")
        if m in a and m in b
    ]
    return json.dumps({"claims": claims}, sort_keys=True), []


# --------------------------------------------------------------------------- redteam.propose


def _redteam(messages: list[dict[str, Any]]) -> tuple[str | None, list[ToolCallRequest]]:
    """Attacker heuristics over the context: re-test earlier holes first, then unprotected exposed
    footholds that reach the corridor, the largest unpatched firmware family, the KEV CVE with most
    unprotected carriers, unprotected EV-charger gateways, and a plain push towards the signals."""
    ctx = _user_json(messages)
    devices = ctx["devices"]
    open_ = [d for d in devices if d["control"] != "patch"]  # weaker controls still leave a way in
    wanted: list[dict[str, Any]] = [p["strategy"] for p in ctx["previous_probes"] if p["hole"]]

    footholds = [d["id"] for d in open_ if d["exposed"] and d["reaches_corridor"]]
    if footholds:
        wanted.append({"entry_points": footholds[:1], "target_category": "signal"})

    families: dict[str, list[dict[str, Any]]] = {}
    for d in devices:
        if d["control"] != "patch":
            families.setdefault(d["firmware_family"], []).append(d)
    _, members = max(families.items(), key=lambda kv: (len(kv[1]), kv[0]), default=("", []))
    if len(members) >= 2:
        entry = [d["id"] for d in members if d["exposed"]][:1]
        wanted.append({"entry_points": entry, "pivot_shared_firmware": True})

    carriers: dict[str, int] = {}
    for d in open_:
        for cve in d["kev_cves"]:
            carriers[cve] = carriers.get(cve, 0) + 1
    if carriers:
        cve = max(carriers.items(), key=lambda kv: (kv[1], kv[0]))[0]
        wanted.append({"campaign_cve": cve})

    gateways = [d["id"] for d in open_ if d["category"] == "ev_charger" and d["reaches_corridor"]]
    if gateways:
        wanted.append({"entry_points": gateways[:3], "target_category": "signal"})
    wanted.append({"target_category": "signal"})

    unique = list({json.dumps(w, sort_keys=True): w for w in wanted}.values())[:5]
    return json.dumps({"strategies": unique}, sort_keys=True), []


RESPONDERS: dict[str, Responder] = {
    "redteam.propose": _redteam,
    "sentinel.extract": _extract,
    "analyst.step": _analyst,
    "planner.constraints": _constraints,
    "planner.claims": _claims,
}


class MockLLM:
    """Deterministic ``LLM`` for CI and keyless runs."""

    mode = "mock"

    def chat(
        self,
        task: str,
        messages: list[dict[str, Any]],
        tier: Tier = "strong",
        tools: list[dict[str, Any]] | None = None,
        json_output: bool = False,
    ) -> LLMResponse:
        responder = RESPONDERS.get(task)
        if responder is None:
            raise ValueError(f"no mock responder for task {task!r}")
        content, calls = responder(messages)
        prompt_chars = len(json.dumps(messages, sort_keys=True)) + len(json.dumps(tools or []))
        completion_chars = len(content or "") + len(json.dumps([c.arguments for c in calls]))
        usage = LLMUsage(
            model="mock",
            prompt_tokens=prompt_chars // 4,
            completion_tokens=completion_chars // 4,
            latency_ms=0,
        )
        return LLMResponse(content=content, tool_calls=calls, usage=usage)
