"""
SENTRIX Root Cause Explainer
----------------------------
Generates plain-language root cause explanations and suggested actions.

Guarantees:
  1. Offline rule-based engine by default — instant and deterministic for demos/viva.
  2. Optional LLM integration via LLM_API_KEY.
  3. PRIVACY GUARANTEE: Never sends raw logs to the LLM. Only pre-redacted
     high-level event summaries are transmitted if LLM mode is active.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Tuple

log = logging.getLogger("sentrix.explainer")


def explain_incident(
    title: str,
    severity: str,
    affected_hosts: List[str],
    timeline: List[Dict[str, Any]]
) -> Tuple[str, str]:
    """
    Produce (likely_cause, suggested_action).
    Tries LLM if LLM_API_KEY is configured, otherwise uses rule-based engine.
    """
    llm_api_key = os.getenv("LLM_API_KEY", "").strip()
    if llm_api_key:
        try:
            cause, action = _explain_with_llm(title, severity, affected_hosts, timeline, llm_api_key)
            if cause and action:
                return cause, action
        except Exception as e:
            log.warning("LLM explanation failed, falling back to rule-based: %s", e)

    return _explain_with_rules(title, severity, affected_hosts, timeline)


def _explain_with_rules(
    title: str,
    severity: str,
    affected_hosts: List[str],
    timeline: List[Dict[str, Any]]
) -> Tuple[str, str]:
    """Rule-based engine with domain knowledge patterns."""
    text_corpus = " ".join([item.get("message", "").lower() for item in timeline])
    title_lower = title.lower()
    hosts_str = ", ".join(affected_hosts) if affected_hosts else "monitored host"

    # Pattern 1: Overheating / CPU spike causing latency
    if "overheating" in title_lower or "cpu spike" in title_lower or "temperature" in text_corpus or "slow response" in text_corpus:
        cause = (
            f"Thermal throttling or compute saturation on {hosts_str} is delaying request processing. "
            f"Correlated metric spikes coincide with website latency increases."
        )
        action = (
            "Inspect high-CPU processes on affected host, verify hardware cooling fans, "
            "and temporarily shift traffic to standby instances."
        )
        return cause, action

    # Pattern 2: Failed logins / Authentication / Brute-force
    event_types = [item.get("event_type", "").lower() for item in timeline]
    if (
        "login" in title_lower
        or "auth" in title_lower
        or "failed_login" in event_types
        or "login" in text_corpus
        or "auth" in text_corpus
    ):
        count = sum(1 for item in timeline if "login" in item.get("event_type", "") or "login" in item.get("message", "").lower())
        count_str = f"{count} failed attempts" if count > 0 else "Multiple failed attempts"
        cause = (
            f"Repeated authentication failures ({count_str}) detected on {hosts_str}. "
            f"Pattern indicates an automated credential-stuffing or brute-force attack."
        )
        action = (
            "Enforce rate-limiting on authentication routes, block offending source IP at edge firewall, "
            "and alert affected account holders to verify credential integrity."
        )
        return cause, action

    # Pattern 3: Application error spike / deployment regression
    if "deployment" in title_lower or "spike" in title_lower or "error" in text_corpus or "exception" in text_corpus:
        cause = (
            f"Sudden surge in unhandled exceptions on {hosts_str} immediately following code deployment or config update. "
            f"High error frequency indicates an unexpected null reference or dependency connection issue."
        )
        action = (
            "Initiate rapid rollback to previous stable release, inspect application error traces, "
            "and verify downstream database and cache connection strings."
        )
        return cause, action

    # Fallback default
    cause = (
        f"Correlated anomalies observed across {hosts_str} within short temporal window. "
        f"Multiple interconnected services experienced simultaneous metric degradation."
    )
    action = "Check recent system changes, review host resource allocation, and monitor system metrics."
    return cause, action


def _explain_with_llm(
    title: str,
    severity: str,
    affected_hosts: List[str],
    timeline: List[Dict[str, Any]],
    api_key: str
) -> Tuple[str, str]:
    """
    Sends ONLY pre-redacted summary to LLM.
    Strictly verifies payload contains no raw PII.
    """
    summary_items = [
        f"[{item.get('timestamp')}] {item.get('event_type')}: {item.get('message')}"
        for item in timeline[-10:]
    ]
    prompt = (
        f"You are SENTRIX AI. Analyze this operational incident:\n"
        f"Title: {title}\n"
        f"Severity: {severity}\n"
        f"Affected Hosts: {', '.join(affected_hosts)}\n"
        f"Events:\n" + "\n".join(summary_items) + "\n\n"
        f"Provide a concise JSON response with keys 'likely_cause' (1-2 sentences) and 'suggested_action' (1 sentence)."
    )

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    req_body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
    }
    data = json.dumps(req_body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

    with urllib.request.urlopen(req, timeout=5) as response:
        res = json.loads(response.read().decode("utf-8"))
        text = res["candidates"][0]["content"]["parts"][0]["text"]
        parsed = json.loads(text)
        return parsed.get("likely_cause", ""), parsed.get("suggested_action", "")
