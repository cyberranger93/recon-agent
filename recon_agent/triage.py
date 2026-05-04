"""
AI triage layer: takes raw Nuclei findings and produces ranked, deduplicated,
false-positive-filtered output with draft impact statements.
"""
import json
import os
from typing import Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Known false-positive templates — skip these
FP_TEMPLATES = {
    "tech-detect", "waf-detect", "ssl-dns-names", "http-missing-security-headers",
    "nameserver-fingerprint", "email-spoofing", "mx-missing-dmarc",
}


def triage_with_llm(findings: list[dict], provider: str = "ollama", model: str = "llama3") -> list[dict]:
    """
    Use LLM to filter false positives and add impact statements.
    Falls back to rule-based triage if LLM unavailable.
    """
    if not findings:
        return []

    # Pre-filter obvious false positives
    filtered = [
        f for f in findings
        if f.get("template-id", "").lower() not in FP_TEMPLATES
        and f.get("info", {}).get("severity", "info").lower() not in ("info",)
    ]

    if not filtered:
        return []

    summary = json.dumps([{
        "template": f.get("template-id", "unknown"),
        "severity": f.get("info", {}).get("severity", "unknown"),
        "name": f.get("info", {}).get("name", "unknown"),
        "host": f.get("host", ""),
        "matched": f.get("matched-at", ""),
    } for f in filtered[:30]], indent=2)  # cap at 30 to avoid context overflow

    prompt = f"""You are a senior bug bounty hunter triaging recon results.

Below are security findings from an automated scan. Your job:
1. Remove any remaining false positives (informational, version disclosures with no real impact)
2. Rank remaining findings by exploitability + business impact
3. For each real finding, add a 1-sentence impact statement suitable for HackerOne/Bugcrowd

Return ONLY valid JSON array. Each object: template, severity, host, keep (bool), impact (string).

Findings:
{summary}"""

    try:
        if provider == "ollama":
            return _ollama_triage(prompt, model, filtered)
        elif provider == "groq":
            return _groq_triage(prompt, filtered)
    except Exception:
        pass

    # Rule-based fallback
    return _rule_based_triage(filtered)


def _ollama_triage(prompt: str, model: str, filtered: list[dict]) -> list[dict]:
    import ollama
    response = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}])
    raw = response["message"]["content"]
    try:
        start = raw.index("[")
        end = raw.rindex("]") + 1
        llm_results = json.loads(raw[start:end])
        return _merge_llm_results(llm_results, filtered)
    except (ValueError, json.JSONDecodeError):
        return _rule_based_triage(filtered)


def _groq_triage(prompt: str, filtered: list[dict]) -> list[dict]:
    from groq import Groq
    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    response = client.chat.completions.create(
        model="llama3-70b-8192",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2048,
    )
    raw = response.choices[0].message.content
    try:
        start = raw.index("[")
        end = raw.rindex("]") + 1
        llm_results = json.loads(raw[start:end])
        return _merge_llm_results(llm_results, filtered)
    except (ValueError, json.JSONDecodeError):
        return _rule_based_triage(filtered)


def _merge_llm_results(llm_results: list[dict], original: list[dict]) -> list[dict]:
    keep_templates = {r["template"] for r in llm_results if r.get("keep", True)}
    impact_map = {r["template"]: r.get("impact", "") for r in llm_results}
    merged = []
    for f in original:
        tid = f.get("template-id", "")
        if tid in keep_templates:
            f["_impact"] = impact_map.get(tid, "")
            merged.append(f)
    merged.sort(key=lambda x: SEVERITY_ORDER.get(x.get("info", {}).get("severity", "unknown"), 5))
    return merged


def _rule_based_triage(findings: list[dict]) -> list[dict]:
    real = [
        f for f in findings
        if SEVERITY_ORDER.get(f.get("info", {}).get("severity", "unknown"), 5) <= 2  # critical, high, medium
    ]
    real.sort(key=lambda x: SEVERITY_ORDER.get(x.get("info", {}).get("severity", "unknown"), 5))
    for f in real:
        sev = f.get("info", {}).get("severity", "unknown")
        name = f.get("info", {}).get("name", "Unknown vulnerability")
        f["_impact"] = f"{name} ({sev}) — may allow unauthorized access or information disclosure."
    return real
