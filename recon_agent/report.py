"""Generate Markdown report from triaged findings."""
from datetime import UTC, datetime


def generate_report(scope: str, subdomains: list[str], live_hosts: list[dict], triaged: list[dict]) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Recon Report: `{scope}`",
        f"Generated: {now} by recon-agent",
        "",
        "---",
        "",
        f"## Summary",
        f"- **Scope:** `{scope}`",
        f"- **Subdomains found:** {len(subdomains)}",
        f"- **Live hosts:** {len(live_hosts)}",
        f"- **Findings (post-triage):** {len(triaged)}",
        "",
    ]

    if not triaged:
        lines.append("No significant findings after triage.")
        return "\n".join(lines)

    lines += [
        "## Findings",
        "",
    ]

    for i, f in enumerate(triaged, 1):
        sev = f.get("info", {}).get("severity", "unknown").upper()
        name = f.get("info", {}).get("name", "Unknown")
        template_id = f.get("template-id", "")
        host = f.get("host", "")
        matched = f.get("matched-at", "")
        impact = f.get("_impact", "")
        tags = f.get("info", {}).get("tags", [])

        sev_marker = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "-"}.get(sev, "-")

        lines += [
            f"### {i}. {sev_marker} [{sev}] {name}",
            f"",
            f"- **Template:** `{template_id}`",
            f"- **Host:** `{host}`",
            f"- **Matched at:** `{matched}`",
        ]
        if tags:
            lines.append(f"- **Tags:** {', '.join(tags) if isinstance(tags, list) else tags}")
        if impact:
            lines += ["", f"**Impact:** {impact}", ""]
        lines += ["---", ""]

    if subdomains:
        lines += [
            "## Subdomains",
            "```",
            *sorted(subdomains[:50]),  # cap at 50 for readability
            "```" if len(subdomains) <= 50 else f"... and {len(subdomains) - 50} more",
            "",
        ]

    return "\n".join(lines)
