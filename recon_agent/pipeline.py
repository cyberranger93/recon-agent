"""
Recon pipeline: Subfinder → Httpx → Nuclei
Wraps external tools as subprocess calls with timeout + error handling.
"""
import subprocess
import json
import shutil
from dataclasses import dataclass
from typing import Optional


@dataclass
class PipelineResult:
    subdomains: list[str]
    live_hosts: list[dict]
    findings: list[dict]
    errors: list[str]


def _check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_subfinder(scope: str, timeout: int = 120) -> tuple[list[str], Optional[str]]:
    if not _check_tool("subfinder"):
        return [], "subfinder not installed. Run: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    try:
        result = subprocess.run(
            ["subfinder", "-d", scope, "-silent", "-json"],
            capture_output=True, text=True, timeout=timeout
        )
        subdomains = []
        for line in result.stdout.strip().splitlines():
            try:
                obj = json.loads(line)
                subdomains.append(obj.get("host", line))
            except json.JSONDecodeError:
                if line.strip():
                    subdomains.append(line.strip())
        return subdomains, None
    except subprocess.TimeoutExpired:
        return [], "subfinder timed out"
    except Exception as e:
        return [], str(e)


def run_httpx(hosts: list[str], timeout: int = 60) -> tuple[list[dict], Optional[str]]:
    if not _check_tool("httpx"):
        return [], "httpx not installed. Run: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    if not hosts:
        return [], None
    try:
        hosts_input = "\n".join(hosts)
        result = subprocess.run(
            ["httpx", "-silent", "-json", "-sc", "-title", "-tech-detect"],
            input=hosts_input, capture_output=True, text=True, timeout=timeout
        )
        live = []
        for line in result.stdout.strip().splitlines():
            try:
                live.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return live, None
    except subprocess.TimeoutExpired:
        return [], "httpx timed out"
    except Exception as e:
        return [], str(e)


def run_nuclei(targets: list[str], severity: str = "medium,high,critical", timeout: int = 300) -> tuple[list[dict], Optional[str]]:
    if not _check_tool("nuclei"):
        return [], "nuclei not installed. Run: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    if not targets:
        return [], None
    try:
        targets_input = "\n".join(targets)
        result = subprocess.run(
            ["nuclei", "-silent", "-json", "-severity", severity, "-l", "/dev/stdin"],
            input=targets_input, capture_output=True, text=True, timeout=timeout
        )
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return findings, None
    except subprocess.TimeoutExpired:
        return [], "nuclei timed out"
    except Exception as e:
        return [], str(e)


def run_pipeline(scope: str, severity: str = "medium,high,critical") -> PipelineResult:
    errors = []

    subdomains, err = run_subfinder(scope)
    if err:
        errors.append(f"subfinder: {err}")

    # Add root domain itself
    all_targets = list(set([scope] + subdomains))

    live_hosts, err = run_httpx(all_targets)
    if err:
        errors.append(f"httpx: {err}")

    live_urls = [h.get("url", h.get("input", "")) for h in live_hosts if h.get("url") or h.get("input")]

    findings, err = run_nuclei(live_urls or all_targets, severity)
    if err:
        errors.append(f"nuclei: {err}")

    return PipelineResult(
        subdomains=subdomains,
        live_hosts=live_hosts,
        findings=findings,
        errors=errors,
    )
