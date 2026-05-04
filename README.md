# recon-agent

> AI-powered bug bounty recon — from scope to prioritized findings in one command.

[![PyPI](https://img.shields.io/pypi/v/recon-agent)](https://pypi.org/project/recon-agent)
[![GitHub stars](https://img.shields.io/github/stars/cyberranger93/recon-agent)](https://github.com/cyberranger93/recon-agent)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<!-- hero GIF: raw Nuclei chaos → clean AI-triaged report -->
<!-- ![demo](assets/demo.gif) -->

## The problem

You run a recon scan. Nuclei gives you 500 lines. 90% is noise — info-level findings, tech detects, version disclosures. You spend 2 hours manually reading output to find 3 real findings worth reporting.

`recon-agent` adds an AI triage layer: run the scan, get a clean Markdown report with severity-ranked findings and HackerOne-ready impact statements.

## Quick Start

```bash
pip install recon-agent
recon-agent --scope example.com --output report.md
```

### Docker (no Python needed)

```bash
docker compose up -d
docker compose run recon-agent --scope example.com --output /output/report.md
```

## Requirements

External tools (all free, all Go):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

LLM (pick one):

```bash
# Option A: Local (free, private)
ollama pull llama3

# Option B: Groq (free tier, faster)
export GROQ_API_KEY=your_key
recon-agent --scope example.com --provider groq
```

## Output

```markdown
# Recon Report: example.com
Generated: 2026-05-04 by recon-agent

## Summary
- Subdomains found: 47
- Live hosts: 23  
- Findings (post-triage): 4

## Findings

### 1. 🔴 [CRITICAL] Unauthenticated Admin Panel
- Template: `exposed-panels/admin-panel`
- Host: admin.example.com
- Matched at: https://admin.example.com/admin

**Impact:** Exposed admin interface may allow unauthorized access to application management functions.

---

### 2. 🟠 [HIGH] SQL Injection (GET parameter)
...
```

## Pipeline

```
Subfinder → Httpx → Nuclei → AI Triage → Markdown Report
   (subdomains)  (live?)  (findings)  (noise removed)  (submit-ready)
```

## Options

```
--scope, -s     Target domain (required)
--output, -o    Output .md file (default: stdout)
--severity      Nuclei severity filter (default: medium,high,critical)
--provider      LLM provider: ollama | groq (default: ollama)
--model         Ollama model name (default: llama3)
--no-triage     Skip AI triage, dump raw findings
```

## Why This vs Running Tools Manually

| | recon-agent | Manual toolchain |
|---|---|---|
| Noise filtered automatically | ✅ | ❌ — you read 500 lines |
| Impact statements generated | ✅ | ❌ — you write them |
| Submit-ready Markdown output | ✅ | ❌ — you format it |
| Local LLM (no API cost) | ✅ | N/A |
| One command to run everything | ✅ | ❌ — 3 tools, piped |

## Security Note

Only use against targets you have explicit written authorization to test. This tool is for authorized penetration testing and bug bounty programs with defined scope.

## Contributing

PRs welcome. Good first issues: add new tool integrations (amass, ffuf, gau), improve triage prompts, add JSON output format.

[Good first issues →](https://github.com/cyberranger93/recon-agent/labels/good%20first%20issue)

## License

MIT © CyberRanger93
