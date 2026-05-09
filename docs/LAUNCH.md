# Launch Notes

## Positioning

Bug bounty recon is noisy. `recon-agent` turns raw ProjectDiscovery output into a cleaner triage report.

## LinkedIn Post

I shipped `recon-agent`, a Python CLI for authorized bug bounty recon.

It runs a Subfinder -> Httpx -> Nuclei pipeline, filters obvious noise, and uses an LLM to draft severity-ranked impact statements in Markdown. The goal is not to replace judgment. It removes the repetitive report-prep work so security engineers can spend more time validating the real findings.

Repo: https://github.com/cyberranger93/recon-agent

Attach: `assets/social-card.png` or `assets/demo.gif`

## Reddit Draft

Title: recon-agent - open-source AI triage for authorized bug bounty recon

I got tired of reading long Nuclei output and manually turning it into a report.

`recon-agent` wraps Subfinder, Httpx, and Nuclei, then filters obvious noise and drafts a Markdown report with impact statements. It supports local Ollama by default and Groq as an optional provider.

GitHub: https://github.com/cyberranger93/recon-agent

Attach: `assets/demo.gif`
