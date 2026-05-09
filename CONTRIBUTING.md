# Contributing

## Local Development

```bash
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -e .
python -m unittest discover
```

## Pull Request Checklist

- Keep scanning behavior explicit and scoped.
- Add tests for parsing, command construction, or reporting changes.
- Update README examples when CLI behavior changes.
- Run `python -m unittest discover` before opening a PR.

## Good First Issues

- Add JSON report output.
- Add import mode for saved Nuclei JSONL.
- Add parser tests for ProjectDiscovery output variants.
