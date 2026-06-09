# Contributing

Thanks for helping improve AKHA XSS Scanner.

## Local Setup

Windows:

```powershell
.\install.ps1
.\.venv\Scripts\Activate.ps1
akha-xss doctor
```

Cross-platform:

```bash
python -m venv .venv
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
python -m playwright install chromium
akha-xss doctor
```

## Development Checks

Run these before opening a PR:

```bash
python -m pytest -q
python -m compileall -q akha tests tools
```

## Contribution Rules

- Keep scanner behavior authorization-safe and scope-aware.
- Add or update tests for detection, report, CLI, and regression changes.
- Do not commit generated reports, cache directories, virtualenvs, or browser binaries.
- Keep reports readable for both technical reviewers and non-technical stakeholders.
- Prefer small, focused pull requests.
