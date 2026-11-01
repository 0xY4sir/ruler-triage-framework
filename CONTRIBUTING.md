# Contributing

Thank you for helping improve Ruler Triage Framework. Before proposing a change, review `AGENTS.md` for project invariants and preserve the ManageEngine ground-truth entry as `pending_verification` unless IT Operations confirms authorization.

## Report a bug

Open a GitHub issue with a clear title, steps to reproduce, expected behavior, actual behavior, Python and operating-system versions, and relevant sanitized console output. Do not attach suspicious binaries, API keys, personal data, or sensitive network details to a public issue.

## Suggest a feature

Open an issue describing the analyst workflow or problem, the proposed behavior, and any effect on scoring, reports, or the GUI. Keep scoring changes explainable and include appropriate test coverage when implementation begins.

## Add a vendor hash

Use the CLI so the SHA-256 format is checked and the record receives the default pending status:

```bash
python3 ruler_triage.py --add-to-db "<64-character-sha256>:Vendor Name:Product Name"
```

A new entry defaults to `pending_verification`. Change it to `approved` only after documented confirmation from IT Operations, following the organization's authorization process. Never submit API keys or sensitive vendor data in a public contribution.

## Submit a change

Keep changes focused, describe the reason and verification performed in the pull request, and run `pytest tests/ -v` when the test dependency is available. Do not change the ground-truth case or scoring model without documenting the rationale and updating its validation coverage.
