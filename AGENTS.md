# Ruler Triage Framework — University of Ha'il

## Project

**A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers: A Case-Driven Approach** is a University of Ha'il COOP project. It provides a Python CLI and Streamlit interface for a structured six-stage triage of suspicious Remote Monitoring and Management (RMM) installer files, using the ManageEngine UEMS investigation as its ground-truth case.

## File map

- `ruler_triage.py` — analysis engine, CLI, signature and VirusTotal integrations, scoring, and reports.
- `vendor_hashes.json` — status-aware vendor hash database.
- `app.py` — Streamlit graphical interface.
- `tests/` — pytest coverage for engine behavior and CLI validation.
- `docs/` — sample report and verification record.
- `README.md`, `CHANGELOG.md`, `requirements.txt`, `Makefile` — project documentation and developer setup.

## Run commands

- All commands use `python3` via the active venv PATH. Do not use `venv/bin/python` directly.
- `make validate` — validate the ManageEngine ground-truth case.
- `make test` — run the pytest suite.
- `make run FILE=/path/to/file.exe` — analyze a file with the CLI.

## Testing

Run tests with `pytest tests/ -v`.

## Critical invariants

1. Preserve the engine's scoring weights, signature tiers, VirusTotal query logic, and ground-truth constant. Only make changes explicitly requested for these areas.
2. Never modify `venv/`; it is environment state, not project source.
3. Keep the ManageEngine ground-truth hash at `pending_verification`; do not mark it approved.
4. Do not delete or rename `GROUND_TRUTH_CASE`, `SCORING_RATIONALE`, `VERDICT_THRESHOLDS`, or `_TOOL_VERSION`.
5. Do not run Streamlit in the foreground; use `venv/bin/streamlit run app.py --server.headless true` in the background for smoke checks.

When adding a new vendor hash: use `--add-to-db`, never edit JSON by hand for `approved` status without IT Ops confirmation.
