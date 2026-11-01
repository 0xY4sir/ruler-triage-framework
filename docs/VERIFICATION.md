# Verification Log

Verified in sandbox on 2026-11-01 using `python3` from the active project venv PATH.

## Verified in sandbox

### 1. `python3 ruler_triage.py --validate-case`

```text

════════════════════════════════════════════════════════════════════════
  SELF-VALIDATION MODE — ManageEngine UEMS Ground-Truth Case
  A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers
════════════════════════════════════════════════════════════════════════

  Case    : ManageEngine UEMS Agent — Tahakom COOP Investigation
  Date    : 2026-07-19
  Network : SMB2 / port 445 / internal-to-internal (10.x.x.20 → 10.x.x.128)
  VT known: 1/69 (ESET: RemoteAdmin)
  Signed  : No (Unsigned)

  Indicator          Tool Result            Ground-Truth
  ────────────────────────────────────────────────────────────────────
  Signature          Unsigned                   Unsigned                   ✓
  VT Ratio           1/69                       1/69                       ✓
  DB Status          pending_verification       pending_verification       ✓
  Score              20                         20                         ✓
  Verdict            Low Confidence (Suspiciou… Low Confidence (Suspiciou… ✓

  Tool verdict (full) : Low Confidence (Suspicious / Pending Verification)
  GT verdict (full)   : Low Confidence (Suspicious / Pending Verification)

  VALIDATION PASSED — All indicators match the ground-truth case. Framework is correctly calibrated.

  Recommendation: Confirm with IT Operations whether the ManageEngine UEMS deployment was authorised before closing the alert.

════════════════════════════════════════════════════════════════════════

```

### 2. `python3 ruler_triage.py /bin/ls`

```text
[INFO] Analysing: /bin/ls
[INFO] Stage 1/6 — Computing cryptographic hashes…
[INFO] Stage 2/6 — Verifying digital signature…
[INFO] Stage 3/6 — Querying VirusTotal API…
[WARN] No VT API key — running in OFFLINE MODE. Verdict accuracy is reduced.
[INFO] Stage 4/6 — Checking vendor hash database…
[INFO] Stage 5/6 — Computing confidence verdict…
[INFO] Stage 6/6 — Generating report…

════════════════════════════════════════════════════════════════════════
  ruler_triage.py v2.0.0  —  TRIAGE ANALYSIS REPORT
  A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers
  University of Ha'il — Department of Information Security
════════════════════════════════════════════════════════════════════════

Generated: 2026-11-01T14:43:29.857544+00:00
File     : ls
Path     : /bin/ls
Size     : 154,208 bytes

── 1. Cryptographic Hashes ──────────────────────────────────────────────
  SHA-256 : 24752389e1d97c9555dd153b644902fadd460dfbe1a166251876c67bbacb0810
  SHA-1   : 17eeca486829edbe23278c2a3a7d9de74605a534
  MD5     : ec4722ce408f7c68a9cb3013c5830a83

── 2. Digital Signature ─────────────────────────────────────────────────
  Status  : Not a PE  [Tier-2 (structural)]
  Detail  : pefile parse error: 'DOS Header magic not found.'

── 3. VirusTotal (v3) ───────────────────────────────────────────────────
  Warning : No VirusTotal API key provided. Running in offline mode — VT intelligence is unavailable. Accuracy is reduced. Provide a key with --vt-key or the VT_API_KEY environment variable.

── 4. Vendor Hash Database ───────────────────────────────────────────────
  NO MATCH — hash not present in vendor database.

── 5. Confidence Verdict ─────────────────────────────────────────────────
  Score   : 10
    ·  ±0  Signature status unknown (Not a PE) — skipped.
    ·  ±0  VT unavailable: No VirusTotal API key provided. Running in offline mode — VT intelligence is unavailable. Accuracy is reduced. Provide a key with --vt-key or the VT_API_KEY environment variable.
    · +10  Hash not found in vendor database.
  ⚠ WARNING : VT intelligence absent — verdict accuracy is reduced.

  ► Low Confidence (Suspicious / Pending Verification)

── 6. Case Validation Reference ─────────────────────────────────────────
  Ground-truth case : ManageEngine UEMS Agent — Tahakom COOP Investigation
  GT SHA-256        : eddb6acad4b6078e7a691d4fb8c452916efd288f27eb99a8426a2b81dfa5539c
  GT Verdict        : Low Confidence (Suspicious / Pending Verification)  (score ≈ 20)
  This file verdict : Low Confidence (Suspicious / Pending Verification)  (score = 10)
  Category match    : ✓ MATCH
  Framework conf.   : Not the ground-truth hash — comparison is informational only.

════════════════════════════════════════════════════════════════════════
```

No Tier-2 structural warning was printed for this non-PE file.

### 3. `python3 ruler_triage.py --version`

```text
ruler_triage.py v2.0.0
```

### 4. `python3 ruler_triage.py --quiet --validate-case`

```text

════════════════════════════════════════════════════════════════════════
  SELF-VALIDATION MODE — ManageEngine UEMS Ground-Truth Case
  A Structured Triage Framework for IDS Alerts on Suspicious RMM Installers
════════════════════════════════════════════════════════════════════════

  Case    : ManageEngine UEMS Agent — Tahakom COOP Investigation
  Date    : 2026-07-19
  Network : SMB2 / port 445 / internal-to-internal (10.x.x.20 → 10.x.x.128)
  VT known: 1/69 (ESET: RemoteAdmin)
  Signed  : No (Unsigned)

  Indicator          Tool Result            Ground-Truth
  ────────────────────────────────────────────────────────────────────
  Signature          Unsigned                   Unsigned                   ✓
  VT Ratio           1/69                       1/69                       ✓
  DB Status          pending_verification       pending_verification       ✓
  Score              20                         20                         ✓
  Verdict            Low Confidence (Suspiciou… Low Confidence (Suspiciou… ✓

  Tool verdict (full) : Low Confidence (Suspicious / Pending Verification)
  GT verdict (full)   : Low Confidence (Suspicious / Pending Verification)

  VALIDATION PASSED — All indicators match the ground-truth case. Framework is correctly calibrated.

  Recommendation: Confirm with IT Operations whether the ManageEngine UEMS deployment was authorised before closing the alert.

════════════════════════════════════════════════════════════════════════

```

There were no `[INFO]` lines in quiet mode.

### 5. GUI syntax check

Command: `python3 -c "import ast; ast.parse(open('app.py').read()); print('app.py syntax OK')"`

```text
app.py syntax OK
```

### 6. GUI engine import check

Command: `python3 -c "from ruler_triage import compute_hashes, check_signature, query_virustotal, load_vendor_db, check_whitelist, compute_verdict, build_case_validation, build_report, GROUND_TRUTH_CASE, VERDICT_THRESHOLDS, SCORING_RATIONALE, _TOOL_VERSION; print('Imports OK')"`

```text
Imports OK
```

### 7. Sample report JSON check

Command: `python3 -c "import json; json.load(open('docs/sample_triage_report.json')); print('sample JSON OK')"`

```text
sample JSON OK
```

### 8. Git history check

Command: `git log --oneline 2>&1 || echo "git not initialized — user will run git manually"`

```text
fatal: not a git repository (or any of the parent directories): .git
git not initialized — user will run git manually
```

## Pending manual by user

- **pytest:** SKIPPED — not installed in sandbox. User to run: `venv/bin/pip install pytest && venv/bin/pytest tests/ -v`
- **Streamlit:** SKIPPED — not installed in sandbox. User to run: `venv/bin/pip install streamlit && venv/bin/streamlit run app.py`
