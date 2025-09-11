# AI Upload Guard — README (Windows, Linux, macOS)

> 🚨 **Advisory Only — Not DLP / Not a Safeguard**
> This tool is a **local heuristic pre-scan** to help you spot likely sensitive information **before** you paste or upload to AI tools or cloud services. It **will** miss things (false negatives) and **will** flag benign content (false positives). **You remain responsible** for what you upload. See **Scope & Limitations** below.

## Overview

`ai_upload_guard.py` is a **local pre-check** that scans documents/spreadsheets/logs before you paste or upload them into AI tools or cloud services. It flags likely **PII, secrets, code, network details, client/internal markers, and IP-like oddities**, then assigns a disposition so you can redact, seek approvals, or proceed.

* **Local only:** no data leaves your machine.
* **Heuristic:** conservative by design; human judgment still required.

---

## ⚠️ Scope & Limitations

**ai\_upload\_guard.py** is a **local, heuristic prescan**. It **does not** guarantee detection and **is not** a Data Loss Prevention (DLP) system, compliance control, or legal review.

* Local only: analysis runs on your machine; file contents are not transmitted.
* Heuristic: patterns, rules, and lightweight ML → **false negatives and false positives are expected**.
* Human review required: flagged results require your judgment, redaction, and/or approvals.
* No compliance claim: using this tool does **not** by itself satisfy HIPAA/PCI/GLBA/FERPA/GDPR/… obligations.
* No secrets in logs: configure/redact logs; never store raw sensitive data in outputs.
* Not for classified/controlled info (e.g., CUI/ITAR): this tool does **not** meet those requirements.

**Treat this as an assistive precheck, not a safeguard or enforcement control.**

---

## What it scans for

* **PII:** emails, phones (strict; GUID/ID/IP-safe), SSN-like, address-like
* **Financial (configurable):**

  * **Credit cards (strict):** real IIN ranges + Luhn + realistic grouping
  * **IBAN (strict):** valid country + length + MOD-97
  * **Bank hints (strict):** routing/ABA (9-digit with label), sort code (valid formats), account numbers (8+ digits), SWIFT/BIC (8/11 chars)
* **Health context:** diagnosis/medical record/patient id/PHI terms
* **Secrets & credentials:** API keys, JWT/Bearer/Basic, cookies, private keys, high-entropy strings, DB/queue connection strings, Azure SAS/AccountKey
* **Source code & SQL:** common language and query patterns
* **Network & infra:** IPv4/IPv6, CIDR, host\:port, MAC addresses, internal URLs/hostnames, cloud resource IDs (AWS/Azure/GCP)
* **Schema clues:** field names like `ssn`, `dob`, `password`, `api_key`
* **Unknowns (human review):** IP-like but not valid (e.g., `420-172.31.120.x`)

---

## Disposition categories

* **PROHIBITED** — secrets/regulated data/code (or escalated network/unknowns).
* **RESTRICTED** — internal/client markers, IPs/hostnames, cloud IDs.
* **ALLOWED\_IF\_IN\_APPROVED\_TOOL** — no risky findings; still use approved tools.
* **ALLOWED\_WITH\_CONDITIONS** — same as above if you pass `--assume-approved-tool`.

> **Tip:** Use `--strict` to treat **RESTRICTED** as **PROHIBITED** for fail-closed behavior.

---

## Data handling & privacy

* **Processing:** local only. The script performs no network calls during scanning.
* **Telemetry:** none by default. Auto-updates/telemetry are **not** performed.
* **Logging:** defaults to minimal metadata (filenames, rule IDs, counts). Raw matches are masked (e.g., `••••`).
* **Cache/Temp:** ensure your OS temp directory isn’t synced to cloud backup if you process sensitive files.
* **Rulepacks:** keep a local, versioned rulepack with a displayed SHA-256 so results are auditable.

---

## Exit codes & automation (CI/hooks)

| Code | Meaning                               | Typical action                    |
| ---- | ------------------------------------- | --------------------------------- |
| `0`  | **OK** (no disallowed findings)       | Proceed                           |
| `1`  | Usage/runtime error                   | Fix invocation/environment        |
| `2`  | **REVIEW** (human review recommended) | Pause; triage/redact/approve      |
| `3`  | **BLOCK** (prohibited indicators)     | Stop; escalate or remove findings |

Wire these into pre-commit hooks, upload wrappers, or CI to prevent accidental leaks.

---

## Report header (prepended to every output)

```
AI Upload Guard — Advisory Only
Heuristic findings for human triage. False negatives/positives are possible.
Not a substitute for DLP, security review, or legal/compliance approvals.
Dispositions: BLOCK | REDACT | REVIEW | PROCEED (record your decision).
Rulepack vX.Y.Z (SHA256: …)
```

---

## First-run risk acknowledgment (recommended UX)

On first run (or always, if you prefer), display:

```
AI Upload Guard — Risk Acknowledgment
This tool is a LOCAL heuristic prescan only. It will miss things and may misclassify content.
It is NOT DLP, NOT a security control, and NOT legal/compliance review.
You remain responsible for any data you upload.

Type "I UNDERSTAND" to continue, or run with --acknowledge-risks to suppress.
```

Persist an acknowledgment file or require `--acknowledge-risks` in CI/wrappers.

---

## Installation

### Windows

1. **Install Python 3 (64-bit):** download from python.org and check **“Add Python to PATH.”**
2. **(Optional) Create a virtual env** in the project folder:

   ```cmd
   python -m venv .venv
   .\.venv\Scripts\activate
   ```
3. **Install dependencies:**

   ```cmd
   pip install pdfminer.six python-docx pandas openpyxl
   ```

### Linux (Debian/Ubuntu example)

1. **Install Python & pip (if needed):**

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-venv
   ```
2. **(Optional) Virtual env:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies:**

   ```bash
   pip install pdfminer.six python-docx pandas openpyxl
   ```

### macOS

1. **Install Python 3:** Homebrew `brew install python` or python.org installer.
2. **(Optional) Virtual env:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies:**

   ```bash
   pip install pdfminer.six python-docx pandas openpyxl
   ```

---

## Supported input types

`.txt`, `.md`, `.csv`, `.json`, `.yaml/.yml`, `.log`, `.pdf`, `.docx`, `.xlsx/.xls`

---

## Quick start

### Windows (Command Prompt)

```cmd
cd C:\AIUploadGuard
python ai_upload_guard.py "C:\path\to\file.xlsx" --context client --assume-approved-tool
```

### Linux / macOS (Terminal)

```bash
cd ~/AIUploadGuard
python3 ai_upload_guard.py "/path/to/file.xlsx" --context client --assume-approved-tool
```

You’ll see progress logs like `[INFO] Running secrets checks…` so big files don’t look stalled.

---

## Common usage patterns

Turn **off all financial checks**:

* Windows:

  ```cmd
  python ai_upload_guard.py "C:\file.xlsx" --no-financial
  ```
* Linux/macOS:

  ```bash
  python3 ai_upload_guard.py "/path/file.xlsx" --no-financial
  ```

Keep **cards/IBAN** but disable bank hints:

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --no-bank-hints
```

Limit to **80 unique** findings (deduped with counts):

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --max-unique 80
```

Treat **IPs/hostnames/unknown IP-like** as **PROHIBITED**:

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --ip-as-prohibited --hostnames-as-prohibited --unknown-as-prohibited
```

Flag internal domains/URLs:

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --internal-domains "(?:corp|intra)\.example\.com"
```

Suppress noisy patterns:

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --ignore "SWIFT\s*-\s*DEV" --ignore "^Financial: bank details"
# or load from a file:
python3 ai_upload_guard.py "/path/file.xlsx" --ignore-file "/path/ignore.txt"
```

Phone numbers only when clearly phones:

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --phone-context
```

---

## CLI options (quick reference)

**Context & clients**

* `--context [public|internal|client]`
* `--client-names "A|B|C"`

**Financial toggles**

* `--no-financial` · `--no-cc` · `--no-iban` · `--no-bank-hints`

**Network sensitivity (escalate)**

* `--ip-as-prohibited` · `--hostnames-as-prohibited` · `--unknown-as-prohibited`

**Precision & noise controls**

* `--phone-context` — require phone-related words nearby
* `--internal-domains "regex"` — flag matching hostnames/URLs as internal
* `--ignore "<regex>"` (repeatable) · `--ignore-file "<path>"`
* `--max-unique N` — cap **unique** findings shown (default 200)
* `--no-dedupe` — print raw reasons (noisy; not recommended)

**Other**

* `--assume-approved-tool` — clean files show as **ALLOWED\_WITH\_CONDITIONS**
* `--strict` — treat **RESTRICTED** as **PROHIBITED**
* `--acknowledge-risks` — skip interactive banner once acknowledged

---

## Output format

* **Summary** — category counts (after de-duplication).
* **Top findings** — unique items with **(xN)** counts, ordered by severity.
* **Operational notes** — toggles and tips.

> Tip: Use `--max-unique` to keep results readable for very large files.

---

## Ignore rules (examples)

Create `ignore.txt`:

```
# Ignore subnet masks
^Network: IP address \(IPv4\): 255\.
# Ignore dev labels using 'SWIFT - DEV'
SWIFT\s*-\s*DEV
# Ignore any bank details heuristics if needed
^Financial: bank details
```

Run with:

```bash
python3 ai_upload_guard.py "/path/file.xlsx" --ignore-file "/path/ignore.txt"
```

---

## Optional one-click launchers

### Windows (Batch) — `run_check.bat`

```bat
@echo off
setlocal
if "%~1"=="" (
  echo Usage: drag-and-drop a file onto this .bat, or run: run_check.bat "C:\path\to\file.ext"
  pause
  exit /b 1
)
python "%~dp0ai_upload_guard.py" "%~1" --context client --assume-approved-tool --max-unique 120 --no-bank-hints --phone-context --acknowledge-risks
endlocal
```

### Linux/macOS (Shell) — `run_check.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then
  echo 'Usage: ./run_check.sh "/path/to/file.ext"'
  exit 1
fi
python3 "$(dirname "$0")/ai_upload_guard.py" "$1" --context client --assume-approved-tool --max-unique 120 --no-bank-hints --phone-context --acknowledge-risks
```

Make it executable:

```bash
chmod +x run_check.sh
```

---

## Troubleshooting

* **`ModuleNotFoundError`** → `pip install pdfminer.six python-docx pandas openpyxl`
* **Excel open errors** → ensure `openpyxl` is installed; very old `.xls` may need extra drivers
* **Slow on huge files** → rely on progress logs; split files; use `--max-unique` and `--ignore` rules
* **Too many network hits (e.g., masks, test IPs)** → add ignore rules (e.g., `^Network: IP address \(IPv4\): 255\.`)

---

## Optional hardening suggestions

* Standardize stricter defaults in your wrappers:
  `--ip-as-prohibited --hostnames-as-prohibited --unknown-as-prohibited --phone-context --no-bank-hints`
* Maintain a shared `ignore.txt` for benign recurring tokens (VM labels, subnet masks, test IPs).
* Periodically rotate/tighten the **secrets** patterns (add your org’s token formats).
* Fail closed in CI by treating exit codes ≥2 as upload blockers.

---

## Compliance & legal notice

This software provides advisory, local-only heuristic scans to assist users in identifying potentially sensitive content prior to upload. It **does not** constitute a compliance control or legal review and **does not** itself satisfy obligations under HIPAA, PCI DSS, GLBA, FERPA, GDPR, CCPA, SOX, or any other framework. **No warranty** is provided; use at your own risk.

---

## Security contact

Report vulnerabilities or concerns to: **[security@example.com](mailto:security@example.com)** (replace with your address).

---

## Versioning & provenance

* Print **rulepack version** and **SHA-256** in every report.
* Tag releases (`vX.Y.Z`) and include a **CHANGELOG.md**.
* Add SPDX headers in source (e.g., `# SPDX-License-Identifier: 0BSD`).

---

## License

Choose a permissive license and include it as `LICENSE` at repo root.

* **0BSD** or **The Unlicense**: *no attribution required*.
* **MIT** / **BSD-2-Clause**: very permissive, attribution required.

---

> ✅ **Reminder:** A license covers *reuse of your code*. The warnings above cover *safe use of the tool*. Keep both.

