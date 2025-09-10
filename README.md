# AI Upload Guard — README (Windows, Linux, macOS)

## Overview

`ai_upload_guard.py` is a **local pre-check** that scans documents/spreadsheets/logs before you paste or upload them into AI tools or cloud services. It flags likely **PII, secrets, code, network details, client/internal markers, and IP-like oddities**, then assigns a disposition so you can redact, seek approvals, or proceed.

* **Local only:** no data leaves your machine.
* **Heuristic:** conservative by design; human judgment still required.

---

> ⚠️ Scope & Limitations
**ai_upload_guard.py** is a **local, heuristic prescan** to help you spot likely sensitive information **before** you paste or upload to AI tools or cloud services.  
It **does not** guarantee detection and **is not** a Data Loss Prevention (DLP) system, compliance control, or legal review.

- Local only: the tool does not transmit file contents; analysis runs on your machine.
- Heuristic: patterns, rules, and lightweight ML → **false negatives and false positives are expected**.
- Human review required: flagged results require your judgment, redaction, and/or approvals.
- No compliance claim: using this tool does **not** by itself satisfy HIPAA/PCI/GLBA/FERPA/GDPR/… obligations.
- No secrets in logs: configure/redact logs; never store raw sensitive data in outputs.

**You are responsible** for what you upload. Treat this as an **assistive precheck**, not a safeguard.

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

---

## Installation

### Windows

1. **Install Python 3 (64-bit):**
   Download from [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/) and check **“Add Python to PATH”**.

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

1. **Install Python 3:**

   * Easiest via **Homebrew**: `brew install python`
   * Or download from [https://www.python.org/downloads/macos/](https://www.python.org/downloads/macos/)

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
* `--strict` — treat **RESTRICTED** signals as **PROHIBITED**

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

### Windows (Batch)

Create `run_check.bat` next to the script:

```bat
@echo off
setlocal
if "%~1"=="" (
  echo Usage: drag-and-drop a file onto this .bat, or run: run_check.bat "C:\path\to\file.ext"
  pause
  exit /b 1
)
python "%~dp0ai_upload_guard.py" "%~1" --context client --assume-approved-tool --max-unique 120 --no-bank-hints --phone-context
endlocal
```

### Linux/macOS (Shell)

Create `run_check.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then
  echo 'Usage: ./run_check.sh "/path/to/file.ext"'
  exit 1
fi
python3 "$(dirname "$0")/ai_upload_guard.py" "$1" --context client --assume-approved-tool --max-unique 120 --no-bank-hints --phone-context
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
