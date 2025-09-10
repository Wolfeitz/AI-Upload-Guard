# AI Upload Guard — README (Windows)

## Overview

`ai_upload_guard.py` is a **local pre-check tool** that scans documents/spreadsheets/logs before you upload or paste them into AI tools or cloud services. It flags likely **PII, secrets, code, network details, client/internal markers, and IP-like oddities** and assigns a clear disposition so you can decide whether to redact, get approvals, or proceed.

* **Local only:** the script does not send data anywhere.
* **Heuristic:** it’s conservative and can over/under-flag; human judgment still required.

---

## What it scans for

* **PII:** emails, phones (strict; GUID/ID/IP-safe), SSN-like, address-like
* **Financial (configurable):**

  * **Credit cards (strict):** real IIN ranges + Luhn + realistic grouping
  * **IBAN (strict):** valid country + length + MOD-97
  * **Bank hints (strict):** routing/ABA (9-digit, labeled), sort code (valid formats), account numbers (8+ digits), SWIFT/BIC (8/11 chars)
* **Health context:** diagnosis/medical record/patient id/PHI indicators
* **Secrets & credentials:** API keys, JWT/Bearer/Basic, cookies, private keys, high-entropy strings, DB/queue connection strings, Azure SAS/AccountKey
* **Source code & SQL:** common language/SQL patterns
* **Network & infrastructure:** IPv4/IPv6, CIDR, host\:port, MAC addresses, internal URLs/hostnames, cloud resource IDs (AWS/Azure/GCP)
* **Schema clues:** sensitive field/column names (`ssn`, `dob`, `password`, `api_key`, etc.)
* **Unknowns (human review):** IP-like but not quite valid (e.g., `420-172.31.120.x`)

---

## Disposition categories

* **PROHIBITED** — contains secrets/regulated data/code (or escalated network/unknowns).
* **RESTRICTED** — contains internal/client markers or system metadata (IPs, hostnames, cloud IDs).
* **ALLOWED\_IF\_IN\_APPROVED\_TOOL** — no risky findings; still use approved tools.
* **ALLOWED\_WITH\_CONDITIONS** — same as above, when `--assume-approved-tool` is provided.

---

## Install (Windows)

### 1) Install Python

1. Download **Python 3.x (64-bit)** from [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)
2. Run the installer and **check “Add Python to PATH.”**
3. Verify:

   ```cmd
   python --version
   ```

### 2) Install dependencies

```cmd
pip install pdfminer.six python-docx pandas openpyxl
```

---

## Save & Run

1. Save `ai_upload_guard.py` to a folder (e.g., `C:\AIUploadGuard`).
2. Open **Command Prompt** and `cd` to that folder:

   ```cmd
   cd C:\AIUploadGuard
   ```
3. Run it:

   ```cmd
   python ai_upload_guard.py "<path-to-file>" --context client --assume-approved-tool
   ```

**Supported inputs:** `.txt`, `.md`, `.csv`, `.json`, `.yaml/.yml`, `.log`, `.pdf`, `.docx`, `.xlsx/.xls`

You’ll see progress messages like `[INFO] Running secrets checks…` so large files don’t look stalled.

---

## Common examples

Turn **off all financial checks** (fastest way to silence non-bank noise):

```cmd
python ai_upload_guard.py "C:\file.xlsx" --no-financial
```

Keep cards/IBAN, disable **bank hints**:

```cmd
python ai_upload_guard.py "C:\file.xlsx" --no-bank-hints
```

Limit output to **80 unique** findings (deduped with counts):

```cmd
python ai_upload_guard.py "C:\file.xlsx" --max-unique 80
```

Treat **IPs/hostnames/unknown IP-likes** as **PROHIBITED**:

```cmd
python ai_upload_guard.py "C:\file.xlsx" --ip-as-prohibited --hostnames-as-prohibited --unknown-as-prohibited
```

Flag internal domains/URLs:

```cmd
python ai_upload_guard.py "C:\file.xlsx" --internal-domains "(?:corp|intra)\.example\.com"
```

Suppress **noisy patterns** with ignore rules:

```cmd
python ai_upload_guard.py "C:\file.xlsx" --ignore "SWIFT\s*-\s*DEV" --ignore "^Financial: bank details"
```

---

## Options (quick reference)

**Context & clients**

* `--context [public|internal|client]` — declare ownership/context (default: `internal`)
* `--client-names "A|B|C"` — regex of client names to flag

**Financial toggles**

* `--no-financial` — disable all financial checks
* `--no-cc` — disable credit card detection
* `--no-iban` — disable IBAN detection
* `--no-bank-hints` — disable routing/sort/account/SWIFT hints

**Network sensitivity (escalation)**

* `--ip-as-prohibited` — treat IP/CIDR as PROHIBITED
* `--hostnames-as-prohibited` — treat hostname/URL/host\:port as PROHIBITED
* `--unknown-as-prohibited` — treat “Unknown: IP-like” as PROHIBITED

**Precision & noise controls**

* `--phone-context` — only flag phones if nearby words like “phone/tel” appear
* `--internal-domains "regex"` — mark matching hostnames/URLs as internal
* `--ignore "<regex>"` — ignore label/sample lines matching regex (repeatable)
* `--ignore-file "<path>"` — file containing one ignore regex per line
* `--max-unique N` — cap number of **unique** findings shown (default 200)
* `--no-dedupe` — print raw (very noisy) reasons

**Other**

* `--assume-approved-tool` — clean files shown as **ALLOWED\_WITH\_CONDITIONS**
* `--strict` — treat **RESTRICTED** signals as **PROHIBITED**

---

## Output format

* **Summary** — category counts (after de-duplication).
* **Top findings** — unique items with **(xN)** counts, ordered by severity.
* **Operational notes** — quick pointers for toggles that can help.

> Tip: Use `--max-unique` to keep the list readable on very large files.

---

## Ignore rules (examples)

Create a text file `ignore.txt`:

```
# Ignore VM labels
^Network: IP address \(IPv4\): 255\.255\.
^Financial: bank details
SWIFT\s*-\s*DEV
```

Run with:

```cmd
python ai_upload_guard.py "C:\file.xlsx" --ignore-file "C:\AIUploadGuard\ignore.txt"
```

---

## Interpreting results

* **Secrets, cards, IBANs, private keys, JWT/Bearer/Basic, DB strings** → **PROHIBITED**
* **IPs/hostnames/cloud IDs/sensitive field names** → **RESTRICTED** (or **PROHIBITED** if you use escalation flags)
* **Unknown IP-like** (e.g., `420-172.31.120.x`) → flagged for **human review** (you can escalate with `--unknown-as-prohibited`)
* **Clean** → **ALLOWED\*** only in approved tools and for legitimate business use

---

## Troubleshooting

* **`ModuleNotFoundError`** → `pip install pdfminer.six python-docx pandas openpyxl`
* **Can’t open `.xlsx`** → ensure `openpyxl` is installed; very old `.xls` may need extra drivers
* **Too slow on huge files** → rely on progress logs, or split files and use `--max-unique` / ignore rules
* **Too many network hits (masks/netmasks)** → use ignore rules for common patterns (e.g., `^Network: IP address \(IPv4\): 255\.`)

---

## Optional: double-click runner (batch)

Create `run_check.bat` in the same folder:

```bat
@echo off
setlocal
REM Drag & drop a file onto this .bat, or pass it as %1
if "%~1"=="" (
  echo Usage: run_check.bat "C:\path\to\file.ext"
  pause
  exit /b 1
)
python "%~dp0ai_upload_guard.py" "%~1" --context client --assume-approved-tool --max-unique 120 --no-bank-hints --phone-context
endlocal
```

---

## Suggestions (optional tightening)

* If network metadata is always sensitive for your use case, standardize on
  `--ip-as-prohibited --hostnames-as-prohibited --unknown-as-prohibited`.
* Maintain a shared `ignore.txt` for your environment’s recurring benign tokens (VM labels, mask constants, etc.).
* Consider adding a lightweight **allowlist** of known public endpoints to down-rank those matches (can be wired into `--ignore-file`).
