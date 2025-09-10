#!/usr/bin/env python3
"""
AI Upload Guard — Heuristic checker for document upload safety pre-screening.

Purpose:
  Local pre-check to flag content that may be ALLOWED / RESTRICTED / PROHIBITED for AI-tool upload
  based on common risk indicators (PII, regulated data, secrets, source code, network info, client/internal markers).

Supported inputs:
  .txt, .md, .csv, .json, .yaml/.yml, .log, .pdf, .docx, .xlsx/.xls

Key detectors:
  - PII: email; phone (GUID/ID/IP-safe); SSN-like; address-like
  - Financial/regulated: STRICT credit cards (IIN + Luhn + realistic grouping), STRICT IBAN (country + length + MOD-97),
    bank details (STRICT, contextual: routing ABA, sort code, acct # with digits, SWIFT/BIC codes only)
  - Health (PHI context): diagnosis, medical record, etc. (keyword-based)
  - Secrets: keys/tokens/connection strings/private keys/high-entropy tokens/JWTs/auth headers/cookies
  - Source code: common language & SQL signals
  - Network: IPv4/IPv6, CIDR, host:port, MAC addresses, internal URLs/hostnames, cloud resource IDs
  - Schema clues: sensitive field/column names
  - Unknowns: IP-like partial/mixed tokens (e.g., "420-172.31.120.x") for human review

New in this version:
  • Financial toggles: --no-financial, --no-cc, --no-iban, --no-bank-hints
  • Ignore patterns: --ignore "regex" (repeatable) and --ignore-file <path>
  • Deduplicated output with counts + category summary; cap unique lines with --max-unique
  • Much stricter bank hints (no 'ACCT-ACPAY2', no 'SWIFT - DEV', no random 'FL...' hostnames)

Examples:
  python ai_upload_guard.py file.xlsx --context client --assume-approved-tool --no-financial
  python ai_upload_guard.py file.xlsx --no-bank-hints --ignore "SWIFT\s*-\s*DEV" --ignore "^Financial: bank details"
  python ai_upload_guard.py file.xlsx --max-unique 50 --ip-as-prohibited --unknown-as-prohibited
"""

import argparse
import ipaddress
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Optional deps
try:
    from pdfminer.high_level import extract_text as pdf_extract_text
except Exception:
    pdf_extract_text = None

try:
    import docx
except Exception:
    docx = None

try:
    import pandas as pd
except Exception:
    pd = None


# ---------- Text Extraction ----------
def read_text(path: Path) -> str:
    suffix = path.suffix.lower()

    if suffix in [".txt", ".md", ".csv", ".log", ".json", ".yaml", ".yml"]:
        return path.read_text(errors="ignore")

    if suffix == ".pdf":
        if not pdf_extract_text:
            raise RuntimeError("pdfminer.six not available. Install with: pip install pdfminer.six")
        return pdf_extract_text(str(path))

    if suffix == ".docx":
        if not docx:
            raise RuntimeError("python-docx not available. Install with: pip install python-docx")
        d = docx.Document(str(path))
        return "\n".join(p.text for p in d.paragraphs)

    if suffix in [".xlsx", ".xls"]:
        if not pd:
            raise RuntimeError("pandas not available. Install with: pip install pandas openpyxl")
        try:
            xls = pd.ExcelFile(str(path))
        except Exception as e:
            raise RuntimeError(f"Failed to open Excel file: {e}")

        chunks = []
        for sheet in xls.sheet_names:
            try:
                df = xls.parse(sheet, dtype=str).fillna("").astype(str)
            except Exception as e:
                chunks.append(f"[[Error reading sheet {sheet}: {e}]]")
                continue
            for r_idx, row in enumerate(df.values.tolist(), start=1):
                for c_idx, val in enumerate(row, start=1):
                    if val.strip():
                        chunks.append(f"{sheet}!R{r_idx}C{c_idx}: {val}")
        return "\n".join(chunks)

    raise RuntimeError(
        f"Unsupported file type: {suffix}. "
        f"Use .txt/.md/.csv/.json/.yaml/.yml/.log/.pdf/.docx/.xlsx/.xls"
    )


# ---------- Utilities ----------
def luhn_check(s: str) -> bool:
    digits_only = re.sub(r"\D", "", s)
    digits = [int(c) for c in digits_only]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def shannon_entropy(s: str) -> float:
    import collections
    if not s:
        return 0.0
    freq = collections.Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ---------- Span helpers ----------
def _compute_guid_spans(text: str):
    guid_re = re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    )
    return [m.span() for m in guid_re.finditer(text)]


def _compute_ip_spans(text: str):
    spans = []
    # IPv4
    for m in re.finditer(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', text):
        token = m.group(0)
        try:
            ipaddress.IPv4Address(token)
            spans.append(m.span())
        except Exception:
            pass
    # IPv6 (compressed/full)
    ipv6_cand = re.compile(
        r'(?<!\w)(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?!\w)'
        r'|(?<!\w)(?:[A-Fa-f0-9]{0,4}:){0,7}:(?:[A-Fa-f0-9]{1,4})?(?!\w)'
    )
    for m in ipv6_cand.finditer(text):
        token = m.group(0)
        try:
            ipaddress.IPv6Address(token)
            spans.append(m.span())
        except Exception:
            pass
    return spans


def _inside_any(spans, start, end) -> bool:
    return any(start >= s and end <= e for s, e in spans)


def _in_negative_id_context(text: str, start: int, end: int) -> bool:
    """
    Suppress phone detection when the candidate is near ID-ish context
    or inside bracketed tokens typical of logs/configs.
    """
    window = text[max(0, start - 40): min(len(text), end + 40)]
    if re.search(r"\[[\s\-]*\d{5,}[\s\-]*\]", window):  # [26002721]
        return True
    bad_ctx = re.compile(
        r"(?i)\b(job\s*id|job|ticket|case\s*id|case|backup|subclient|client|set|server|host|node|vm|volume|container|task|run\s*id|request\s*id|session|txn|txid|order|invoice|entry|alert|log|thread|process|pid|guid|uuid|object\s*id|doc\s*id|ref|backup\s*set)\b"
    )
    return bool(bad_ctx.search(window))


# ---------- PII ----------
def detect_pii(text: str, require_phone_context: bool = False):
    """
    Phone detection is strict:
      - E.164: +<7-14 digits>
      - NANP: (xxx) xxx-xxxx  OR  xxx-xxx-xxxx  OR  xxx xxx xxxx  OR  xxx.xxx.xxxx
      - Intl grouped: country & groups separated by spaces or hyphens ONLY (no dots)
      - Excludes GUID/UUID and any IP spans; rejects mixed hyphen+dot tokens
    """
    findings = []
    guid_spans = _compute_guid_spans(text)
    ip_spans = _compute_ip_spans(text)

    # Emails
    for m in re.finditer(r"\b[a-zA-Z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        if not _inside_any(guid_spans, *m.span()):
            findings.append(("PII: email", m.group(0)))

    # Phones
    e164 = re.compile(r"(?<!\w)\+\d{7,14}(?!\w)")
    nanp1 = re.compile(r"(?<!\w)\(\d{3}\)\s*\d{3}[-\s]?\d{4}(?!\w)")
    nanp2 = re.compile(r"(?<!\w)\d{3}[-\s]\d{3}[-\s]\d{4}(?!\w)")
    nanp3 = re.compile(r"(?<!\w)\d{3}\.\d{3}\.\d{4}(?!\w)")
    intl_sp_hy = re.compile(r"(?<!\w)(?:\+?\d{1,3}[-\s])(?:\d{2,4}[-\s]){2,4}\d{2,4}(?!\w)")
    phone_ctx = re.compile(r"(?i)\b(phone|tel|telephone|mobile|cell|call|contact)\b")

    phone_matches = []
    for pat in (e164, nanp1, nanp2, nanp3, intl_sp_hy):
        for m in pat.finditer(text):
            phone_matches.append(m)

    seen = set()
    for m in phone_matches:
        s, e = m.start(), m.end()
        if (s, e) in seen:
            continue
        seen.add((s, e))

        if _inside_any(guid_spans, s, e) or _inside_any(ip_spans, s, e):
            continue

        candidate = m.group(0)
        if "." in candidate and not re.fullmatch(r"\d{3}\.\d{3}\.\d{4}", candidate):
            continue
        if "-" in candidate and "." in candidate:
            continue

        digits = re.sub(r"\D", "", candidate)
        if not (7 <= len(digits) <= 15):
            continue

        if _in_negative_id_context(text, s, e):
            window = text[max(0, s - 40): min(len(text), e + 40)]
            if not phone_ctx.search(window):
                continue

        findings.append(("PII: phone", candidate))

    # SSN-like
    for m in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", text):
        if not _inside_any(guid_spans, *m.span()):
            findings.append(("PII: national ID/SSN-like", m.group(0)))

    # Address-like
    addr_pat = re.compile(
        r"\b\d{1,6}\s+[A-Za-z0-9.\- ]+\s+(Street|St\.|Avenue|Ave\.|Road|Rd\.|Lane|Ln\.|Boulevard|Blvd\.|Drive|Dr\.)\b",
        re.IGNORECASE
    )
    for m in addr_pat.finditer(text):
        if not _inside_any(guid_spans, *m.span()):
            findings.append(("PII: address-like", m.group(0)))

    return findings


# ---------- Financial / Regulated ----------
def _cc_iin_valid(digits: str) -> bool:
    l = len(digits)
    try:
        i2 = int(digits[:2]); i3 = int(digits[:3]); i4 = int(digits[:4]); i6 = int(digits[:6])
    except ValueError:
        return False

    if l == 13:
        return digits.startswith("4")
    if l == 15:
        return digits.startswith("34") or digits.startswith("37")  # Amex
    if l == 16:
        return (
            digits.startswith("4") or                                # Visa
            51 <= i2 <= 55 or                                        # MC old
            2221 <= i4 <= 2720 or                                    # MC 2-series
            digits.startswith("6011") or 644 <= i3 <= 649 or digits.startswith("65") or
            622126 <= i6 <= 622925                                   # Discover
        )
    if l == 19:
        return (
            digits.startswith("4") or
            digits.startswith("6011") or 644 <= i3 <= 649 or digits.startswith("65") or
            622126 <= i6 <= 622925
        )
    return False


def _cc_grouping_valid(candidate: str, digits: str) -> bool:
    if "." in candidate:
        return False
    sep_types = set(ch for ch in candidate if ch in "- ")
    if len(sep_types) > 1:
        return False
    if not sep_types:
        return True
    sep = "-" if "-" in sep_types else " "
    groups = [g for g in candidate.split(sep) if g]
    pat = tuple(len(g) for g in groups)
    l = len(digits)
    if l == 16:
        return pat == (4, 4, 4, 4)
    if l == 15:
        return pat == (4, 6, 5)
    if l == 19:
        return pat == (4, 4, 4, 4, 3)
    if l == 13:
        return len(sep_types) == 0
    return False


def _cc_embedded_in_guidish(text: str, start: int, end: int) -> bool:
    tail = text[end:end+7]
    return bool(re.match(r"-[0-9a-fA-F]{2,}", tail))


def detect_credit_cards_strict(text: str):
    findings = []
    guid_spans = _compute_guid_spans(text)
    cc_cand = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}\d(?!\d)")
    for m in cc_cand.finditer(text):
        s, e = m.start(), m.end()
        if _inside_any(guid_spans, s, e):
            continue
        cand = m.group(0)
        digits = re.sub(r"\D", "", cand)
        if len(digits) not in (13, 15, 16, 19):
            continue
        if _cc_embedded_in_guidish(text, s, e):
            continue
        if not _cc_grouping_valid(cand, digits):
            continue
        if not _cc_iin_valid(digits):
            continue
        if not luhn_check(digits):
            continue
        findings.append(("Regulated: credit card number (PCI)", cand))
    return findings


_IBAN_COUNTRIES = {
    "AL","AD","AT","AZ","BH","BE","BA","BG","CR","HR","CY","CZ","DK","DO","EE","FO","FI",
    "FR","GE","DE","GI","GR","GL","GT","HU","IS","IE","IL","IQ","IT","JO","KZ","XK","KW",
    "LV","LB","LI","LT","LU","MT","MR","MU","MD","MC","ME","NL","NO","PK","PS","PL","PT",
    "QA","RO","SM","SA","RS","SK","SI","ES","SE","CH","TN","TR","UA","AE","GB","VG"
}

def _iban_mod97(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    digits = ""
    for ch in rearranged:
        if ch.isdigit():
            digits += ch
        elif "A" <= ch <= "Z":
            digits += str(ord(ch) - 55)
        elif "a" <= ch <= "z":
            digits += str(ord(ch.upper()) - 55)
        else:
            return False
    rem = 0
    for c in digits:
        rem = (rem * 10 + int(c)) % 97
    return rem == 1

def detect_iban_strict(text: str):
    findings = []
    cand = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z0-9]{10,30}(?![A-Z0-9])")
    for m in cand.finditer(text):
        token = m.group(0)
        cc = token[:2].upper()
        if cc not in _IBAN_COUNTRIES:
            continue
        if not (15 <= len(token) <= 34):
            continue
        if not _iban_mod97(token):
            continue
        findings.append(("Financial: IBAN", token))
    return findings


def detect_bank_details_strict(text: str):
    """
    Strict contextual bank details:
      - Routing/ABA: 9 digits with 'routing' or 'aba' nearby
      - Sort Code: 6 digits or 2-2-2 format with 'sort code' nearby
      - Account/Acct: requires 8+ digits (no letters) near 'account'/'acct'
      - SWIFT/BIC: 8 or 11 character code (letters/digits), not VM names like 'SWIFT - DEV' or 'SWIFT-DB01B'
    """
    findings = []

    # Routing (ABA 9 digits)
    for m in re.finditer(r"(?i)\b(?:routing|aba)\b[:\s#-]*([0-9]{9})\b", text):
        findings.append(("Financial: bank details (routing)", m.group(0)))

    # Sort code (UK): 12 34 56 or 12-34-56 or 123456
    for m in re.finditer(r"(?i)\bsort\s*code\b[:\s#-]*((?:\d{2}[-\s]\d{2}[-\s]\d{2})|\d{6})", text):
        findings.append(("Financial: bank details (sort code)", m.group(0)))

    # Account number: require 8+ digits; allow spaces/hyphens but no letters in number token
    acct_pat = re.compile(r"(?i)\b(account(?:\s*number)?|acct)\b[:\s#-]*([0-9][0-9\-\s]{7,})")
    for m in acct_pat.finditer(text):
        num = re.sub(r"[\s\-]", "", m.group(2))
        if num.isdigit() and len(num) >= 8:
            findings.append(("Financial: bank details (account)", m.group(0)))

    # SWIFT/BIC code (8 or 11)
    # Real SWIFT/BIC: 4 letters bank + 2 letters country + 2 alnum location + optional 3 alnum branch
    for m in re.finditer(r"(?i)\b(?:SWIFT|BIC)\b[:\s#-]*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b", text):
        findings.append(("Financial: bank details (SWIFT/BIC)", m.group(0)))

    return findings


def detect_financial(text: str, enable_cc=True, enable_iban=True, enable_bank_hints=True):
    findings = []
    if enable_cc:
        findings += detect_credit_cards_strict(text)
    if enable_iban:
        findings += detect_iban_strict(text)
    if enable_bank_hints:
        findings += detect_bank_details_strict(text)
    return findings


# ---------- Health ----------
def detect_health(text: str):
    findings = []
    for kw in ["diagnosis", "medical record", "patient id", "prescription", "hipaa", "radiology", "lab result"]:
        for m in re.finditer(rf"\b{re.escape(kw)}\b", text, flags=re.IGNORECASE):
            findings.append(("Regulated: potential PHI context", m.group(0)))
    return findings


# ---------- Secrets ----------
def detect_secrets(text: str):
    findings = []
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "Secret: AWS Access Key ID"),
        (r"ASIA[0-9A-Z]{16}", "Secret: AWS STS Key ID"),
        (r"aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{30,})", "Secret: AWS Secret Access Key"),
        (r"(?i)api[_\- ]?key\s*[:=]\s*([A-Za-z0-9_\-]{16,})", "Secret: API key"),
        (r"(?i)token\s*[:=]\s*([A-Za-z0-9\-\._]{16,})", "Secret: token"),
        (r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Secret: Bearer token"),
        (r"(?i)\bAuthorization:\s*Basic\s+[A-Za-z0-9+/]{8,}={0,2}", "Secret: Basic auth header"),
        (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "Secret: JWT token"),
        (r"(?i)\bSet-Cookie:\s*[^;=\s]+=[^;\r\n]+", "Secret: session cookie"),
        (r"(?i)\bServer=[^;]+;[^;]*Database=[^;]+;[^;]*(?:User\s*Id|Uid)=[^;]+;[^;]*(?:Password|Pwd)=[^;]+;", "Secret: DB connection string"),
        (r"(?i)mongodb(?:\+srv)?:\/\/[^@\s:]+:[^@\s]+@", "Secret: MongoDB connection string"),
        (r"(?i)postgres(?:ql)?:\/\/[^@\s:]+:[^@\s]+@", "Secret: Postgres connection string"),
        (r"(?i)mysql:\/\/[^@\s:]+:[^@\s]+@", "Secret: MySQL connection string"),
        (r"(?i)amqps?:\/\/[^@\s:]+:[^@\s]+@", "Secret: MQ connection string"),
        (r"(?i)\bSharedAccessSignature=sr=[^&\s]+&sig=[^&\s]+&se=\d+", "Secret: Azure SAS token"),
        (r"(?i)\bAccountKey=([A-Za-z0-9+/=]{20,})", "Secret: Azure Storage AccountKey"),
        (r"ghp_[A-Za-z0-9]{36,}", "Secret: GitHub token"),
        (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Secret: Slack token"),
        (r"ssh-rsa\s+[A-Za-z0-9+/]{100,}={0,3}", "Secret: SSH public key"),
        (r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----", "Secret: Private key block"),
        (r'(?i)"private_key"\s*:\s*"-----BEGIN', "Secret: private key (JSON)"),
        (r"(?i)<password>[^<]{1,256}</password>", "Secret: password tag"),
    ]
    for pat, label in patterns:
        for m in re.finditer(pat, text):
            findings.append((label, m.group(0)))
    # High-entropy strings
    for m in re.finditer(r"[A-Za-z0-9+/]{32,}={0,2}", text):
        if shannon_entropy(m.group(0)) >= 4.0:
            findings.append(("Secret: high-entropy string", m.group(0)[:16] + "..."))
    return findings


# ---------- Source code ----------
def detect_source_code(text: str):
    findings = []
    code_signals = [
        r"\bclass\s+\w+\s*[:{]", r"\bdef\s+\w+\s*\(", r"\bimport\s+\w+",
        r"#include\s*<\w+\.h>", r"using\s+namespace\s+\w+",
        r"\bpublic\s+static\s+void\s+main\b", r"\bfunction\s+\w+\s*\(",
        r"\bconsole\.log\(", r"\bSELECT\s+.+\s+FROM\b",
        r"\bINSERT\s+INTO\b", r"\bCREATE\s+TABLE\b",
    ]
    for pat in code_signals:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            findings.append(("Source code / queries", m.group(0)))
    return findings


# ---------- Network ----------
def detect_network(text: str):
    findings = []

    # IPv4
    for m in re.finditer(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', text):
        token = m.group(0)
        try:
            ipaddress.IPv4Address(token)
            findings.append(("Network: IP address (IPv4)", token))
        except Exception:
            pass

    # IPv6
    ipv6_cand = re.compile(
        r'(?<!\w)(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?!\w)'
        r'|(?<!\w)(?:[A-Fa-f0-9]{0,4}:){0,7}:(?:[A-Fa-f0-9]{1,4})?(?!\w)'
    )
    for m in ipv6_cand.finditer(text):
        token = m.group(0)
        try:
            ipaddress.IPv6Address(token)
            findings.append(("Network: IP address (IPv6)", token))
        except Exception:
            pass

    # CIDR
    for m in re.finditer(r'(?<!\d)((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})(?!\d)', text):
        ip, pfx = m.group(1), int(m.group(2))
        try:
            ipaddress.IPv4Address(ip)
            if 0 <= pfx <= 32:
                findings.append(("Network: CIDR", m.group(0)))
        except Exception:
            pass

    # host:port
    hostport = re.compile(r'(?i)\b([a-z0-9\-\.]+|\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b')
    for m in hostport.finditer(text):
        port = int(m.group(2))
        if 1 <= port <= 65535:
            findings.append(("Network: host:port", m.group(0)))

    # MAC addresses
    mac_pat = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b')
    for m in mac_pat.finditer(text):
        findings.append(("Network: MAC address", m.group(0)))

    return findings


def detect_urls_hostnames(text: str, internal_domains_regex: str = ""):
    findings = []
    url_pat = re.compile(r'(?i)\bhttps?://[^\s<>"\']{3,}')
    internal_hint = re.compile(r'(?i)\.(?:local|internal|corp|lan)\b')
    dom_re = re.compile(internal_domains_regex, re.I) if internal_domains_regex else None

    for m in url_pat.finditer(text):
        url = m.group(0)
        host_m = re.search(r'(?i)https?://([^/\s:]+)', url)
        host = host_m.group(1) if host_m else ""
        if (dom_re and dom_re.search(host)) or internal_hint.search(host):
            findings.append(("Network: URL", url))

    # Hostnames (FQDN-ish); skip emails
    host_pat = re.compile(r'\b[a-z0-9](?:[a-z0-9\-]{0,62})(?:\.[a-z0-9](?:[a-z0-9\-]{0,62})){1,}\b', re.I)
    for m in host_pat.finditer(text):
        start = m.start()
        if start > 0 and text[start-1] == '@':
            continue
        host = m.group(0)
        if (dom_re and dom_re.search(host)) or internal_hint.search(host):
            findings.append(("Network: hostname", host))
    return findings


def detect_cloud_ids(text: str):
    findings = []
    patterns = [
        (r'\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s]+', "Network: cloud resource (AWS ARN)"),
        (r'(?i)/subscriptions/[0-9a-f\-]{36}/resourceGroups/[^/\s]+/providers/[^/\s]+/.+?(?=\s|$)', "Network: cloud resource (Azure)"),
        (r'(?i)\bprojects/[a-z0-9\-]+/(?:instances|topics|subscriptions|buckets)/[^\s]+', "Network: cloud resource (GCP)"),
    ]
    for pat, label in patterns:
        for m in re.finditer(pat, text):
            findings.append((label, m.group(0)))
    return findings


def detect_sensitive_headers(text: str):
    findings = []
    keywords = [
        "ssn","social_security","national_id","dob","date_of_birth","patient_id","mrn","hipaa","phi",
        "card_number","cc_number","cvv","cvc","iban","routing_number","account_number",
        "password","passwd","passphrase","secret","api_key","token","private_key"
    ]
    header_pat = re.compile(r'(?i)\b(' + "|".join(map(re.escape, keywords)) + r')\b')
    for m in header_pat.finditer(text):
        findings.append(("Network: sensitive field name", m.group(0)))
    return findings


def detect_unknown_network_like(text: str):
    findings = []
    mixed = re.compile(r'\b\d{1,4}(?:(?:[-.])\d{1,4}){2,}\w*\b')
    masked = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){1,3}\.(?:x|X|\*)\b')
    dotted = re.compile(r'\b\d{1,4}(?:\.\d{1,4}){2,}\d{1,4}\b')

    def is_ipv4(token: str) -> bool:
        try:
            ipaddress.IPv4Address(token)
            return True
        except Exception:
            return False

    for pat in (mixed, masked, dotted):
        for m in pat.finditer(text):
            tok = m.group(0)
            if is_ipv4(tok) or re.fullmatch(r"\d{3}\.\d{3}\.\d{4}", tok):
                continue
            findings.append(("Unknown: IP-like (requires review)", tok))
    return findings


def detect_client_internal(text: str, client_regex: str, context: str):
    findings = []
    if client_regex:
        for m in re.finditer(client_regex, text, flags=re.IGNORECASE):
            findings.append(("Client identifier", m.group(0)))
    for pat in [r"\bCONFIDENTIAL\b", r"\bINTERNAL USE ONLY\b", r"\bPROPRIETARY\b"]:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            findings.append(("Classification marker", m.group(0)))
    if context.lower() in ["client", "internal"]:
        findings.append(("Context", f"user-declared:{context.lower()}"))
    return findings


# ---------- Ignore filters ----------
def load_ignore_patterns(ignore_list, ignore_file):
    patterns = []
    if ignore_list:
        for rx in ignore_list:
            try:
                patterns.append(re.compile(rx, re.I))
            except re.error:
                print(f"[WARN] Invalid ignore regex skipped: {rx}")
    if ignore_file:
        try:
            for line in Path(ignore_file).read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    patterns.append(re.compile(line, re.I))
                except re.error:
                    print(f"[WARN] Invalid ignore regex in file skipped: {line}")
        except Exception as e:
            print(f"[WARN] Could not read ignore file: {e}")
    return patterns


def apply_ignores(findings, patterns):
    if not patterns:
        return findings
    out = []
    for label, sample in findings:
        text = f"{label} {sample}"
        if any(p.search(text) for p in patterns):
            continue
        out.append((label, sample))
    return out


# ---------- Policy Disposition ----------
def policy_disposition(findings, strict: bool, assume_approved_tool: bool,
                       ip_as_prohibited: bool, hostnames_as_prohibited: bool,
                       unknown_as_prohibited: bool):
    labels = [f[0] for f in findings]

    if ip_as_prohibited and any(lbl.startswith("Network: IP") or lbl == "Network: CIDR" for lbl in labels):
        return "PROHIBITED"
    if hostnames_as_prohibited and any(lbl in ("Network: hostname", "Network: URL", "Network: host:port") for lbl in labels):
        return "PROHIBITED"
    if unknown_as_prohibited and any(lbl.startswith("Unknown:") for lbl in labels):
        return "PROHIBITED"

    if any(lbl.startswith(("PII:", "Regulated:", "Secret:", "Source code")) for lbl in labels):
        return "PROHIBITED"

    if any(lbl.startswith(("Client identifier", "Classification marker", "Context", "Network:", "Unknown:")) for lbl in labels):
        return "PROHIBITED" if strict else "RESTRICTED"

    return "ALLOWED_WITH_CONDITIONS" if assume_approved_tool else "ALLOWED_IF_IN_APPROVED_TOOL"


# ---------- Output helpers ----------
def severity_rank(label: str) -> int:
    if label.startswith(("Secret:", "Regulated:", "PII:", "Source code")):
        return 1
    if label.startswith(("Network:", "Client identifier", "Classification marker", "Unknown:")):
        return 2
    return 3

def category_name(label: str) -> str:
    if label.startswith("Source code"):
        return "Source code"
    return label.split(":")[0]

def print_summary(findings):
    cat_counts = Counter(category_name(lbl) for lbl, _ in findings)
    if not cat_counts:
        print("Summary: no findings.")
        return
    print("Summary (unique lines, post-dedupe):")
    for cat, cnt in sorted(cat_counts.items(), key=lambda kv: ({"Secret":0,"Regulated":1,"PII":2,"Source code":3,"Network":4,"Client identifier":5,"Classification marker":6,"Unknown":7}.get(kv[0], 99), -kv[1], kv[0])):
        print(f" - {cat}: {cnt}")


# ---------- CLI ----------
def build_arg_parser():
    ap = argparse.ArgumentParser(
        description="AI Upload Guard — policy-aligned document checker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    ap.add_argument("file", type=str,
                    help="Path to .txt/.md/.csv/.json/.yaml/.yml/.log/.pdf/.docx/.xlsx/.xls")
    ap.add_argument("--client-names", type=str, default="",
                    help='Regex of client names: e.g., "Acme|Contoso|Globex"')
    ap.add_argument("--context", type=str, default="internal",
                    choices=["public", "internal", "client"],
                    help="Ownership/confidentiality context (declared)")
    ap.add_argument("--assume-approved-tool", action="store_true",
                    help="Assume an approved tool is being used (affects ALLOWED* wording).")
    ap.add_argument("--strict", action="store_true",
                    help="Treat restricted signals as PROHIBITED.")
    ap.add_argument("--ip-as-prohibited", action="store_true",
                    help="Escalate IP/CIDR findings to PROHIBITED.")
    ap.add_argument("--hostnames-as-prohibited", action="store_true",
                    help="Escalate hostname/URL/host:port findings to PROHIBITED.")
    ap.add_argument("--unknown-as-prohibited", action="store_true",
                    help="Escalate Unknown: IP-like findings to PROHIBITED.")
    ap.add_argument("--phone-context", action="store_true",
                    help="Only flag phone numbers if phone-related words appear nearby.")
    ap.add_argument("--internal-domains", type=str, default="",
                    help="Regex for internal domains/hosts to flag (e.g., '(?:corp|intra)\\.example\\.com').")
    ap.add_argument("--max-findings", type=int, default=100,
                    help="(Legacy) cap raw prints; replaced by --max-unique for deduped output.")
    # NEW: financial toggles
    ap.add_argument("--no-financial", action="store_true", help="Disable all financial checks.")
    ap.add_argument("--no-cc", action="store_true", help="Disable credit card detection.")
    ap.add_argument("--no-iban", action="store_true", help="Disable IBAN detection.")
    ap.add_argument("--no-bank-hints", action="store_true", help="Disable bank details (routing/sort/acct/SWIFT) detection.")
    # NEW: ignore + dedupe
    ap.add_argument("--ignore", action="append", default=[], help='Regex to ignore (label/sample). Repeatable.')
    ap.add_argument("--ignore-file", type=str, default="", help="Path to file with one regex per line to ignore.")
    ap.add_argument("--max-unique", type=int, default=200, help="Show at most this many unique lines (post-dedupe).")
    ap.add_argument("--no-dedupe", action="store_true", help="Print raw, non-deduped reasons (not recommended).")
    return ap


# ---------- Main ----------
def main():
    ap = build_arg_parser()
    args = ap.parse_args()

    p = Path(args.file)
    if not p.exists():
        print(f"File not found: {p}", file=sys.stderr)
        sys.exit(2)

    print(f"[INFO] Reading file: {p}")
    text = read_text(p)
    print(f"[INFO] File loaded ({len(text)} characters). Starting checks...")

    findings = []

    print("[INFO] Running PII checks...")
    findings += detect_pii(text, require_phone_context=args.phone_context)

    if not args.no_financial:
        print("[INFO] Running financial checks (strict cards + IBAN + bank hints)...")
        findings += detect_financial(
            text,
            enable_cc=not args.no_cc,
            enable_iban=not args.no_iban,
            enable_bank_hints=not args.no_bank_hints
        )
    else:
        print("[INFO] Skipping financial checks (--no-financial).")

    print("[INFO] Running health/PHI checks...")
    findings += detect_health(text)

    print("[INFO] Running secrets checks...")
    findings += detect_secrets(text)

    print("[INFO] Running source code checks...")
    findings += detect_source_code(text)

    print("[INFO] Running network/IP checks...")
    findings += detect_network(text)

    print("[INFO] Running URL/hostname checks...")
    findings += detect_urls_hostnames(text, internal_domains_regex=args.internal_domains)

    print("[INFO] Running cloud resource ID checks...")
    findings += detect_cloud_ids(text)

    print("[INFO] Checking for sensitive field/column names...")
    findings += detect_sensitive_headers(text)

    print("[INFO] Running client/internal markers checks...")
    findings += detect_client_internal(text, args.client_names, args.context)

    print("[INFO] Flagging unknown IP-like tokens for human review...")
    findings += detect_unknown_network_like(text)

    # Apply ignores
    ignore_patterns = load_ignore_patterns(args.ignore, args.ignore_file)
    if ignore_patterns:
        print(f"[INFO] Applying {len(ignore_patterns)} ignore pattern(s).")
        findings = apply_ignores(findings, ignore_patterns)

    print("[INFO] All checks complete. Compiling disposition...")
    disposition = policy_disposition(
        findings,
        strict=args.strict,
        assume_approved_tool=args.assume_approved_tool,
        ip_as_prohibited=args.ip_as_prohibited,
        hostnames_as_prohibited=args.hostnames_as_prohibited,
        unknown_as_prohibited=args.unknown_as_prohibited
    )

    # Dedupe + counts
    if not findings:
        unique = []
        pair_counts = Counter()
    else:
        if args.no_dedupe:
            unique = findings
            pair_counts = Counter((lbl, samp) for lbl, samp in findings)
        else:
            pair_counts = Counter((lbl, samp) for lbl, samp in findings)
            unique = list(pair_counts.keys())

    # Sort by severity, then label, then count desc
    unique_sorted = sorted(
        unique,
        key=lambda ls: (severity_rank(ls[0]), ls[0], -pair_counts[ls])
    )

    print("\n=== AI Upload Guard Report ===")
    print(f"File: {p}")
    print(f"Declared context: {args.context}")
    print(f"Disposition: {disposition}\n")

    # Summary
    print_summary(unique_sorted)
    print()

    # Detailed (deduped) reasons
    if unique_sorted:
        print(f"Top findings (unique; up to {args.max_unique}):")
        for i, (label, sample) in enumerate(unique_sorted[: args.max_unique], start=1):
            count = pair_counts[(label, sample)]
            snippet = (sample[:200] + "…") if len(sample) > 200 else sample
            print(f" {i:>3}. {label}: {snippet}   (x{count})")
        if len(unique_sorted) > args.max_unique:
            print(f" ... ({len(unique_sorted) - args.max_unique} more unique lines not shown)")
    else:
        print("No risk indicators detected by heuristics.")

    print("\nOperational Notes:")
    print(" - Use --no-financial / --no-cc / --no-iban / --no-bank-hints to turn off or dial down financial checks.")
    print(' - Use --ignore "<regex>" (repeatable) and/or --ignore-file to suppress noisy patterns (e.g., SWIFT\\s*-\\s*DEV).')
    print(" - Output is deduplicated with counts; use --no-dedupe to see raw lines (not recommended for large files).")
    print(" - Use --ip-as-prohibited / --hostnames-as-prohibited / --unknown-as-prohibited to tighten policy.")
    print(" - Heuristic pre-check; human judgment still required.")

if __name__ == "__main__":
    main()
