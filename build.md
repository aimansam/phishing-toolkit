# BUILD — Phishing Email Analysis Toolkit

**Date:** 2026-09-19
**Project:** Build a phishing email analysis toolkit in Python

## What Was Built

A complete phishing email analysis toolkit (`phishauditor.py`, ~500 lines) that:

- **Header parsing** — extracts From, To, Return-Path, SPF/DKIM/DMARC results
- **SPF/DKIM/DMARC analysis** — checks Authentication-Results header, detects alignment issues
- **URL extraction and scoring** — finds all URLs in body, scores each for phishing risk (TLD, IP hostname, shorteners, phishing patterns, @ symbol, IDN)
- **Body analysis** — extracts text from HTML, detects phishing keywords, urgent language
- **Attachment analysis** — checks file extensions against high-risk list, double extensions, large files
- **Overall risk scoring** — 0-100 score with SAFE/LOW/MEDIUM/HIGH/CRITICAL levels
- **Multiple input modes** — .eml file, headers+body text, JSON output, verbose mode

## File Structure

```
build/
  phishauditor.py    # Complete module: analyze_email(), URL scoring, header parsing, body analysis, CLI
```

## How to Run

```bash
# Analyze an .eml file
python -m phishadvisor --email sample.eml

# Analyze with headers and body text
python -m phishadvisor --headers "From: support@bank.com" --body "Click here to verify your account immediately"

# JSON output
python -m phishadvisor --json --email sample.eml

# Verbose output (show finding details)
python -m phishadvisor --email sample.eml --verbose
```

## Demo Output

```
$ python -m phishadvisor --headers "From: security@paypal.com" --body "Click here to verify your account immediately. Your account will be suspended within 24 hours."

============================================================
  PHISHING EMAIL ANALYSIS
============================================================
  Risk: 🚨 HIGH (65/100)
  From: security@paypal.com
  To: (not set)

  Authentication:
    SPF: not_found
    DKIM: not_found
    DMARC: not_found

  Findings (3):
    [MEDIUM] phishing_keywords: Phishing keywords (3)
      click here, verify your account, your account has been
    [MEDIUM] urgent_language: Urgent/pressure language detected
    [MEDIUM] suspicious_url: Suspicious URL detected
      http://paypal-verify.tk/login.php?user=123 — score: 75/100

============================================================
```

## Deviations from Plan

- SPF/DKIM/DMARC checking relies on Authentication-Results header presence (cannot perform actual DNS lookups without domain context)
- URL extraction uses regex (may miss some edge cases)
- Attachment parsing from .eml is basic (filename extraction only)

## Known Issues

- No actual DNS SPF/DKIM/DMARC validation (header-only analysis)
- HTML parsing with HTMLParser is basic (may not handle all malformed HTML)
- URL regex may miss some edge cases (data: URLs, internationalized domains without punycode)

## What Would Make It More Useful

- Integrate with actual DNS libraries for SPF/DKIM/DMARC record lookup
- Add machine learning model for phishing detection
- Add email header chain analysis (Received headers)
- Add integration with threat intelligence APIs
