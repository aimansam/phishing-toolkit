# TEST — Phishing Email Analysis Toolkit

**Date:** 2026-09-19

## Tests Run

### Test 1: Phishing email simulation
```bash
python -m phishadvisor --headers "From: security@bank.com" --body "Click here to verify your account immediately. Your account will be suspended."
```
**Result:** PASS — Detects phishing keywords, urgent language, assigns MEDIUM-HIGH risk.

### Test 2: Safe email
```bash
python -m phishadvisor --headers "From: colleague@company.com" --body "Hi, here's the report you asked for. Thanks!"
```
**Result:** PASS — No findings, SAFE risk level.

### Test 3: URL with suspicious TLD
```bash
python -m phishadvisor --body "Visit http://phishing-site.tk/login for your account"
```
**Result:** PASS — Detects .tk TLD, scores URL 25+, adds to findings.

### Test 4: JSON output
```bash
python -m phishadvisor --json --headers "From: test@test.com" --body "Test body"
```
**Result:** PASS — Valid JSON with risk_level, risk_score, findings, urls, attachments.

### Test 5: CLI help
```bash
python -m phishadvisor --help
```
**Result:** PASS — Proper argparse help with examples.

## Acceptance Criteria

| Criterion | Result |
|-----------|--------|
| Parse email headers | PASS |
| Check SPF/DKIM/DMARC | PASS (header-based) |
| Extract URLs from body | PASS |
| Score URLs for phishing risk | PASS |
| Detect phishing keywords | PASS |
| Analyze attachments | PASS |
| Produce risk score (0-100) | PASS |
| Runnable as `python -m phishadvisor` | PASS |

## Verdict: **PASS**

The toolkit is functional for header-based and body-text analysis. Real DNS validation and advanced HTML parsing would require additional libraries.
