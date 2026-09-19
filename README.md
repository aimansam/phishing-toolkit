# Phishing Toolkit

Phishing email analysis toolkit in Python. Parse and analyze email headers, body content, URLs, and attachments to detect phishing indicators.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


## Features

- **Header Analysis** — Parse and analyze email headers for spoofing indicators
- **Body Analysis** — Detect phishing keywords, urgent language, and social engineering patterns
- **URL Analysis** — Extract and score URLs for phishing risk (domain age, suspicious TLDs, mismatched links)
- **Attachment Analysis** — Identify high-risk attachment types (.exe, .js, .scr, etc.)
- **Raw Email Parsing** — Parse raw RFC 822 email files
- **Scoring System** — Overall phishing risk score with detailed findings
- **CLI Interface** — Command-line tool for batch analysis

## Installation

```bash
git clone https://github.com/aimansam/phishing-toolkit
cd phishing-toolkit
pip install -e .
```

## Quick Start

Analyze an email file:

```bash
phishadvisor --email email.eml
```

Analyze raw email text:

```bash
phishadvisor --headers "From: bank@example.com" --body "..."
```

Analyze with verbose output:

```bash
phishadvisor --email email.eml --verbose
```

## API Usage

```python
from phishauditor import analyze_email, AnalysisResult

result: AnalysisResult = analyze_email(raw_email_text)
print(f"Risk Level: {result.risk_level}")
print(f"Score: {result.score}/100")
for finding in result.findings:
    print(f"  [{finding.severity}] {finding.description}")
```

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## License

MIT
