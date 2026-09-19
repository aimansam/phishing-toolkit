#!/usr/bin/env python3
"""
Phishing Email Analysis Toolkit — parses email headers and body content,
checks SPF/DKIM/DMARC alignment, extracts and scores suspicious URLs against
threat intelligence patterns, analyzes attachment metadata, and produces a
phishing risk score with detailed findings.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from typing import Optional


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    type: str
    severity: RiskLevel
    description: str
    detail: str = ""


@dataclass
class AnalysisResult:
    subject: str = ""
    from_address: str = ""
    to_addresses: list[str] = field(default_factory=list)
    spf_result: str = "not_checked"
    dkim_result: str = "not_checked"
    dmarc_result: str = "not_checked"
    alignment_issues: list[str] = field(default_factory=list)
    suspicious_urls: list[dict] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    findings: list[Finding] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: int = 0


URL_REGEX = re.compile(
    r'https?://(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/?|[/?]\S+)',
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "men", "date", "adult", "xyz", "top", "work", "club", "download", "review", "stream", "bid", "loan", "racing", "win", "trade", "crypto"}

PHISHING_URL_PATTERNS = [
    (r'login', "Login page mimic"), (r'sign.?in', "Sign-in page mimic"),
    (r'account', "Account-related page"), (r'verify', "Verification page"),
    (r'secure', "Security-themed page"), (r'update', "Update prompt"),
    (r'confirm', "Confirmation prompt"), (r'bank', "Banking-related"),
    (r'paypal', "PayPal mimic"), (r'apple.?id', "Apple ID mimic"),
    (r'google', "Google mimic"), (r'amazon', "Amazon mimic"),
    (r'facebook', "Facebook mimic"), (r'microsoft', "Microsoft mimic"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "IP address as hostname"),
    (r'xn--', "IDN/punycode domain"), (r'bit\.ly|tinyurl|goo\.gl|ow\.ly', "URL shortener"),
    (r'\.php\?.*=', "PHP query string"), (r'\.asp\?.*=', "ASP query string"),
]

PHISHING_BODY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify your account",
    "suspended", "terminated", "unauthorized access", "security alert",
    "confirm your identity", "click here", "update your information",
    "your account has been", "limited time", "expire", "winner",
    "congratulations", "you have won", "claim your", "free money",
    "prize", "within 24 hours", "final notice", "failure to comply",
]

HIGH_RISK_ATTACHMENTS = {
    ".exe": "Executable", ".scr": "Screensaver (executable)", ".bat": "Batch script",
    ".cmd": "Command script", ".ps1": "PowerShell script", ".vbs": "VBScript",
    ".js": "JavaScript", ".hta": "HTML application", ".wsf": "Windows Script File",
    ".reg": "Registry script", ".msi": "Installer", ".jar": "Java archive",
    ".zip": "Compressed archive", ".rar": "Compressed archive",
    ".docm": "Word with macros", ".xlsm": "Excel with macros", ".pptm": "PowerPoint with macros",
    ".doc": "Legacy Word (DDE risk)",
}


class BodyTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.text_parts.append(data)

    def get_text(self) -> str:
        return " ".join(self.text_parts)


def extract_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def extract_display_links(html: str) -> list[dict]:
    links = []
    for m in re.finditer(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL):
        href, display = m.group(1), re.sub(r'<[^>]+>', '', m.group(2)).strip()
        if display and href and display.lower() != href.lower():
            links.append({"display": display, "href": href})
    return links


def score_url(url: str) -> tuple[int, list[str]]:
    score, reasons = 0, []
    url_lower, domain = url.lower(), ""

    dm = re.search(r'https?://([^/]+)', url, re.IGNORECASE)
    if dm:
        domain = dm.group(1)

    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
        score, reasons = 30, ["Uses IP address instead of domain name"]

    tld_m = re.search(r'\.([a-z]+)(?::|\/|$|\?)', domain)
    if tld_m and tld_m.group(1).lower() in SUSPICIOUS_TLDS:
        score, reasons = score + 25, reasons + [f"Suspicious TLD: .{tld_m.group(1)}"]

    for s in ["bit.ly", "tinyurl", "goo.gl", "ow.ly"]:
        if s in domain:
            score, reasons = score + 15, reasons + [f"URL shortener: {s}"]
            break

    for pat, reason in PHISHING_URL_PATTERNS:
        if re.search(pat, url_lower):
            score, reasons = score + 10, reasons + [reason]
            break

    if len(domain.split('.')) > 3:
        score, reasons = score + 10, reasons + [f"Excessive subdomains ({len(domain.split('.'))} parts)"]

    if '@' in url and not url.startswith('mailto:'):
        score, reasons = score + 25, reasons + ["URL contains @ symbol (credential harvesting)"]

    if url.startswith('http://') and not url.startswith('https://'):
        score, reasons = score + 5, reasons + ["Uses unencrypted HTTP"]

    if 'xn--' in domain:
        score, reasons = score + 20, reasons + ["IDN/punycode domain"]

    return min(score, 100), reasons


def analyze_headers(headers_text: str) -> dict:
    result = {"spf_result": "not_found", "dkim_result": "not_found", "dmarc_result": "not_found",
              "from_address": "", "to_addresses": [], "return_path": "", "received_spf": "", "authentication_results": ""}
    current_header, current_value = "", ""

    for line in headers_text.split('\n'):
        if line.startswith(' ') or line.startswith('\t'):
            current_value += line.strip()
        else:
            if current_header:
                _ph(current_header, current_value, result)
            parts = line.split(':', 1)
            if len(parts) == 2:
                current_header, current_value = parts[0].strip().lower(), parts[1].strip()
            else:
                current_header, current_value = "", ""

    if current_header:
        _ph(current_header, current_value, result)

    auth = result.get("authentication_results", "").lower()
    for proto in ("spf", "dkim", "dmarc"):
        if f'{proto}=' in auth:
            m = re.search(rf'{proto}=(\w+)', auth)
            if m:
                result[f'{proto}_result'] = m.group(1).upper()
    if result["spf_result"] == "not_found" and result.get("received_spf"):
        result["spf_result"] = result["received_spf"].upper()
    return result


def _ph(name: str, value: str, r: dict) -> None:
    if name == "from": r["from_address"] = value
    elif name == "to": r["to_addresses"] = [a.strip() for a in value.split(',')]
    elif name == "return-path": r["return_path"] = value
    elif name == "received-spf": r["received_spf"] = value
    elif name == "authentication-results": r["authentication_results"] = value


def analyze_body(body: str, ct: str = "text/plain") -> dict:
    result = {"text": body, "html": "", "suspicious_urls": [], "phishing_keywords": [],
              "urgent_language": False, "threat_score": 0}

    if ct == "text/html" or "<html" in body.lower() or "<body" in body.lower():
        result["html"] = body
        try:
            parser = BodyTextExtractor()
            parser.feed(body)
            result["text"] = parser.get_text()
        except Exception:
            result["text"] = body

    tl = result["text"].lower()
    kw = [k for k in PHISHING_BODY_KEYWORDS if k in tl]
    result["phishing_keywords"] = kw

    for pat in [r'urgent\s+(action|attention|response)', r'\bimmediately\b', r'within\s+\d+\s*hours', r'final\s+notice', r'last\s+chance']:
        if re.search(pat, tl):
            result["urgent_language"] = True
            break

    urls = extract_urls(result["text"])
    if result["html"]:
        urls.extend(d["href"] for d in extract_display_links(result["html"]))

    for url in urls:
        s, rs = score_url(url)
        result["suspicious_urls"].append({"url": url, "score": s, "reasons": rs})
        result["threat_score"] = max(result["threat_score"], s)

    if len(kw) >= 3: result["threat_score"] = max(result["threat_score"], 40)
    if result["urgent_language"]: result["threat_score"] = max(result["threat_score"], 30)

    return result


def analyze_attachments(atts: list[dict]) -> list[dict]:
    results = []
    for a in atts:
        fn = (a.get("filename") or "").lower()
        sz = a.get("size", 0)
        r = {"filename": a.get("filename", ""), "size": sz, "risk_level": RiskLevel.SAFE, "risk_score": 0, "reasons": []}

        for ext, desc in HIGH_RISK_ATTACHMENTS.items():
            if fn.endswith(ext):
                r["risk_level"], r["risk_score"], r["reasons"] = RiskLevel.HIGH, 70, [f"High-risk: {desc} ({ext})"]
                break

        if len(fn.rsplit('.', 2)) >= 3:
            r["risk_level"] = max(r["risk_level"], RiskLevel.MEDIUM)
            r["risk_score"] = max(r["risk_score"], 40)
            r["reasons"].append(f"Double extension: {'.'.join(fn.rsplit('.', 2)[-2:])}")

        if sz > 10 * 1024 * 1024:
            r["risk_level"] = max(r["risk_level"], RiskLevel.MEDIUM)
            r["risk_score"] = max(r["risk_score"], 20)
            r["reasons"].append("Large file (>10MB)")

        results.append(r)
    return results


def analyze_email(headers_text: str, body_text: str = "", body_html: str = "", attachments: list[dict] = None) -> AnalysisResult:
    result, attachments = AnalysisResult(), attachments or []
    h = analyze_headers(headers_text)
    result.from_address, result.to_addresses = h["from_address"], h["to_addresses"]
    result.spf_result, result.dkim_result, result.dmarc_result = h["spf_result"], h["dkim_result"], h["dmarc_result"]
    result.return_path = h.get("return_path", "")

    issues = []
    fd = ""
    if '@' in h["from_address"]:
        fd = h["from_address"].split('@')[1].lower()
    rp = h.get("return_path", "")
    if rp and '@' in rp:
        rpd = rp.split('@')[1].lower()
        if fd and fd != rpd:
            issues.append(f"Return-Path domain ({rpd}) != From domain ({fd})")

    if h["spf_result"] in ("FAIL", "SOFTFAIL"):
        issues.append(f"SPF: {h['spf_result']}")
    if h["dkim_result"] in ("FAIL", "NONE"):
        issues.append(f"DKIM: {h['dkim_result']}")
    if h["dmarc_result"] in ("FAIL", "QUARANTINE"):
        issues.append(f"DMARC: {h['dmarc_result']}")
    result.alignment_issues = issues

    ba = analyze_body(body_text if body_text else (body_text + "\n" + body_html), "text/html" if body_html else "text/plain")
    result.body_text, result.body_html = body_text, body_html

    if not body_text and body_html:
        result.body_text = ba["text"]

    for ui in ba["suspicious_urls"]:
        if ui["score"] >= 30:
            result.findings.append(Finding("suspicious_url", RiskLevel.HIGH if ui["score"] >= 70 else RiskLevel.MEDIUM,
                                           "Suspicious URL", f"{ui['url']} — score: {ui['score']}/100. {'; '.join(ui['reasons'])}"))
            result.suspicious_urls.append(ui)

    if ba["phishing_keywords"]:
        sev = RiskLevel.HIGH if len(ba["phishing_keywords"]) >= 3 else RiskLevel.MEDIUM
        result.findings.append(Finding("phishing_keywords", sev, f"Phishing keywords ({len(ba['phishing_keywords'])})", ", ".join(ba["phishing_keywords"][:5])))

    if ba["urgent_language"]:
        result.findings.append(Finding("urgent_language", RiskLevel.MEDIUM, "Urgent/pressure language", "Email uses urgency to pressure recipient"))

    for ar in analyze_attachments(attachments):
        if ar["risk_score"] >= 40:
            result.findings.append(Finding("suspicious_attachment", ar["risk_level"], f"Risky attachment: {ar['filename']}", f"Risk: {ar['risk_score']}/100. {'; '.join(ar['reasons'])}"))
            result.attachments.append(ar)

    if issues:
        sev = RiskLevel.HIGH if any("FAIL" in i for i in issues) else RiskLevel.MEDIUM
        result.findings.append(Finding("authentication_mismatch", sev, "Email authentication issues", "; ".join(issues)))

    rs = sum({RiskLevel.SAFE: 0, RiskLevel.LOW: 5, RiskLevel.MEDIUM: 15, RiskLevel.HIGH: 30, RiskLevel.CRITICAL: 50}.get(f.severity, 0) for f in result.findings)
    rs = min(100, rs + ba["threat_score"])
    result.risk_score = max(0, min(100, rs))

    if rs >= 70: result.risk_level = RiskLevel.CRITICAL
    elif rs >= 50: result.risk_level = RiskLevel.HIGH
    elif rs >= 30: result.risk_level = RiskLevel.MEDIUM
    elif rs >= 10: result.risk_level = RiskLevel.LOW
    return result


def parse_raw_email(raw: str) -> tuple[str, str, str, list[dict]]:
    parts = raw.split('\n\n', 1)
    ht, body = parts[0] if parts else "", parts[1] if len(parts) > 1 else ""
    bh, bt = "", body
    if '<html' in body.lower() or '<body' in body.lower():
        bh = body
        try:
            p = BodyTextExtractor(); p.feed(body); bt = p.get_text()
        except Exception: bt = ""
    atts = [{"filename": f.strip(), "size": 0} for f in re.findall(r'Content-Disposition:\s*attachment;\s*filename=["\']?([^"\';\n]+)["\']?', body, re.IGNORECASE)]
    return ht, bt, bh, atts


def main():
    parser = argparse.ArgumentParser(description="Phishing Email Analysis Toolkit", formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python -m phishadvisor --email sample.eml\n  python -m phishadvisor --headers 'From: phisher@evil.com' --body 'Click here to verify...'\n  python -m phishadvisor --json --email sample.eml")
    parser.add_argument("--email", "-e", help="Path to .eml file")
    parser.add_argument("--headers", help="Email headers text")
    parser.add_argument("--body", help="Email body text")
    parser.add_argument("--body-html", help="Email body HTML")
    parser.add_argument("--headers-file", help="File with headers")
    parser.add_argument("--body-file", help="File with body")
    parser.add_argument("--attachments", help="JSON file with attachment list")
    parser.add_argument("--json", "-j", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    ht, bt, bh, atts = args.headers or "", args.body or "", args.body_html or "", []
    if args.email:
        try:
            with open(args.email) as f: ht, bt, bh, atts = parse_raw_email(f.read())
        except FileNotFoundError: print(f"Error: {args.email} not found", file=sys.stderr); return 1
    if args.headers_file:
        try:
            with open(args.headers_file) as f: ht = f.read()
        except FileNotFoundError: print(f"Error: {args.headers_file} not found", file=sys.stderr); return 1
    if args.body_file:
        try:
            with open(args.body_file) as f: bt = f.read()
        except FileNotFoundError: print(f"Error: {args.body_file} not found", file=sys.stderr); return 1
    if args.attachments:
        try:
            with open(args.attachments) as f: atts = json.loads(f.read())
        except Exception as e: print(f"Error: {e}", file=sys.stderr); return 1

    result = analyze_email(ht, bt, bh, atts)

    if args.json:
        print(json.dumps({
            "risk_level": result.risk_level.value, "risk_score": result.risk_score,
            "from_address": result.from_address, "to_addresses": result.to_addresses,
            "spf": result.spf_result, "dkim": result.dkim_result, "dmarc": result.dmarc_result,
            "alignment_issues": result.alignment_issues, "suspicious_urls": result.suspicious_urls,
            "attachments": result.attachments,
            "findings": [{"type": f.type, "severity": f.severity.value, "description": f.description, "detail": f.detail} for f in result.findings],
        }, indent=2))
        return 0

    emoji = {"safe": "✅", "low": "⚠️", "medium": "⚠️", "high": "🚨", "critical": "🔴"}
    print(f"\n{'='*60}\n  PHISHING EMAIL ANALYSIS\n{'='*60}")
    print(f"  Risk: {emoji.get(result.risk_level.value, '?')} {result.risk_level.value.upper()} ({result.risk_score}/100)")
    print(f"  From: {result.from_address or '(not set)'}")
    print(f"  To: {', '.join(result.to_addresses) if result.to_addresses else '(not set)'}")
    print(f"\n  Authentication:\n    SPF: {result.spf_result}\n    DKIM: {result.dkim_result}\n    DMARC: {result.dmarc_result}")
    if result.alignment_issues:
        print(f"\n  Issues:"); [print(f"    - {i}") for i in result.alignment_issues]
    if result.findings:
        print(f"\n  Findings ({len(result.findings)}):")
        for f in result.findings:
            print(f"    [{f.severity.value.upper()}] {f.type}: {f.description}")
            if args.verbose and f.detail: print(f"      {f.detail}")
    if result.suspicious_urls:
        print(f"\n  URLs ({len(result.suspicious_urls)}):")
        for u in result.suspicious_urls: print(f"    - {u['url']} (score: {u['score']})")
    if result.attachments:
        print(f"\n  Attachments:")
        for a in result.attachments: print(f"    - {a['filename']} (risk: {a['risk_score']})")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
