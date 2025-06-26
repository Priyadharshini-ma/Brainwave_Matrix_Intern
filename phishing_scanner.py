#!/usr/bin/env python3
"""
Phishing Link Scanner
~~~~~~~~~~~~~~~~~~~~~
A simple command-line tool that scores a URL for common phishing traits.

How it works
------------
1. Basic validation (proper URL syntax).
2. Heuristic checks:
   • Uses raw IP address instead of domain?
   • Contains an "@" (user-info trick)?
   • Excessive length (> 100 chars)?
   • Too many sub-domains (> 3)?
   • Suspicious keywords (login, verify, update, secure, etc.)?
   • Punycode / IDN homograph?
   • Typosquatting: fuzzy match against popular brands (e.g., google, paypal).
3. Generates a risk score (0 – 100) and prints a verdict.

Author  : Priyadharshini M A
License : MIT
"""

import argparse
import re
import sys
from difflib import SequenceMatcher
from urllib.parse import unquote

import tldextract
import validators

# ---------------------------------------------------------------------------#
#  Configuration
# ---------------------------------------------------------------------------#
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "confirm",
    "banking",
    "paypal",
    "signin",
    "password",
}

POPULAR_BRANDS = {
    "google",
    "paypal",
    "facebook",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "instagram",
    "whatsapp",
    "twitter",
    "linkedin",
    "dropbox",
    "github",
    "bankofamerica",
}

# Threshold for fuzzy matching (0 – 1). 0.8 = 80 % similarity.
FUZZY_THRESHOLD = 0.8


# ---------------------------------------------------------------------------#
#  Helper functions
# ---------------------------------------------------------------------------#
def looks_like_ip(host: str) -> bool:
    """Return True if host is a raw IPv4 or IPv6 address."""
    ipv4 = re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)
    ipv6 = ":" in host and re.fullmatch(r"[0-9a-fA-F:]+", host)
    return bool(ipv4 or ipv6)


def contains_idn(host: str) -> bool:
    """Detect punycode (xn--) or mixed-script IDNs (e.g., Cyrillic look-alikes)."""
    return host.startswith("xn--") or any(ord(ch) > 127 for ch in host)


def fuzzy_match_brand(domain: str) -> bool:
    """Return True if domain closely resembles a popular brand (typosquatting)."""
    for brand in POPULAR_BRANDS:
        if SequenceMatcher(None, domain, brand).ratio() >= FUZZY_THRESHOLD and domain != brand:
            return True
    return False


def score_url(url: str) -> dict:
    """
    Examine a single URL and return a dictionary with details and risk score.
    Score logic (additive):
        +30 IP address instead of domain
        +15 contains "@"
        +10 excessive length (>100 chars)
        +10 too many subdomains (>3)
        +15 suspicious keywords in path/query
        +20 IDN / punycode
        +25 typosquatted brand
    """
    details = {
        "url": url,
        "valid": validators.url(url),
        "score": 0,
        "flags": [],
    }

    if not details["valid"]:
        details["flags"].append("invalid-url")
        details["score"] = 100  # treat invalid URL as highest risk
        return details

    decoded_url = unquote(url)
    ext = tldextract.extract(decoded_url)
    host = ext.fqdn
    subdomain_parts = [p for p in ext.subdomain.split(".") if p]

    # 1. Raw IP address
    if looks_like_ip(host):
        details["flags"].append("uses-ip-address")
        details["score"] += 30

    # 2. "@" symbol
    if "@" in decoded_url.split("//", 1)[-1]:
        details["flags"].append("contains-@")
        details["score"] += 15

    # 3. Long URL
    if len(decoded_url) > 100:
        details["flags"].append("long-url")
        details["score"] += 10

    # 4. Too many subdomains
    if len(subdomain_parts) > 3:
        details["flags"].append("many-subdomains")
        details["score"] += 10

    # 5. Suspicious keywords
    path_query = decoded_url.split(host, 1)[-1].lower()
    if any(word in path_query for word in SUSPICIOUS_KEYWORDS):
        details["flags"].append("suspicious-keywords")
        details["score"] += 15

    # 6. IDN / punycode
    if contains_idn(host):
        details["flags"].append("idn-punycode")
        details["score"] += 20

    # 7. Typosquatting
    if fuzzy_match_brand(ext.domain):
        details["flags"].append("brand-look-alike")
        details["score"] += 25

    details["score"] = min(details["score"], 100)
    return details


def verdict(score: int) -> str:
    if score >= 70:
        return "🔴 HIGH RISK (likely phishing)"
    if score >= 40:
        return "🟠 SUSPICIOUS"
    return "🟢 LOW RISK (likely safe)"


# ---------------------------------------------------------------------------#
#  CLI
# ---------------------------------------------------------------------------#
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Phishing Link Scanner – evaluate a URL for phishing signs."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Scan a single URL", metavar="URL")
    group.add_argument(
        "-f", "--file", help="File containing one URL per line", metavar="PATH"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    targets = []

    if args.url:
        targets.append(args.url.strip())
    else:
        try:
            with open(args.file, encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
        except IOError as exc:
            sys.exit(f"Error reading file: {exc}")

    for url in targets:
        data = score_url(url)
        v = verdict(data["score"])
        print(f"\nURL     : {data['url']}")
        print(f"Valid   : {data['valid']}")
        print(f"Score   : {data['score']} / 100")
        print(f"Flags   : {', '.join(data['flags']) or 'none'}")
        print(f"Verdict : {v}")

    print("\nDone ✔️")


if __name__ == "__main__":
    main()
