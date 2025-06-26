# 🔐 Phishing Link Scanner

A Python-based cybersecurity tool that analyzes URLs to detect potential phishing threats using heuristics and pattern matching.

## 🚀 Features

- ✅ Validates URL structure
- 🕵️ Detects:
  - IP address instead of domain
  - Use of '@' symbols (social engineering trick)
  - Excessive URL length
  - Too many subdomains
  - Suspicious keywords (e.g., login, verify, update)
  - IDN homograph attacks (Punycode)
  - Brand typosquatting (fuzzy match with popular domains)
- 🧠 Assigns a **risk score** and provides a **verdict**:
  - 🟢 Low Risk
  - 🟠 Suspicious
  - 🔴 High Risk

## 📦 Requirements

Install the dependencies using:

```bash
pip install -r requirements.txt
