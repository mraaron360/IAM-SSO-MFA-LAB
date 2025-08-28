# 🔐 IAM SSO + MFA Lab

[![Python](https://img.shields.io/badge/Python-3.10+-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)]()

Hands-on lab showcasing **Okta OIDC + SAML** SSO and **MFA automation**.

## 🚀 Features
- OIDC Authorization Code Flow (Authlib)
- SAML 2.0 AuthnRequest/Response (+ metadata endpoints)
- User session & claims page
- **MFA audit** (`mfa-enforcement/okta_mfa_audit.py`) → `mfa_report.csv`
- **MFA enforcement** (`mfa-enforcement/okta_mfa_enforce.py`) → add users to “MFA Required” group

## ⚙️ Quickstart
```bash
git clone https://github.com/mraaron360/IAM-SSO-MFA-LAB.git
cd IAM-SSO-MFA-LAB
pip install -r requirements.txt
cp .env.example .env   # fill in values
python app.py          # runs Flask SSO demo

# MFA audit
python mfa-enforcement/okta_mfa_audit.py
