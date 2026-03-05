
[README.md](https://github.com/user-attachments/files/25756707/README.md)
# 🔐 IAM SSO MFA

> Centralized Identity & Access Management with Single Sign-On and Multi-Factor Authentication

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: MFA](https://img.shields.io/badge/Security-MFA%20Enabled-green.svg)]()
[![SSO: SAML2/OIDC](https://img.shields.io/badge/SSO-SAML2%20%7C%20OIDC-blue.svg)]()
[![Status: Active](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [SSO Setup](#sso-setup)
- [MFA Setup](#mfa-setup)
- [IAM Policies](#iam-policies)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Overview

This project provides a unified **IAM (Identity and Access Management)** solution integrating **SSO (Single Sign-On)** and **MFA (Multi-Factor Authentication)** for secure, scalable user access across services and environments.

Supports:
- **SAML 2.0** and **OIDC/OAuth 2.0** for SSO federation
- **TOTP**, **FIDO2/WebAuthn**, **SMS**, and **Push** for MFA
- **RBAC** and **ABAC** policy enforcement
- Integration with **AWS IAM**, **Azure AD**, **Okta**, **Ping Identity**, and **Keycloak**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client Apps                          │
│              (Web / Mobile / CLI / API)                     │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    Identity Provider (IdP)                   │
│          SAML 2.0 / OIDC / OAuth 2.0 / SCIM                 │
└───────────┬───────────────────────────┬─────────────────────┘
            │                           │
            ▼                           ▼
┌───────────────────┐       ┌───────────────────────┐
│   SSO Federation  │       │     MFA Engine         │
│  (AuthN / AuthZ)  │       │  TOTP / FIDO2 / Push   │
└───────────────────┘       └───────────────────────┘
            │                           │
            └──────────────┬────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    IAM Policy Engine                         │
│              RBAC / ABAC / JIT Provisioning                  │
└─────────────────────────────────────────────────────────────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
       AWS IAM        Azure AD       Custom Apps
```

---

## Features

| Feature | Description |
|---|---|
| 🔑 **SSO** | SAML 2.0, OIDC, OAuth 2.0 federation |
| 📱 **MFA** | TOTP (RFC 6238), FIDO2/WebAuthn, SMS, Push |
| 🛡️ **RBAC/ABAC** | Role and attribute-based access control |
| 🔄 **JIT Provisioning** | Just-in-time user provisioning via SCIM 2.0 |
| 📋 **Audit Logging** | Full auth event trail with SIEM integration |
| 🔒 **Session Management** | Token rotation, session timeouts, device trust |
| ⚙️ **Admin Console** | Web UI for policy and user management |
| 🔌 **IdP Connectors** | Okta, Azure AD, Ping, Keycloak, LDAP/AD |

---

## Prerequisites

```bash
# Runtime
Node.js >= 18.x  OR  Python >= 3.10
Docker >= 24.x
Kubernetes >= 1.28 (optional)

# Dependencies
Redis >= 7.x         # session store
PostgreSQL >= 15.x   # user/policy store
Vault >= 1.14        # secrets management (optional)
```

---

## Installation

### Docker (Recommended)

```bash
git clone https://github.com/your-org/iam-sso-mfa.git
cd iam-sso-mfa

cp .env.example .env
# Edit .env with your IdP credentials and DB config

docker compose up -d
```

### Manual

```bash
git clone https://github.com/your-org/iam-sso-mfa.git
cd iam-sso-mfa

npm install          # or: pip install -r requirements.txt

npm run db:migrate
npm run build
npm start
```

### Kubernetes

```bash
helm repo add iam-sso-mfa https://charts.your-org.com
helm repo update

helm install iam-sso-mfa iam-sso-mfa/iam-sso-mfa \
  --namespace identity \
  --create-namespace \
  -f values.yaml
```

---

## Configuration

### Environment Variables

```env
# Application
APP_PORT=8080
APP_ENV=production
APP_SECRET=<32-byte-random-secret>

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=iam_db
DB_USER=iam_user
DB_PASS=<strong-password>

# Redis (Session Store)
REDIS_URL=redis://localhost:6379

# SSO - SAML 2.0
SAML_ENTRY_POINT=https://idp.example.com/sso/saml
SAML_ISSUER=https://your-app.example.com
SAML_CERT=<base64-idp-cert>
SAML_PRIVATE_KEY=<base64-sp-private-key>

# SSO - OIDC
OIDC_ISSUER=https://idp.example.com
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=<client-secret>
OIDC_REDIRECT_URI=https://your-app.example.com/auth/callback

# MFA
MFA_TOTP_ISSUER=YourOrg
MFA_SMS_PROVIDER=twilio          # twilio | aws_sns | vonage
MFA_PUSH_PROVIDER=duo            # duo | okta_verify
TWILIO_ACCOUNT_SID=<sid>
TWILIO_AUTH_TOKEN=<token>
TWILIO_FROM_NUMBER=+15555555555

# Session
SESSION_TTL=3600                 # seconds
SESSION_IDLE_TIMEOUT=900
MFA_SESSION_TTL=86400

# Audit / SIEM
AUDIT_LOG_LEVEL=info
SIEM_ENDPOINT=https://siem.example.com/ingest
SIEM_TOKEN=<token>
```

---

## SSO Setup

### SAML 2.0

1. **Register your SP metadata** with your IdP using the endpoint:
   ```
   GET /auth/saml/metadata
   ```

2. **Configure attribute mapping** in `config/saml.yaml`:
   ```yaml
   attribute_mapping:
     email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
     first_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
     last_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
     groups: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
   ```

3. **Initiate SSO login**:
   ```
   GET /auth/saml/login?RelayState=<original-url>
   ```

### OIDC / OAuth 2.0

1. **Register redirect URIs** in your IdP:
   ```
   https://your-app.example.com/auth/oidc/callback
   ```

2. **Authorization Code Flow**:
   ```
   GET /auth/oidc/login
   → Redirects to IdP → Callback → Token exchange → Session
   ```

3. **Token introspection endpoint**:
   ```
   POST /auth/token/introspect
   Authorization: Bearer <access-token>
   ```

---

## MFA Setup

### TOTP (Google Authenticator / Authy)

```bash
# Enroll a user
POST /api/mfa/totp/enroll
Authorization: Bearer <session-token>

# Response: returns QR code URI and backup codes
{
  "qr_uri": "otpauth://totp/YourOrg:user@example.com?secret=BASE32SECRET&issuer=YourOrg",
  "backup_codes": ["xxxxx-xxxxx", ...]
}

# Verify TOTP
POST /api/mfa/totp/verify
{ "code": "123456" }
```

### FIDO2 / WebAuthn

```bash
# Begin registration
POST /api/mfa/webauthn/register/begin
Authorization: Bearer <session-token>

# Complete registration
POST /api/mfa/webauthn/register/complete
{ "credential": { ...authenticatorAttestationResponse } }

# Authenticate
POST /api/mfa/webauthn/authenticate/begin
POST /api/mfa/webauthn/authenticate/complete
```

### SMS OTP

```bash
# Send OTP
POST /api/mfa/sms/send
{ "phone": "+15555555555" }

# Verify OTP
POST /api/mfa/sms/verify
{ "code": "123456" }
```

---

## IAM Policies

### Role Definitions (`config/roles.yaml`)

```yaml
roles:
  admin:
    description: Full access
    permissions:
      - "*:*"

  developer:
    description: Read/write to dev resources
    permissions:
      - "dev:read"
      - "dev:write"
      - "staging:read"

  read_only:
    description: Read-only across all resources
    permissions:
      - "*:read"
```

### ABAC Policy Example (`config/policies.yaml`)

```yaml
policies:
  - name: allow-us-region-access
    effect: allow
    conditions:
      - attribute: user.department
        operator: equals
        value: "engineering"
      - attribute: request.ip_country
        operator: in
        value: ["US", "CA"]
    resources:
      - "arn:example:s3:::prod-*"
```

### Assigning Roles via API

```bash
POST /api/iam/users/{userId}/roles
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "roles": ["developer"],
  "expires_at": "2025-12-31T23:59:59Z"   // optional
}
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/auth/saml/login` | Initiate SAML SSO |
| `GET` | `/auth/saml/metadata` | SP metadata (XML) |
| `POST` | `/auth/saml/callback` | SAML ACS endpoint |
| `GET` | `/auth/oidc/login` | Initiate OIDC flow |
| `GET` | `/auth/oidc/callback` | OIDC redirect callback |
| `POST` | `/auth/logout` | Global logout / SLO |
| `POST` | `/api/mfa/totp/enroll` | Enroll TOTP |
| `POST` | `/api/mfa/totp/verify` | Verify TOTP code |
| `POST` | `/api/mfa/webauthn/register/begin` | Start WebAuthn registration |
| `POST` | `/api/mfa/webauthn/authenticate/begin` | Start WebAuthn authn |
| `POST` | `/api/mfa/sms/send` | Send SMS OTP |
| `POST` | `/api/mfa/sms/verify` | Verify SMS OTP |
| `GET` | `/api/iam/users` | List users |
| `POST` | `/api/iam/users/{id}/roles` | Assign roles |
| `GET` | `/api/audit/logs` | Query audit logs |
| `GET` | `/health` | Health check |

Full OpenAPI spec: [`docs/openapi.yaml`](docs/openapi.yaml)

---

## Security Considerations

- **Token Storage**: Never store tokens in `localStorage`. Use `httpOnly` + `Secure` + `SameSite=Strict` cookies.
- **PKCE**: Always enforce PKCE for public clients in OIDC flows.
- **MFA Bypass Prevention**: Enforce MFA at the policy layer; do not rely on client-side checks.
- **Brute Force**: Rate-limit `/auth` and `/api/mfa` endpoints (default: 5 attempts / 15 min).
- **Backup Codes**: Single-use TOTP backup codes are hashed (bcrypt) at rest.
- **Session Binding**: Sessions are bound to IP + User-Agent by default (configurable).
- **Secrets Rotation**: Rotate `APP_SECRET` and IdP credentials via `/api/admin/rotate-secrets`.
- **Audit Logs**: All auth events (success, failure, MFA challenge, role change) are immutably logged.

---

## Troubleshooting

**SAML assertion validation failing**
```bash
# Check clock skew between SP and IdP (must be < 5 min)
timedatectl status

# Dump decoded SAML response
npm run debug:saml -- --response <base64-saml-response>
```

**TOTP codes rejected**
```
- Verify NTP sync on server
- Default window: ±1 step (30s). Widen with MFA_TOTP_WINDOW=2 in .env
```

**WebAuthn registration fails in browser**
```
- Requires HTTPS or localhost
- Check RP ID matches domain exactly: MFA_WEBAUTHN_RP_ID=your-app.example.com
```

**SSO redirect loop**
```
- Verify SP Entity ID matches what's registered in IdP
- Check SAML NameID format: set SAML_NAMEID_FORMAT=emailAddress
```

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit: `git commit -m "feat: add your feature"`
4. Push: `git push origin feat/your-feature`
5. Open a Pull Request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) and ensure all auth-related changes include security review notes in the PR description.

---

## License

[MIT](LICENSE) © Your Org
