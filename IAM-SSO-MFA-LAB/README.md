# ============================================================
# IAM SSO + MFA LAB — COMPLETE CODE
# ============================================================
# FILE STRUCTURE:
#   1. app.py
#   2. saml_handler.py
#   3. mfa-enforcement/okta_mfa_audit.py
#   4. mfa-enforcement/okta_mfa_enforce.py
#   5. requirements.txt
#   6. .env.example
#   7. Dockerfile
#   8. docker-compose.yml
#   9. templates/index.html
#  10. templates/profile.html
#  11. templates/error.html
# ============================================================


# ============================================================
# FILE 1: app.py
# ============================================================

"""
IAM SSO + MFA Lab — app.py
Okta OIDC (Authorization Code Flow) + SAML 2.0 SSO demo.
"""

import os
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, redirect, url_for, session,
    render_template, request, jsonify, make_response
)
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from saml_handler import (
    build_authn_request, process_saml_response,
    build_metadata, SAMLError
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # hard-fails if missing

oauth = OAuth(app)
okta = oauth.register(
    name="okta",
    client_id=os.environ["OKTA_CLIENT_ID"],
    client_secret=os.environ["OKTA_CLIENT_SECRET"],
    server_metadata_url=(
        f"{os.environ['OKTA_ISSUER']}/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile",
        "token_endpoint_auth_method": "client_secret_post",
    },
)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            session["next"] = request.url
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


@app.get("/")
def index():
    user = session.get("user")
    return render_template("index.html", user=user)


@app.get("/login/oidc")
def login_oidc():
    redirect_uri = url_for("oidc_callback", _external=True)
    return okta.authorize_redirect(redirect_uri)


@app.get("/callback/oidc")
def oidc_callback():
    try:
        token = okta.authorize_access_token()
    except Exception as exc:
        log.warning("OIDC callback error: %s", exc)
        return render_template("error.html", message="OIDC login failed."), 400

    userinfo = token.get("userinfo") or okta.userinfo()
    session["user"] = {
        "sub":         userinfo.get("sub"),
        "email":       userinfo.get("email"),
        "name":        userinfo.get("name"),
        "given_name":  userinfo.get("given_name"),
        "auth_method": "oidc",
        "logged_in_at": datetime.now(timezone.utc).isoformat(),
    }
    log.info("OIDC login: %s", userinfo.get("email"))
    next_url = session.pop("next", url_for("profile"))
    return redirect(next_url)


@app.get("/login/saml")
def login_saml():
    try:
        authn_url, relay_state = build_authn_request(
            idp_sso_url=os.environ["OKTA_SAML_SSO_URL"],
            sp_entity_id=os.environ["SP_ENTITY_ID"],
            acs_url=url_for("saml_acs", _external=True),
        )
        session["saml_relay_state"] = relay_state
        return redirect(authn_url)
    except Exception as exc:
        log.error("SAML request build failed: %s", exc)
        return render_template("error.html", message="SAML login initiation failed."), 500


@app.post("/callback/saml")
def saml_acs():
    saml_response = request.form.get("SAMLResponse")
    relay_state    = request.form.get("RelayState", "")

    if not saml_response:
        return render_template("error.html", message="Missing SAMLResponse."), 400

    if relay_state != session.pop("saml_relay_state", None):
        log.warning("SAML relay state mismatch — possible CSRF")
        return render_template("error.html", message="Invalid relay state."), 400

    try:
        attrs = process_saml_response(
            saml_response_b64=saml_response,
            idp_cert=os.environ["OKTA_SAML_CERT"],
            sp_entity_id=os.environ["SP_ENTITY_ID"],
            acs_url=url_for("saml_acs", _external=True),
        )
    except SAMLError as exc:
        log.warning("SAML validation error: %s", exc)
        return render_template("error.html", message=f"SAML error: {exc}"), 400

    session["user"] = {
        "sub":         attrs.get("nameID"),
        "email":       attrs.get("email", attrs.get("nameID")),
        "name":        attrs.get("displayName", attrs.get("email", "")),
        "auth_method": "saml",
        "logged_in_at": datetime.now(timezone.utc).isoformat(),
    }
    log.info("SAML login: %s", session["user"]["email"])
    return redirect(url_for("profile"))


@app.get("/saml/metadata")
def saml_metadata():
    xml = build_metadata(
        sp_entity_id=os.environ["SP_ENTITY_ID"],
        acs_url=url_for("saml_acs", _external=True),
        org_name=os.getenv("ORG_NAME", "IAM Lab"),
        org_url=request.url_root,
    )
    resp = make_response(xml)
    resp.headers["Content-Type"] = "application/xml"
    return resp


@app.get("/profile")
@login_required
def profile():
    return render_template("profile.html", user=session["user"])


@app.get("/api/me")
@login_required
def api_me():
    return jsonify(session["user"])


@app.get("/logout")
def logout():
    user = session.pop("user", None)
    if user:
        log.info("Logout: %s", user.get("email"))
    session.clear()
    return redirect(url_for("index"))


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)


# ============================================================
# FILE 2: saml_handler.py
# ============================================================

"""
saml_handler.py — SAML 2.0 AuthnRequest builder + Response validator.

- Deflate-compressed, Base64-encoded AuthnRequest (HTTP-Redirect binding)
- Base64-decoded + XML-parsed SAMLResponse (HTTP-POST binding)
- XML signature verification via signxml
- Assertion condition checks (NotBefore / NotOnOrAfter / Audience)
"""

import base64
import uuid
import zlib
import logging
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
from xml.etree import ElementTree as ET

from signxml import XMLVerifier
from lxml import etree

log = logging.getLogger(__name__)

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
    "md":    "urn:oasis:names:tc:SAML:2.0:metadata",
}


class SAMLError(Exception):
    """Raised for any SAML validation failure."""


def build_authn_request(
    idp_sso_url: str,
    sp_entity_id: str,
    acs_url: str,
) -> tuple[str, str]:
    request_id    = f"_{uuid.uuid4().hex}"
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    relay_state   = uuid.uuid4().hex

    authn_xml = (
        f'<samlp:AuthnRequest'
        f' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}"'
        f' Version="2.0"'
        f' IssueInstant="{issue_instant}"'
        f' Destination="{idp_sso_url}"'
        f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
        f' AssertionConsumerServiceURL="{acs_url}">'
        f'  <saml:Issuer>{sp_entity_id}</saml:Issuer>'
        f'  <samlp:NameIDPolicy'
        f'    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"'
        f'    AllowCreate="true"/>'
        f'</samlp:AuthnRequest>'
    )

    compressed = zlib.compress(authn_xml.encode("utf-8"))[2:-4]
    encoded    = base64.b64encode(compressed).decode("utf-8")
    params     = urlencode({"SAMLRequest": encoded, "RelayState": relay_state})
    return f"{idp_sso_url}?{params}", relay_state


def process_saml_response(
    saml_response_b64: str,
    idp_cert: str,
    sp_entity_id: str,
    acs_url: str,
    clock_skew_seconds: int = 60,
) -> dict:
    try:
        raw_xml = base64.b64decode(saml_response_b64)
    except Exception as exc:
        raise SAMLError(f"Base64 decode failed: {exc}") from exc

    try:
        root = etree.fromstring(raw_xml)
    except etree.XMLSyntaxError as exc:
        raise SAMLError(f"XML parse failed: {exc}") from exc

    cert_pem = _normalize_cert(idp_cert)
    try:
        XMLVerifier().verify(raw_xml, x509_cert=cert_pem)
    except Exception as exc:
        raise SAMLError(f"Signature verification failed: {exc}") from exc

    status_code = root.find(".//samlp:StatusCode", NS)
    if status_code is None:
        raise SAMLError("No StatusCode found in response")
    if "Success" not in status_code.get("Value", ""):
        raise SAMLError(f"IdP returned non-success status: {status_code.get('Value')}")

    assertion = root.find(".//saml:Assertion", NS)
    if assertion is None:
        raise SAMLError("No Assertion element found")

    conditions = assertion.find("saml:Conditions", NS)
    if conditions is not None:
        now  = datetime.now(timezone.utc)
        skew = timedelta(seconds=clock_skew_seconds)

        not_before_str      = conditions.get("NotBefore")
        not_on_or_after_str = conditions.get("NotOnOrAfter")

        if not_before_str:
            not_before = _parse_saml_datetime(not_before_str)
            if now < not_before - skew:
                raise SAMLError(f"Assertion not yet valid (NotBefore={not_before_str})")

        if not_on_or_after_str:
            not_on_or_after = _parse_saml_datetime(not_on_or_after_str)
            if now > not_on_or_after + skew:
                raise SAMLError(f"Assertion has expired (NotOnOrAfter={not_on_or_after_str})")

        audience_restriction = conditions.find("saml:AudienceRestriction", NS)
        if audience_restriction is not None:
            audiences = [a.text for a in audience_restriction.findall("saml:Audience", NS)]
            if sp_entity_id not in audiences:
                raise SAMLError(f"SP entityID '{sp_entity_id}' not in audiences: {audiences}")

    subj_confirm_data = assertion.find(".//saml:SubjectConfirmationData", NS)
    if subj_confirm_data is not None:
        recipient = subj_confirm_data.get("Recipient", "")
        if recipient and recipient != acs_url:
            raise SAMLError(f"ACS URL mismatch: expected '{acs_url}', got '{recipient}'")

    name_id_el = assertion.find(".//saml:NameID", NS)
    name_id    = name_id_el.text.strip() if name_id_el is not None else None

    attrs: dict = {"nameID": name_id}
    for attr_stmt in assertion.findall("saml:AttributeStatement", NS):
        for attr in attr_stmt.findall("saml:Attribute", NS):
            name   = attr.get("Name", "")
            values = [v.text for v in attr.findall("saml:AttributeValue", NS) if v.text]
            key    = _normalize_attr_name(name)
            attrs[key] = values[0] if len(values) == 1 else values

    log.info("SAML assertion validated for nameID=%s", name_id)
    return attrs


def build_metadata(
    sp_entity_id: str,
    acs_url: str,
    org_name: str = "IAM Lab",
    org_url: str  = "http://localhost",
) -> str:
    valid_until = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z")
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{sp_entity_id}"
    validUntil="{valid_until}">
  <md:SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{acs_url}"
        index="1"/>
    <md:NameIDFormat>
      urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    </md:NameIDFormat>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">{org_name}</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">{org_name}</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">{org_url}</md:OrganizationURL>
  </md:Organization>
</md:EntityDescriptor>"""


def _normalize_cert(cert: str) -> str:
    cert = cert.strip().replace("\\n", "\n")
    if not cert.startswith("-----BEGIN"):
        cert = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
    return cert


def _parse_saml_datetime(dt_str: str) -> datetime:
    dt_str = dt_str.rstrip("Z")
    try:
        dt = datetime.fromisoformat(dt_str)
    except ValueError:
        dt = datetime.strptime(dt_str[:19], "%Y-%m-%dT%H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


_ATTR_MAP = {
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    "given_name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":      "family_name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "displayName",
    "urn:oid:0.9.2342.19200300.100.1.3":                                   "email",
    "urn:oid:2.5.4.3":                                                     "displayName",
}


def _normalize_attr_name(name: str) -> str:
    if name in _ATTR_MAP:
        return _ATTR_MAP[name]
    return name.rsplit("/", 1)[-1].rsplit(":", 1)[-1].lower() or name


# ============================================================
# FILE 3: mfa-enforcement/okta_mfa_audit.py
# ============================================================

"""
Audits all Okta users and reports their MFA enrollment status.

Usage:
  python mfa-enforcement/okta_mfa_audit.py
  python mfa-enforcement/okta_mfa_audit.py --output reports/audit.csv --status ACTIVE

Requires env vars:
  OKTA_DOMAIN    — e.g. yourorg.okta.com
  OKTA_API_TOKEN — SSWS token with okta.users.read + okta.factors.read
"""

import argparse
import csv
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Generator

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

OKTA_DOMAIN    = os.environ.get("OKTA_DOMAIN", "")
OKTA_API_TOKEN = os.environ.get("OKTA_API_TOKEN", "")

CSV_FIELDS = [
    "user_id", "login", "email", "first_name", "last_name",
    "status", "created", "last_login",
    "mfa_enrolled", "factor_types", "factor_count",
]


class OktaClient:
    def __init__(self, domain: str, token: str):
        if not domain or not token:
            sys.exit("ERROR: OKTA_DOMAIN and OKTA_API_TOKEN must be set.")
        self.base = f"https://{domain.rstrip('/')}/api/v1"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {token}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        })

    def _get(self, url: str, params: dict | None = None) -> requests.Response:
        for attempt in range(5):
            resp = self.session.get(url, params=params)
            if resp.status_code == 429:
                wait = max(
                    int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5)) - int(time.time()), 1
                )
                log.warning("Rate limited — waiting %ds (attempt %d/5)", wait, attempt + 1)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp
        raise RuntimeError("Exceeded retry limit on rate-limited request")

    def paginate(self, url: str, params: dict | None = None) -> Generator[dict, None, None]:
        while url:
            resp    = self._get(url, params=params)
            params  = None
            yield from resp.json()
            url = None
            for part in resp.headers.get("Link", "").split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    break

    def list_users(self, status: str = "ACTIVE") -> Generator[dict, None, None]:
        yield from self.paginate(
            f"{self.base}/users",
            params={"filter": f'status eq "{status}"', "limit": 200},
        )

    def list_factors(self, user_id: str) -> list[dict]:
        return self._get(f"{self.base}/users/{user_id}/factors").json()


def audit_user(client: OktaClient, user: dict) -> dict:
    profile = user.get("profile", {})
    try:
        factors = client.list_factors(user["id"])
    except requests.HTTPError:
        factors = []

    active_factors = [f for f in factors if f.get("status") == "ACTIVE"]
    factor_types   = sorted({f.get("factorType", "") for f in active_factors})

    return {
        "user_id":      user["id"],
        "login":        profile.get("login", ""),
        "email":        profile.get("email", ""),
        "first_name":   profile.get("firstName", ""),
        "last_name":    profile.get("lastName", ""),
        "status":       user.get("status", ""),
        "created":      user.get("created", ""),
        "last_login":   user.get("lastLogin", ""),
        "mfa_enrolled": "YES" if active_factors else "NO",
        "factor_types": "|".join(factor_types),
        "factor_count": len(active_factors),
    }


def run_audit(output_path: str, user_status: str = "ACTIVE") -> None:
    client = OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN)
    log.info("Starting MFA audit — status filter: %s", user_status)
    start = datetime.now(timezone.utc)

    rows = []
    total = enrolled = unenrolled = 0

    for user in client.list_users(status=user_status):
        row = audit_user(client, user)
        rows.append(row)
        total += 1
        if row["mfa_enrolled"] == "YES":
            enrolled += 1
        else:
            unenrolled += 1
        if total % 50 == 0:
            log.info("Processed %d users…", total)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    print(
        f"\n{'='*50}\n"
        f"  MFA Audit Summary\n"
        f"{'='*50}\n"
        f"  Total users    : {total}\n"
        f"  MFA enrolled   : {enrolled}  ({enrolled/max(total,1)*100:.1f}%)\n"
        f"  MFA missing    : {unenrolled}  ({unenrolled/max(total,1)*100:.1f}%)\n"
        f"  Report         : {output_path}\n"
        f"  Elapsed        : {elapsed:.1f}s\n"
        f"{'='*50}\n"
    )


def main():
    parser = argparse.ArgumentParser(description="Okta MFA Audit")
    parser.add_argument("--output", "-o", default="mfa_report.csv")
    parser.add_argument("--status", default="ACTIVE",
        choices=["ACTIVE", "PROVISIONED", "STAGED", "DEPROVISIONED"])
    args = parser.parse_args()
    run_audit(output_path=args.output, user_status=args.status)


if __name__ == "__main__":
    main()


# ============================================================
# FILE 4: mfa-enforcement/okta_mfa_enforce.py
# ============================================================

"""
Adds unenrolled-MFA users to an Okta group ("MFA Required").
ALWAYS run with --dry-run first. Requires --execute to write.

Usage:
  python mfa-enforcement/okta_mfa_enforce.py --dry-run
  python mfa-enforcement/okta_mfa_enforce.py --from-csv mfa_report.csv --dry-run
  python mfa-enforcement/okta_mfa_enforce.py --execute
  python mfa-enforcement/okta_mfa_enforce.py --from-csv mfa_report.csv --execute

Requires env vars:
  OKTA_DOMAIN        — e.g. yourorg.okta.com
  OKTA_API_TOKEN     — SSWS token with okta.users.read + okta.groups.manage
  MFA_REQUIRED_GROUP — Okta group name (default: "MFA Required")
"""

import argparse
import csv
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Generator

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

OKTA_DOMAIN    = os.environ.get("OKTA_DOMAIN", "")
OKTA_API_TOKEN = os.environ.get("OKTA_API_TOKEN", "")
MFA_GROUP_NAME = os.environ.get("MFA_REQUIRED_GROUP", "MFA Required")


class OktaClient:
    def __init__(self, domain: str, token: str):
        if not domain or not token:
            sys.exit("ERROR: OKTA_DOMAIN and OKTA_API_TOKEN must be set.")
        self.base = f"https://{domain.rstrip('/')}/api/v1"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {token}",
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        })

    def _req(self, method: str, url: str, **kwargs) -> requests.Response:
        for attempt in range(5):
            resp = self.session.request(method, url, **kwargs)
            if resp.status_code == 429:
                wait = max(
                    int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5)) - int(time.time()), 1
                )
                log.warning("Rate limited — waiting %ds", wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp
        raise RuntimeError("Retry limit exceeded")

    def paginate(self, url: str, params: dict | None = None) -> Generator[dict, None, None]:
        while url:
            resp   = self._req("GET", url, params=params)
            params = None
            yield from resp.json()
            url = None
            for part in resp.headers.get("Link", "").split(","):
                if 'rel="next"' in part:
                    url = part.split(";")[0].strip().strip("<>")
                    break

    def find_group_by_name(self, name: str) -> dict | None:
        for group in self.paginate(f"{self.base}/groups", params={"q": name, "limit": 200}):
            if group.get("profile", {}).get("name") == name:
                return group
        return None

    def create_group(self, name: str, description: str = "") -> dict:
        resp = self._req("POST", f"{self.base}/groups",
            json={"profile": {"name": name, "description": description}})
        return resp.json()

    def get_group_members(self, group_id: str) -> set[str]:
        return {u["id"] for u in self.paginate(
            f"{self.base}/groups/{group_id}/users", params={"limit": 200}
        )}

    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        self._req("PUT", f"{self.base}/groups/{group_id}/users/{user_id}")

    def list_users_active(self) -> Generator[dict, None, None]:
        yield from self.paginate(
            f"{self.base}/users",
            params={"filter": 'status eq "ACTIVE"', "limit": 200},
        )

    def list_factors(self, user_id: str) -> list[dict]:
        return self._req("GET", f"{self.base}/users/{user_id}/factors").json()


def get_unenrolled_from_okta(client: OktaClient) -> list[dict]:
    unenrolled = []
    total = 0
    for user in client.list_users_active():
        total += 1
        try:
            factors = client.list_factors(user["id"])
        except requests.HTTPError:
            factors = []
        if not [f for f in factors if f.get("status") == "ACTIVE"]:
            unenrolled.append({
                "user_id": user["id"],
                "login":   user.get("profile", {}).get("login", ""),
                "email":   user.get("profile", {}).get("email", ""),
            })
        if total % 50 == 0:
            log.info("Scanned %d users, %d unenrolled so far…", total, len(unenrolled))
    log.info("Scan complete: %d/%d unenrolled", len(unenrolled), total)
    return unenrolled


def get_unenrolled_from_csv(csv_path: str) -> list[dict]:
    unenrolled = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("mfa_enrolled", "").upper() == "NO":
                unenrolled.append({
                    "user_id": row["user_id"],
                    "login":   row["login"],
                    "email":   row["email"],
                })
    log.info("Loaded %d unenrolled users from %s", len(unenrolled), csv_path)
    return unenrolled


def enforce(unenrolled: list[dict], client: OktaClient, group_name: str, dry_run: bool) -> None:
    if not unenrolled:
        log.info("No unenrolled users — nothing to enforce.")
        return

    group = client.find_group_by_name(group_name)
    if group is None:
        if dry_run:
            log.info("[DRY RUN] Group '%s' not found — would create it.", group_name)
            group_id        = "<would-be-created>"
            existing_members: set = set()
        else:
            log.info("Group '%s' not found — creating it.", group_name)
            group            = client.create_group(name=group_name,
                                description="Users required to enroll in MFA")
            group_id         = group["id"]
            existing_members = set()
    else:
        group_id         = group["id"]
        existing_members = client.get_group_members(group_id) if not dry_run else set()
        log.info("Target group: '%s' (id=%s)", group_name, group_id)

    added = skipped = failed = 0

    for u in unenrolled:
        uid, login = u["user_id"], u["login"]
        if uid in existing_members:
            skipped += 1
            continue
        if dry_run:
            log.info("[DRY RUN] Would add: %s (%s)", login, uid)
            added += 1
        else:
            try:
                client.add_user_to_group(group_id, uid)
                log.info("Added: %s", login)
                added += 1
            except requests.HTTPError as exc:
                log.error("Failed to add %s: %s", login, exc)
                failed += 1

    print(
        f"\n{'='*50}\n"
        f"  MFA Enforcement {'[DRY RUN] ' if dry_run else ''}Summary\n"
        f"{'='*50}\n"
        f"  Unenrolled found       : {len(unenrolled)}\n"
        f"  {'Would add' if dry_run else 'Added'} to group  : {added}\n"
        f"  Already in group       : {skipped}\n"
        f"  Errors                 : {failed}\n"
        f"  Target group           : {group_name}\n"
        f"{'='*50}\n"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Okta MFA Enforcement",
        epilog="Always --dry-run first.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run",  action="store_true", help="Preview only (SAFE)")
    mode.add_argument("--execute",  action="store_true", help="Write changes to Okta")
    parser.add_argument("--from-csv", metavar="PATH",
        help="Use existing mfa_report.csv instead of re-querying Okta")
    parser.add_argument("--group", default=MFA_GROUP_NAME)
    args = parser.parse_args()

    client     = OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN)
    unenrolled = get_unenrolled_from_csv(args.from_csv) if args.from_csv \
                 else get_unenrolled_from_okta(client)
    enforce(unenrolled=unenrolled, client=client,
            group_name=args.group, dry_run=args.dry_run)


if __name__ == "__main__":
    main()


# ============================================================
# FILE 5: requirements.txt
# ============================================================
#
# Flask==3.0.3
# authlib==1.3.1
# requests==2.32.3
# python-dotenv==1.0.1
# lxml==5.2.2
# signxml==3.2.2
# gunicorn==22.0.0


# ============================================================
# FILE 6: .env.example
# ============================================================
#
# Copy to .env and fill in values. NEVER commit .env.
#
# FLASK_SECRET_KEY=replace-with-openssl-rand-hex-32
# FLASK_DEBUG=false
# PORT=5000
#
# # OIDC
# OKTA_ISSUER=https://yourorg.okta.com/oauth2/default
# OKTA_CLIENT_ID=0oaXXXXXXXXXXXXXX
# OKTA_CLIENT_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#
# # SAML
# OKTA_SAML_SSO_URL=https://yourorg.okta.com/app/yourapp/XXXXXXXXX/sso/saml
# SP_ENTITY_ID=https://localhost:5000/saml/metadata
# OKTA_SAML_CERT=MIIDpDCCAoygAwIBAgIGAXXXXXXXXXXX...
#
# # MFA Scripts
# OKTA_DOMAIN=yourorg.okta.com
# OKTA_API_TOKEN=00XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# MFA_REQUIRED_GROUP=MFA Required
#
# # Optional
# ORG_NAME=My Org


# ============================================================
# FILE 7: Dockerfile
# ============================================================
#
# FROM python:3.11-slim
# WORKDIR /app
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     libxml2-dev libxslt-dev xmlsec1 \
#     && rm -rf /var/lib/apt/lists/*
# COPY requirements.txt ./
# RUN pip install --no-cache-dir -r requirements.txt
# COPY . .
# ENV PORT=5000
# EXPOSE 5000
# CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]


# ============================================================
# FILE 8: docker-compose.yml
# ============================================================
#
# version: "3.9"
# services:
#   sso-lab:
#     build: .
#     ports:
#       - "5000:5000"
#     env_file: .env
#     restart: unless-stopped


# ============================================================
# FILE 9: templates/index.html
# ============================================================
#
# <!DOCTYPE html>
# <html lang="en">
# <head>
#   <meta charset="UTF-8"/>
#   <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
#   <title>IAM SSO + MFA Lab</title>
#   <style>
#     *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
#     body {
#       font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
#       background: #0f172a; color: #e2e8f0; min-height: 100vh;
#       display: flex; flex-direction: column; align-items: center; justify-content: center;
#     }
#     .card {
#       background: #1e293b; border: 1px solid #334155;
#       border-radius: 12px; padding: 2.5rem 3rem; width: 100%; max-width: 420px;
#       box-shadow: 0 25px 50px rgba(0,0,0,0.4);
#     }
#     .logo { font-size: 2rem; text-align: center; margin-bottom: 0.5rem; }
#     h1 { text-align: center; font-size: 1.4rem; color: #f1f5f9; margin-bottom: 0.25rem; }
#     .subtitle { text-align: center; font-size: 0.85rem; color: #94a3b8; margin-bottom: 2rem; }
#     .btn {
#       display: block; width: 100%; padding: 0.75rem 1.5rem;
#       border: none; border-radius: 8px; font-size: 0.95rem; font-weight: 600;
#       cursor: pointer; text-decoration: none; text-align: center;
#       transition: opacity 0.15s, transform 0.1s;
#     }
#     .btn:hover { opacity: 0.88; transform: translateY(-1px); }
#     .btn-oidc  { background: #3b82f6; color: #fff; margin-bottom: 0.75rem; }
#     .btn-saml  { background: #8b5cf6; color: #fff; }
#     .divider { text-align: center; color: #475569; font-size: 0.8rem; margin: 1rem 0; }
#     .logged-in { text-align: center; }
#     .badge {
#       display: inline-block; background: #064e3b; color: #6ee7b7;
#       border-radius: 999px; padding: 0.2rem 0.75rem; font-size: 0.75rem;
#       font-weight: 700; margin-bottom: 1rem; letter-spacing: 0.05em;
#     }
#     .username { font-size: 1.1rem; font-weight: 600; margin-bottom: 1.5rem; }
#     .btn-profile { background: #0f766e; color: #fff; margin-bottom: 0.75rem; }
#     .btn-logout  { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
#   </style>
# </head>
# <body>
#   <div class="card">
#     <div class="logo">🔐</div>
#     <h1>IAM SSO + MFA Lab</h1>
#     <p class="subtitle">Okta OIDC &amp; SAML 2.0 Demo</p>
#     {% if user %}
#       <div class="logged-in">
#         <div class="badge">✓ AUTHENTICATED</div>
#         <p class="username">{{ user.name or user.email }}</p>
#         <a href="/profile" class="btn btn-profile">View Profile &amp; Claims</a>
#         <a href="/logout"  class="btn btn-logout">Sign Out</a>
#       </div>
#     {% else %}
#       <a href="/login/oidc" class="btn btn-oidc">🔑 Sign in with Okta (OIDC)</a>
#       <div class="divider">— or —</div>
#       <a href="/login/saml" class="btn btn-saml">🔏 Sign in with Okta (SAML)</a>
#     {% endif %}
#   </div>
# </body>
# </html>


# ============================================================
# FILE 10: templates/profile.html
# ============================================================
#
# <!DOCTYPE html>
# <html lang="en">
# <head>
#   <meta charset="UTF-8"/>
#   <title>Profile — IAM Lab</title>
#   <style>
#     body { font-family: -apple-system, sans-serif; background: #0f172a;
#            color: #e2e8f0; padding: 2rem 1rem; }
#     .container { max-width: 680px; margin: 0 auto; }
#     header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
#     .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
#             padding: 2rem; margin-bottom: 1.5rem; }
#     .card h2 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em;
#                color: #64748b; margin-bottom: 1.25rem; }
#     table { width: 100%; border-collapse: collapse; }
#     td { padding: 0.6rem 0; font-size: 0.875rem; }
#     td:first-child { color: #64748b; width: 40%; }
#     td:last-child  { font-family: monospace; font-size: 0.82rem; word-break: break-all; }
#     .api-block { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px;
#                  padding: 1rem; font-family: monospace; font-size: 0.8rem; color: #94a3b8; }
#   </style>
# </head>
# <body>
#   <div class="container">
#     <header>
#       <h1>🔐 IAM Lab — Profile</h1>
#       <a href="/logout">Sign Out</a>
#     </header>
#     <div class="card">
#       <h2>Session Claims</h2>
#       <table>
#         {% for key, value in user.items() %}
#         <tr><td>{{ key }}</td><td>{{ value }}</td></tr>
#         {% endfor %}
#       </table>
#     </div>
#     <div class="card">
#       <h2>API — GET /api/me</h2>
#       <div class="api-block" id="api-output">Loading…</div>
#     </div>
#   </div>
#   <script>
#     fetch("/api/me").then(r => r.json())
#       .then(d => { document.getElementById("api-output").textContent = JSON.stringify(d, null, 2); });
#   </script>
# </body>
# </html>


# ============================================================
# FILE 11: templates/error.html
# ============================================================
#
# <!DOCTYPE html>
# <html lang="en">
# <head>
#   <meta charset="UTF-8"/>
#   <title>Error — IAM Lab</title>
#   <style>
#     body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0;
#       display: flex; align-items: center; justify-content: center; min-height: 100vh; }
#     .card { background: #1e293b; border: 1px solid #7f1d1d; border-radius: 12px;
#       padding: 2.5rem 3rem; max-width: 440px; text-align: center; }
#     h1 { color: #fca5a5; margin-bottom: 0.75rem; }
#     p  { color: #94a3b8; font-size: 0.9rem; margin-bottom: 1.5rem; }
#   </style>
# </head>
# <body>
#   <div class="card">
#     <div>⚠️</div>
#     <h1>Authentication Error</h1>
#     <p>{{ message or "An unexpected error occurred." }}</p>
#     <a href="/">← Try Again</a>
#   </div>
# </body>
# </html>
