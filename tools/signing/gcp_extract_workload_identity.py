#!/usr/bin/env python3
"""Verify a GCP Confidential Space sample JWT and extract the workload identity.

Used by the GCP branch of kms_policy_update.yml. This verifies the token was
genuinely issued and *signed* by Google's Confidential Space attestation
service (not merely that it claims to be), then prints a JSON *object* of the
fields the GCP key release policy cares about:

    {"service_accounts": ["sa@proj.iam.gserviceaccount.com"],
     "image_digest": "sha256:...",
     "image_reference": "...",
     "swname": "CONFIDENTIAL_SPACE",
     "iss": "https://confidentialcomputing.googleapis.com"}

Emitting an object (rather than just the service-account array) is deliberate:
adding a newly-allowlisted field later (e.g. image_digest, to pin trusted
container images) becomes a workflow-only change -- this script never has to
change again. That keeps the registration flow strictly additive.

Trust model: the signature check is what makes pasting a sample token more
trustworthy than pasting a raw service-account string. A valid signature proves
a real Confidential Space VM ran as the service account(s) and obtained a
Google-signed token. Expiry is intentionally NOT enforced, because a pasted
"sample" token is typically already expired (~1h lifetime); we only need proof
of authenticity, not a live session. Audience is workload-specific and
irrelevant to registration, so it is not checked either.
"""
import json
import sys
import urllib.request

import jwt
from jwt import PyJWKClient

ISSUER = "https://confidentialcomputing.googleapis.com"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
ALLOWED_ALGS = ["RS256", "ES256"]


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        fail("usage: gcp_extract_workload_identity.py <jwt>")
    token = sys.argv[1].strip()

    # Resolve Google's JWKS URI from the OIDC discovery document.
    try:
        with urllib.request.urlopen(DISCOVERY_URL, timeout=15) as resp:
            jwks_uri = json.load(resp)["jwks_uri"]
    except Exception as e:  # noqa: BLE001
        fail(f"could not fetch OIDC discovery from {DISCOVERY_URL}: {e}")

    # Verify the signature against Google's published signing keys.
    try:
        signing_key = PyJWKClient(jwks_uri).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGS,
            issuer=ISSUER,
            options={"verify_exp": False, "verify_aud": False},
        )
    except Exception as e:  # noqa: BLE001
        fail(f"JWT signature/issuer verification failed: {e}")

    # Confirm this is a Confidential Space token, not some other Google token.
    if claims.get("swname") != "CONFIDENTIAL_SPACE":
        fail(f"not a Confidential Space token (swname={claims.get('swname')!r})")

    sas = claims.get("google_service_accounts") or []
    if isinstance(sas, str):
        sas = [sas]
    if not sas:
        fail("token carries no google_service_accounts claim")

    container = (claims.get("submods") or {}).get("container") or {}
    identity = {
        "service_accounts": sas,
        # Reserved for a later, purely-additive step: allowlisting the exact
        # container image. Extracted now so the workflow can pick it up without
        # ever touching this script again.
        "image_digest": container.get("image_digest"),
        "image_reference": container.get("image_reference"),
        "swname": claims.get("swname"),
        "iss": claims.get("iss"),
    }
    print(json.dumps(identity))


if __name__ == "__main__":
    main()
