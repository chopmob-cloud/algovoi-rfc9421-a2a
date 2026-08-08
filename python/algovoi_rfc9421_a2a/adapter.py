"""
algovoi_rfc9421_a2a.adapter — bind the AlgoVoi RFC 9421 signer/verifier/keyid
resolver to the A2A per-message signing extension.

This is thin glue over three shipped, hardened primitives; it introduces no new
cryptography:
- signing:   algovoi-rfc9421-signer
- verifying: algovoi-rfc9421-verifier (Sprint A replay/tag/alg hardening)
- keyid:     algovoi-rfc9421-keyid (SSRF-guarded resolution)

Layer note: this is the PER-MESSAGE signature layer (RFC 9421 + RFC 9530 over a
specific request). It is orthogonal to A2A AgentCard signing (spec 8.4, which is
JWS over the card document) and composes with it: the 8.4-signed card can carry
this extension's declaration and the agent's keyid.

TRUST BOUNDARY (read this): verifying a signature proves the request was signed
by the holder of the key that `keyid` resolves to. It does NOT by itself prove
the request came from the agent you expect — that binding (which keyid is
legitimate for a given agent) is a policy decision the caller owns, normally via
the agent's 8.4-signed AgentCard. `verify_a2a_request` therefore requires you to
either pin `expected_keyid`, supply an `authorize_keyid` predicate, or explicitly
opt out with `require_keyid_authorization=False` (attesting key-holder control
only). It will not silently trust an arbitrary attacker-chosen keyid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from algovoi_rfc9421_signer import sign_request
from algovoi_rfc9421_verifier import verify_request
from algovoi_rfc9421_verifier.parse import parse_signature_input
from algovoi_rfc9421_keyid import resolve_keyid

#: Our extension URI, declared in AgentCard capabilities.extensions and activated
#: per request via the A2A-Extensions header. The wire format is byte-compatible
#: with the #1829 proposal; deployers may add the envoys URI as an alias.
DEFAULT_EXTENSION_URI = "https://algovoi.co.uk/a2a/ext/signature/v1"

#: Neutral, versioned, extension-scoped RFC 9421 `tag` (anti cross-protocol reuse).
DEFAULT_TAG = "a2a-signature-v1"

#: A2A 1.0.1 preferred media type (#1753). Content-Digest is over these body bytes.
A2A_MEDIA_TYPE = "application/a2a+json"

#: Covered components for an A2A JSON-RPC request, matching the #1829 shape.
DEFAULT_COVERED = ["@method", "@path", "content-digest", "created"]


class A2ASignatureError(ValueError):
    """Raised on a caller/configuration error (not on a failed verification,
    which is reported in A2AVerifyResult)."""


@dataclass
class A2AVerifyResult:
    valid: bool = False
    keyid: Optional[str] = None
    key_source: Optional[str] = None
    extension_activated: bool = False
    errors: list = field(default_factory=list)


def sign_a2a_request(
    *,
    body: bytes,
    private_key,
    keyid: str,
    authority: str,
    path: str,
    method: str = "POST",
    tag: str = DEFAULT_TAG,
    created: int | None = None,
    nonce: str | None = None,
    expires: int | None = None,
    covered_components: list | None = None,
    extension_uri: str = DEFAULT_EXTENSION_URI,
) -> dict:
    """Sign an outbound A2A request and return the headers to attach.

    `body` is the exact a2a+json body that will be sent; Content-Digest is
    computed over these bytes, so the receiver must verify over the raw bytes it
    receives (do not re-serialise before verifying).
    """
    covered = list(covered_components) if covered_components is not None else list(DEFAULT_COVERED)
    res = sign_request(
        method=method,
        authority=authority,
        path=path,
        body=body,
        private_key=private_key,
        keyid=keyid,
        tag=tag,
        created=created,
        nonce=nonce,
        expires=expires,
        covered_components=covered,
    )
    return {
        "Signature-Input": res.signature_input,
        "Signature": res.signature,
        "Content-Digest": res.content_digest,
        "Content-Type": A2A_MEDIA_TYPE,
        "A2A-Extensions": extension_uri,
    }


def _keyid_from_signature_input(si_value: str) -> Optional[str]:
    return parse_signature_input(si_value).parameters.get("keyid")


def verify_a2a_request(
    *,
    headers: dict,
    body: bytes,
    authority: str,
    path: str,
    method: str = "POST",
    resolver: Callable = resolve_keyid,
    resolver_kwargs: dict | None = None,
    expected_tag: str = DEFAULT_TAG,
    max_age_seconds: int | None = 300,
    max_skew_seconds: int = 60,
    now: int | None = None,
    nonce_seen: Callable[[str, str], bool] | None = None,
    allowed_algorithms: Iterable[str] = frozenset({"ed25519"}),
    accepted_extension_uris: Iterable[str] = frozenset({DEFAULT_EXTENSION_URI}),
    require_extension_activation: bool = True,
    expected_keyid: str | None = None,
    authorize_keyid: Callable[[str], bool] | None = None,
    require_keyid_authorization: bool = True,
) -> A2AVerifyResult:
    """Verify an inbound A2A request. Fails closed. See the module TRUST BOUNDARY.

    `body` must be the raw received body bytes (not re-serialised).
    """
    h = {k.lower(): v for k, v in headers.items()}
    r = A2AVerifyResult()

    # Extension activation is an UNSIGNED client hint (opt-in signalling), not a
    # security control; the signature is the control. We check it for protocol
    # correctness only.
    ext_uris = {u.strip() for u in h.get("a2a-extensions", "").split(",") if u.strip()}
    r.extension_activated = bool(ext_uris & set(accepted_extension_uris))
    if require_extension_activation and not r.extension_activated:
        r.errors.append("A2A signature extension not activated (A2A-Extensions header)")
        return r

    si_value = h.get("signature-input")
    if not si_value:
        r.errors.append("missing Signature-Input header")
        return r
    # Parse the attacker-controlled Signature-Input under a guard: a malformed
    # header must fail closed (valid=False), never raise out of the verifier.
    try:
        keyid = _keyid_from_signature_input(si_value)
    except Exception as e:
        r.errors.append(f"malformed Signature-Input: {e}")
        return r
    r.keyid = keyid
    if not keyid:
        r.errors.append("Signature-Input missing keyid")
        return r

    # TRUST BOUNDARY: authorise the keyid BEFORE resolving or trusting its key, so
    # an attacker-chosen keyid cannot be silently accepted.
    if expected_keyid is not None:
        if keyid != expected_keyid:
            r.errors.append(f"keyid {keyid!r} does not match expected {expected_keyid!r}")
            return r
    elif authorize_keyid is not None:
        try:
            ok = authorize_keyid(keyid)
        except Exception as e:
            r.errors.append(f"keyid authorization callback errored: {e}")
            return r
        if not ok:
            r.errors.append(f"keyid {keyid!r} is not authorized")
            return r
    elif require_keyid_authorization:
        raise A2ASignatureError(
            "verify_a2a_request requires expected_keyid or authorize_keyid; "
            "set require_keyid_authorization=False to attest key-holder control only"
        )

    try:
        resolved = resolver(keyid, **(resolver_kwargs or {}))
    except Exception as e:
        r.errors.append(f"keyid resolution failed: {e}")
        return r
    r.key_source = getattr(resolved, "key_source", None)

    vr = verify_request(
        method=method,
        authority=authority,
        path=path,
        headers=h,
        body=body,
        public_key=resolved.public_key,
        require_content_digest=True,
        expected_tag=expected_tag,
        max_age_seconds=max_age_seconds,
        max_skew_seconds=max_skew_seconds,
        now=now,
        nonce_seen=nonce_seen,
        allowed_algorithms=allowed_algorithms,
    )
    r.valid = vr.valid
    r.errors.extend(vr.errors)
    return r


__all__ = [
    "DEFAULT_EXTENSION_URI",
    "DEFAULT_TAG",
    "A2A_MEDIA_TYPE",
    "DEFAULT_COVERED",
    "A2ASignatureError",
    "A2AVerifyResult",
    "sign_a2a_request",
    "verify_a2a_request",
]
