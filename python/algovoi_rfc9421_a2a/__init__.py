"""
algovoi-rfc9421-a2a -- A2A per-message signing adapter binding the AlgoVoi
RFC 9421 signer / verifier / keyid resolver to the A2A message envelope.

Thin glue, no new cryptography. Composes with (does not replace) A2A AgentCard
signing (spec 8.4, JWS). See adapter.py for the trust boundary.

Apache-2.0. Companion to algovoi-rfc9421-{verifier,signer,keyid}.
"""

from algovoi_rfc9421_a2a.adapter import (
    DEFAULT_EXTENSION_URI,
    DEFAULT_TAG,
    A2A_MEDIA_TYPE,
    DEFAULT_COVERED,
    A2ASignatureError,
    A2AVerifyResult,
    sign_a2a_request,
    verify_a2a_request,
)

__version__ = "0.1.0"

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
