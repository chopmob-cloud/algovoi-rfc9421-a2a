"""Tests for the A2A RFC 9421 signing adapter (offline: did:key keyids)."""
from __future__ import annotations

import pytest

from algovoi_rfc9421_keyid import encode_did_key
from algovoi_rfc9421_a2a import (
    DEFAULT_EXTENSION_URI,
    A2ASignatureError,
    sign_a2a_request,
    verify_a2a_request,
)

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
PUB = bytes.fromhex("700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41")
DIDKEY = encode_did_key(PUB)                       # self-certifying, no network
OTHER_DIDKEY = encode_did_key(bytes(32))           # a different (all-zero) key
AUTH = "api.algovoi.co.uk"
PATH = "/a2a/rpc"
BODY = b'{"jsonrpc":"2.0","method":"message/send","id":1}'
T = 1778955520


def _sign(**over):
    kw = dict(body=BODY, private_key=SEED, keyid=DIDKEY, authority=AUTH, path=PATH, created=T)
    kw.update(over)
    return sign_a2a_request(**kw)


def _verify(headers, body=BODY, **over):
    kw = dict(headers=headers, body=body, authority=AUTH, path=PATH,
              now=T + 5, expected_keyid=DIDKEY)
    kw.update(over)
    return verify_a2a_request(**kw)


def test_roundtrip_valid():
    h = _sign()
    assert h["A2A-Extensions"] == DEFAULT_EXTENSION_URI
    assert h["Content-Type"] == "application/a2a+json"
    r = _verify(h)
    assert r.valid is True, r.errors
    assert r.extension_activated is True
    assert r.key_source == "inline"       # did:key resolved without network
    assert r.keyid == DIDKEY


def test_tampered_body_fails():
    h = _sign()
    r = _verify(h, body=b'{"jsonrpc":"2.0","method":"evil","id":1}')
    assert r.valid is False
    assert any("content-digest" in e.lower() or "digest" in e.lower() for e in r.errors)


def test_expired_fails():
    h = _sign()
    r = _verify(h, now=T + 10_000, max_age_seconds=300)
    assert r.valid is False
    assert any("age" in e.lower() or "older" in e.lower() for e in r.errors)


def test_wrong_tag_fails():
    h = _sign(tag="some-other-protocol")
    r = _verify(h)  # expected_tag defaults to a2a-signature-v1
    assert r.valid is False
    assert any("tag" in e.lower() for e in r.errors)


def test_extension_not_activated_fails_closed():
    h = _sign()
    del h["A2A-Extensions"]
    r = _verify(h)
    assert r.valid is False
    assert any("not activated" in e.lower() for e in r.errors)


def test_extension_activation_optional_when_disabled():
    h = _sign()
    del h["A2A-Extensions"]
    r = _verify(h, require_extension_activation=False)
    assert r.valid is True, r.errors


# --- TRUST BOUNDARY ---

def test_keyid_mismatch_rejected_without_resolving():
    # An attacker-chosen keyid that is not the expected one must be rejected
    # BEFORE any resolution/verification happens.
    h = _sign()
    resolver_called = {"n": 0}

    def spy_resolver(keyid, **kw):
        resolver_called["n"] += 1
        raise AssertionError("resolver must not run on a keyid mismatch")

    r = _verify(h, expected_keyid=OTHER_DIDKEY, resolver=spy_resolver)
    assert r.valid is False
    assert resolver_called["n"] == 0
    assert any("does not match expected" in e for e in r.errors)


def test_authorize_keyid_predicate_denies():
    h = _sign()
    r = verify_a2a_request(headers=h, body=BODY, authority=AUTH, path=PATH, now=T + 5,
                           expected_keyid=None, authorize_keyid=lambda k: False)
    assert r.valid is False
    assert any("not authorized" in e.lower() for e in r.errors)


def test_requires_keyid_authorization_by_default():
    # No expected_keyid and no authorize_keyid -> must refuse to guess (fail closed).
    h = _sign()
    with pytest.raises(A2ASignatureError):
        verify_a2a_request(headers=h, body=BODY, authority=AUTH, path=PATH,
                           now=T + 5, expected_keyid=None, authorize_keyid=None)


def test_optout_attests_key_holder_control_only():
    h = _sign()
    r = verify_a2a_request(headers=h, body=BODY, authority=AUTH, path=PATH, now=T + 5,
                           expected_keyid=None, authorize_keyid=None,
                           require_keyid_authorization=False)
    assert r.valid is True, r.errors


def test_replayed_nonce_fails():
    h = _sign(nonce="n-once-1")
    r = _verify(h, nonce_seen=lambda n, k: True)
    assert r.valid is False
    assert any("replay" in e.lower() for e in r.errors)


def test_malformed_signature_input_fails_closed_no_raise():
    # Attacker-controlled malformed Signature-Input must return valid=False,
    # never raise out of the verifier (security-validate finding).
    h = _sign()
    h["Signature-Input"] = "this is not a valid signature-input"
    r = _verify(h)  # must not raise
    assert r.valid is False
    assert any("malformed" in e.lower() or "signature-input" in e.lower() for e in r.errors)


def test_host_binding_opt_in_via_covered_authority():
    # By default @authority is not covered (per the #1829 shape), so the caller
    # opts into host binding by covering it. Prove the covered-authority path
    # round-trips and that a wrong authority then fails.
    covered = ["@method", "@authority", "@path", "content-digest", "created"]
    h = _sign(covered_components=covered)
    ok = _verify(h)
    assert ok.valid is True, ok.errors
    bad = _verify(h, authority="evil.example.com")
    assert bad.valid is False
