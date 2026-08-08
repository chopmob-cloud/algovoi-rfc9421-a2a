#!/usr/bin/env python3
"""Runner for the rfc9421_negative_v0 conformance vectors.

Reproducible: signs baselines from the pinned RFC 8032 keypair, applies each
case's mutation, verifies through algovoi-rfc9421-a2a, and compares the verdict
to vectors.json. Exit code 0 iff every case matches.

    pip install algovoi-rfc9421-a2a
    python verify.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from algovoi_rfc9421_a2a import sign_a2a_request, verify_a2a_request
from algovoi_rfc9421_keyid import encode_did_key

HERE = Path(__file__).resolve().parent
M = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
KP, BL = M["keypair"], M["baseline"]

SEED = KP["seed_hex"]
PUB = bytes.fromhex(KP["public_key_hex"])
KEYID = encode_did_key(PUB)
OTHER_KEYID = encode_did_key(bytes(32))
AUTH, PATH, METHOD = BL["authority"], BL["path"], BL["method"]
T, NOW, TAG = BL["created"], BL["verify_now"], BL["tag"]
BODY = b'{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[{"text":"hi"}]}}}'

assert KEYID == KP["keyid"], f"keyid drift: {KEYID} != {KP['keyid']}"


def _sign(**over):
    kw = dict(body=BODY, private_key=SEED, keyid=KEYID, authority=AUTH,
              path=PATH, method=METHOD, created=T, tag=TAG)
    kw.update(over)
    return sign_a2a_request(**kw)


def _verify(headers, body=BODY, **over):
    kw = dict(headers=headers, body=body, authority=AUTH, path=PATH,
              method=METHOD, now=NOW, expected_keyid=KEYID)
    kw.update(over)
    return verify_a2a_request(**kw)


def run(name):
    if name == "valid_control":
        return _verify(_sign())
    if name == "tampered_body":
        return _verify(_sign(), body=b'{"jsonrpc":"2.0","id":1,"method":"evil"}')
    if name == "expired":
        return _verify(_sign(), now=T + 10_000, max_age_seconds=300)
    if name == "wrong_tag":
        return _verify(_sign(), expected_tag="a-different-context")
    if name == "absent_alg":
        h = _sign(); h["Signature-Input"] = h["Signature-Input"].replace(';alg="ed25519"', ""); return _verify(h)
    if name == "disallowed_alg":
        return _verify(_sign(), allowed_algorithms={"ecdsa-p256-sha256"})
    if name == "wrong_keyid":
        return _verify(_sign(), expected_keyid=OTHER_KEYID)
    if name == "malformed_signature_input":
        h = _sign(); h["Signature-Input"] = "garbage not a valid structured field"; return _verify(h)
    if name == "no_extension_activation":
        h = _sign(); h.pop("A2A-Extensions", None); return _verify(h)
    if name == "replayed_nonce":
        return _verify(_sign(nonce="nonce-1"), nonce_seen=lambda n, k: True)
    if name == "missing_content_digest_coverage":
        return _verify(_sign(covered_components=["@method", "@path", "created"]))
    raise SystemExit(f"unknown case: {name}")


def main():
    fails = 0
    for c in M["cases"]:
        r = run(c["name"])
        ok = (r.valid == c["expect_valid"])
        if not c["expect_valid"] and c.get("error_contains"):
            ok = ok and any(c["error_contains"].lower() in e.lower() for e in r.errors)
        print(f"{'PASS' if ok else 'FAIL'}  {c['name']:32s} valid={r.valid!s:5s} "
              f"expected={c['expect_valid']!s:5s} err={(r.errors[:1] or [''])[0][:60]}")
        fails += (not ok)
    total = len(M["cases"])
    print(f"\n{total - fails}/{total} vectors matched")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
