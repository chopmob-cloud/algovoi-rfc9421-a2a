# algovoi-rfc9421-a2a


[![PyPI](https://img.shields.io/pypi/v/algovoi-rfc9421-a2a)](https://pypi.org/project/algovoi-rfc9421-a2a/)

A2A per-message signing adapter binding the AlgoVoi RFC 9421 signer, verifier,
and keyid resolver to the A2A message envelope. Thin glue over three shipped,
hardened primitives; no new cryptography.

- Signs and verifies A2A JSON-RPC requests with RFC 9421 (HTTP Message
  Signatures) + RFC 9530 (Content-Digest) over `application/a2a+json`.
- Resolves the signer `keyid` with the SSRF-guarded `algovoi-rfc9421-keyid`
  resolver (`did:key` / `did:web` / HTTPS).
- Enforces the Sprint A hardening: replay window, single-use nonce, `tag`
  anti cross-protocol reuse, and an algorithm allow-list.

## Layers

This is the per-message signature layer (does this specific request come from
the key holder). It is orthogonal to A2A AgentCard signing (spec 8.4, JWS over
the card document) and composes with it.

## Trust boundary

Verifying a signature proves the request was signed by the holder of the key
that `keyid` resolves to. It does not by itself prove the sender's identity;
that binding is a policy decision the caller owns, normally via the agent's
8.4-signed AgentCard. `verify_a2a_request` therefore requires `expected_keyid`,
an `authorize_keyid` predicate, or an explicit `require_keyid_authorization=False`
opt-out. It will not silently trust an attacker-chosen keyid.

## Install

```
pip install algovoi-rfc9421-a2a
```

Apache-2.0.
