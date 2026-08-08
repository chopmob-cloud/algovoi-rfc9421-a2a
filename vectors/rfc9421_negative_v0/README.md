# rfc9421_negative_v0

Negative (must-reject) conformance vectors for the A2A per-message signature
extension v1, plus one positive control. A conforming verifier must reject all
ten negative cases and accept the control.

Reproducible from the RFC 8032 section 7.1 keypair; the runner signs the
baselines, applies each case's mutation, and compares the verdict to
`vectors.json`.

```
pip install algovoi-rfc9421-a2a
python verify.py     # exit 0 iff all 11 cases match
```

Cases: `valid_control`, `tampered_body`, `expired`, `wrong_tag`, `absent_alg`,
`disallowed_alg`, `wrong_keyid`, `malformed_signature_input`,
`no_extension_activation`, `replayed_nonce`, `missing_content_digest_coverage`.

Cross-validated against the installed `algovoi-rfc9421-a2a` 0.1.0 wheel (11/11).
