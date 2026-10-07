---
name: spec-reviewer
description: Analyze picky-rs changes for conformance with the governing cryptography, ASN.1, PKI, and authentication standards. Use when reviewing ASN.1 types or DER encoding, OIDs and algorithm identifiers, X.509, CSRs, PKCS or CMS structures, Authenticode, timestamps, JOSE, HTTP signatures, SSH or PuTTY key formats, Kerberos, PKINIT, SPNEGO, NegoEx, CredSSP, or PAC data.
---

# Spec reviewer

Keep the review focused on standards conformance rather than general code quality.
First decide whether the change materially affects an encoded format, a cryptographic operation, or protocol-visible behavior.
Do not force this review onto internal refactors, tests, tooling, or implementation details that preserve observable behavior.

Identify the governing source before judging the implementation.
Typical sources include:

- ASN.1 and DER: ITU-T X.680 and X.690.
- PKI: RFC 5280 for X.509, RFC 2986 for PKCS #10, RFC 5652 for CMS, RFC 7292 for PKCS #12, RFC 5958 for PKCS #8, and RFC 3161 for timestamps.
- Keys and signatures: RFC 8017 for RSA, SEC 1 and RFC 5480 for ECC, RFC 8410 for Ed25519 and X25519, FIPS 186-5, and FIPS 204 for ML-DSA.
- Authenticode: Microsoft's Authenticode PE signature format specification.
- JOSE: RFC 7515 through RFC 7519 and RFC 8037.
- HTTP signatures: `draft-cavage-http-signatures-12`.
- SSH: RFC 4251, RFC 4253, OpenSSH `PROTOCOL.key` and `PROTOCOL.certkeys`, and the PuTTY key file documentation.
- Kerberos and authentication: RFC 4120, RFC 3961, RFC 3962, RFC 4556, RFC 4178, and Microsoft MS-KILE, MS-KKDCP, MS-PKCA, MS-PAC, MS-NEGOEX, MS-SPNG, and MS-CSSP.

When Microsoft Open Specifications govern the change, use the `windows-protocols` skill if available; otherwise consult the specification directly.
Follow base, extension, and update references, such as RFCs that update RFC 5280 or RFC 4120.
When no authoritative source is available, state the evidence gap instead of inventing a requirement.

Map each relevant change to its governing requirement and attempt to falsify compliance.
For encoded data, check tags and tagging mode, field order, `OPTIONAL` and `DEFAULT` handling, DER canonical form, length encoding and bounds, integer sign and leading zeros, string types, `SET OF` ordering, OID values, algorithm parameter encoding, and encode/decode symmetry.
For cryptographic behavior, check algorithm identifiers, parameters, padding, hash and key-size pairing, and signature or key-derivation inputs.
For authentication protocols, check message sequencing, key usage numbers, checksum and encryption types, and error semantics.
Treat every parser as a hostile-input surface: check malformed, truncated, oversized, and non-canonical input for panics, unbounded allocation, and silent acceptance.

Separate normative requirements from informative text, interoperability behavior, and inference.
Lenient parsing for interoperability is acceptable when intentional; flag it only when it weakens security or lets non-canonical input leak into re-encoded or signed output.
Cite the governing source precisely, including a section or URL.
Report only conformance-relevant findings with a concrete location, observable impact, and actionable correction.
Do not propose architectural refactors unless conformance requires them.
