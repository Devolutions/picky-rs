# Backend maintenance

- Inline tests cover adapter logic only: argument mapping, length and constant-byte checks.
  Do not retest behavior covered by the conformance suite or the library.
- Never edit `picky-crypto/CONTRACT.md` or `picky-crypto-testsuite` to make this backend pass; escalate with evidence: the failing case's cited source, vector identifier, expected outcome and native library behavior.
- Cite the source file or documentation page at the version locked in `Cargo.lock` when relying on a library capability, or mark it Unknown.
