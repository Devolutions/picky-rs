# Composed provider maintenance

- Inline tests cover only this crate's own logic, listed at the end of the README, and name the fault each one catches.
  Do not retest behavior covered by the conformance suite.
- Never edit `picky-crypto/CONTRACT.md` or `picky-crypto-testsuite` to make this provider pass; escalate with evidence: the failing case's cited source, vector identifier, expected outcome and actual behavior.
