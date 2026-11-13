# Bundle maintenance

- Keep `provider()`, its documentation and the README's composition order and feature table in agreement.
- To add a backend, add a feature enabling the whole backend, include it in `all`, and insert its feature-gated line at its place in the backend list of `provider()`.
- Inline tests cover only the feature assembly; the conformance suite tests the composition.
- Never edit `picky-crypto/CONTRACT.md` or `picky-crypto-testsuite` to make this provider pass; escalate with evidence: the failing case's cited source, vector identifier, expected outcome and actual behavior.
