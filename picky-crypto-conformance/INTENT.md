# picky-crypto-conformance

## Purpose

Runs the `picky-crypto-testsuite` conformance and differential suites against every backend provider and every composition the workspace ships, from one test binary built once per backend set.

## Invariants

- It contains no test logic.
  Test cases, vectors and the harness live in `picky-crypto-testsuite`; this crate only lists providers and invokes the suite.
- Backends are optional dependencies, each behind a feature of this crate, and each is built with its full capability set.
- Backends that cannot share a build (the FIPS and non-FIPS builds of `aws-lc-rs`) are covered by separate builds of the same binary.
- Every enabled provider runs the full conformance suite, and every pair of enabled providers runs the differential suite.
- Conformance runs on unwrapped providers; policy-wrapped providers are tested in `picky-crypto-fips-policy`.
- It is never published.
