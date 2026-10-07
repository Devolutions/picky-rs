---
name: commit-scope
description: Derive and validate the canonical scope for picky-rs Conventional Commit and pull-request titles. Use whenever composing, reviewing, correcting, or checking a commit or PR title, especially when several crates or product surfaces intersect.
---

# Commit scope

Choose at most one optional scope for `<type>[optional scope][!]: <description>`.

## Canonical scopes

```text
picky picky-asn1 picky-asn1-der picky-asn1-x509 picky-krb picky-test-data
ffi wasm fuzz release agents deps
```

Crate scopes use the full crate name.
Use these aggregate mappings:

- `picky`: the `picky` crate under `picky/`, excluding its fuzzing harness.
- `ffi`: the Rust FFI crate under `ffi/` and the generated or manual .NET and Swift bindings, including `ffi/dotnet`.
- `wasm`: the WASM bindings under `ffi/wasm` and the npm package under `ffi/js`.
- `fuzz`: fuzz targets, harnesses, corpora, and fuzzing automation under `picky/fuzz`.
- `release`: changelogs, packaging, publishing to crates.io, NuGet, npm, or Swift registries, and release automation.
- `agents`: agent instructions and reusable skills.

## Selection rules

1. Scope the contract or behavior being changed, not every touched path.
2. When another component owns the change, ignore supporting tests, documentation, generated files, manifests, lockfiles, and call-site adaptations.
3. Prefer the component defining the behavior over components that merely consume it.
4. Prefer the crate defining the format: `picky-asn1-x509` over `picky` for an X.509 structure change, and `picky-asn1-der` for DER serialization behavior.
5. Split independent contract changes when practical.
6. Omit the scope when an indivisible change has multiple equal owners.
7. Never combine scopes or invent a catch-all scope; explain secondary effects in the body.
8. Add a new scope only for a distinct contract that does not fit an existing aggregate.

Use the component scope with any applicable type:

```text
fix(picky): don't panic on RFC 3161 timestamp fallback
feat(picky-krb): add IAKerb proxy message encoding/decoding
ci(release): use Trusted Publishing for NuGet
build(wasm): update frontend dependencies
```

Do not use types, package ecosystems, or cross-cutting aspects as scopes.
This excludes `ci`, `test`, `docs`, `build`, `perf`, `tooling`, `automation`, `workspace`, `crypto`, `security`, `api`, `nuget`, `npm`, `swift`, `dotnet`, and `crates`.
Use no scope for genuinely repository-wide changes.

## Dependency updates

Use `build(deps)` for changes that only update dependency versions or features, such as Dependabot PRs and lockfile refreshes.
When an update requires code changes, scope it to the crate owning those changes, such as `build(picky-krb)`.
`deps` is valid only with the `build` type.

## Tests

A production change accompanied by tests keeps its production type and scope.
For test-only changes, use `test(<crate>)` with the crate under test, or `test(picky-test-data)` for shared fixtures.
Omit the scope when test-only changes span several crates.
