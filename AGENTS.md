# picky-rs

Reusable agent skills live in `.agents/skills/` and `.github/skills/`; use the matching skill before committing, opening a pull request, posting a GitHub comment, or writing prose.
Skills listed in `.github/skills-sync.yml` are overwritten weekly from `Devolutions/devolutions-gateway`; change those upstream, and keep repository-local skills out of that list.

Start a work session with `/contribute`, which picks the delivery flow by scale and the skills each step needs.

## Intent files

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.
Read all applicable intent files before modifying code.
Do not create, modify, or delete intent files.
If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Writing for the repository

Committed text (code, comments, docs, commit messages) and PR titles and descriptions never refer to work stages, decision identifiers, agent roles, sessions or planning documents.
State rationale, not history.

## Rust

Write Rust with the `rust-style` skill and tests with the `test-writer` skill.
Think before silencing a lint, then use `#[expect(<lint>, reason = "...")]` so the suppression explains itself and expires when it stops being needed.
Library crates expose typed errors, with `thiserror` or hand-rolled `Display`/`Error` impls, never `anyhow`.

## Untested-property comments

When code must keep a property that no test checks, mark it with an `UNTESTED:` comment at that code, because passing tests prove nothing about it.
The comment states the property, why it matters, and what to check when changing the code.
List `UNTESTED:` properties in a PR comment as well, not in the PR description, because the description becomes the squash commit body.

```rust
// UNTESTED: decryption is blinded with the OS generator.
// Blinding changes no output; it is the rsa crate's countermeasure against timing attacks on the private key.
// When changing this call, keep `decrypt_blinded` with the generator from `os_rng()`.
```
