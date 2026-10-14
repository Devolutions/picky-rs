## INTENT.md

`INTENT.md` and `*.intent.md` files contain human-owned intent for the software.

- Read all applicable intent files before modifying code.
- Do not create, modify, or delete intent files.
- If a requested change conflicts with intent, stop and surface the conflict for human resolution.

## Writing for the repository

Committed text (code, comments, docs, commit messages) and PR titles and descriptions never refer to work stages, decision identifiers, agent roles, sessions or planning documents.
State rationale, not history.

## Invariant and untested-property comments

Define invariants with `INVARIANT:` comments: at the code for local and loop invariants, in the doc comment for field and function-output invariants.
Reference an invariant elsewhere without the prefix, which is reserved for defining it (for example, "Per invariants: …").

When code must keep a property that no test checks, mark it with an `UNTESTED:` comment at that code, because passing tests prove nothing about it.
The comment states the property, why it matters, and what to check when changing the code.
List `UNTESTED:` properties in a PR comment as well, not in the PR description, because the description becomes the squash commit body.

```rust
// INVARIANT: for i in 0..lo: xs[i] < x

// UNTESTED: decryption is blinded with the OS generator.
// Blinding changes no output; it is the rsa crate's countermeasure against timing attacks on the private key.
// When changing this call, keep `decrypt_blinded` with the generator from `os_rng()`.
```
