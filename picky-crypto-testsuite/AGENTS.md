# picky-crypto-testsuite

Sources, versions and checksums are in `vectors/manifest.toml`; `cargo xtask check-vectors` checks it.

## Changing the vector set

- Add vectors only for algorithms and parameters the contract defines.
- Wycheproof is the `vectors/wycheproof` submodule.
  To add or update its vectors, move the pinned commit (submodule and manifest together), list the files the suite reads, and rerun the suite against every backend.
- Other sources are vendored.
  Vendor a whole upstream file when all of it applies; otherwise keep whole groups or sections, cut only at their headers, and record the rule as the entry's `extract` and the kept upstream line ranges as `lines`.
  Record the source URL and version; the checksum is `git hash-object --no-filters <file>`.
- To update a vendored source, replace its files wholesale and rerun the suite against every backend.
- Never edit a vector file or trim inside a group.
- A boundary value may be derived from a published value by a change confined to known bytes and asserted in the test (for example p − 1 for odd p: only the last byte differs).
  Like other hand-written inputs, it expects a specified error, or acceptance only as a control at a boundary the contract defines (`INTENT.md`).
- Report newly failing vectors, and the size of any vendored data added.

## Hand-written inputs

- Structural inputs are not limited to empty, zero, one, or lengths at or beyond a limit.
- A hand-written input that targets one check carries a control in the test asserting that every other check holds, so it can fail only for the intended reason.
- A control sits at a boundary the contract defines: the accepted value next to a rejected range limit, or the value just above the must-support set.
  It accepts success, or `Unsupported` when its value is outside the must-support set.
  It asserts only contract properties, and differential runs compare its output between backends when it has no published answer.
- Keep controls small: omit any control whose processing could exhaust a conforming backend's time or memory, and record the boundary it leaves unchecked as a known gap in `CONTRACT.md` section 12.
- Prefer deriving such inputs from published ones.
