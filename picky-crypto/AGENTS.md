# picky-crypto

## Changing the contract

Before adding or changing an operation, check that RustCrypto, aws-lc-rs, ring, PKCS#11 (through `cryptoki`) and Windows CNG can each implement it natively or return `Unsupported`.
If any of them needs a workaround, do not add the operation; report the mismatch.

Before adding an operation, check whether it can be derived from existing operations.
If it can, implement it above the contract unless one of the exceptions in `INTENT.md` applies, and write down which one.

When you verify a library capability, cite the source file or documentation page at the pinned version, or write a minimal compile probe.
Mark anything you could not verify as Unknown.

## Contract item links

Every mention of an item `picky-crypto` exports in `CONTRACT.md` is an intra-doc link, such as [`Item`] or [`Type::method`]; a plain code span for such an item is a review finding.
Refer to enum variants by linking the variant, such as [`BuildError::Duplicate`], and describe its fields in prose instead of writing constructor-style spans such as `Duplicate(Algorithm)`.
Standard library items may be linked; names from crates `picky-crypto` does not depend on stay plain code spans.
