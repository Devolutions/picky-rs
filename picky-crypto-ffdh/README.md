# picky-crypto-ffdh

Finite-field Diffie-Hellman for the [picky-crypto contract], implemented over crypto-bigint.
This is a fill-in provider: no reference library offers FFDH in the form the contract requires, so this crate implements it for any base provider.
Call `picky_crypto_ffdh::provider(&base)` with the provider whose secure random entry ephemeral exponents should come from; it is the only randomness this provider uses.

Each entry exists when what it needs exists:

- loading of static keys (`PrivateKeyLoader` for `KeyType::Ffdh`) needs no randomness and is always present;
- ephemeral agreement (`FfdhKeyAgreement`) is present only when `base` has a secure random entry, which `provider` takes when it runs.

Loaded keys support static agreement only; like every FFDH key, they don't export a public key.
Both entries and every loaded key report `fips() == false`, because FFDH with arbitrary groups is not FIPS-approved.

## Checks

Parameters, private values and peer values are checked exactly as contract section 6.11 requires, with the errors it assigns.
B denotes q, or `(p − 1) / 2` when q is absent.
Public values and shared secrets are left-padded to the byte length of p.
The primality of p and q and the order of g are trusted, not checked.

## Capacity limit

A modulus above 8192 bits, the size of the largest RFC 3526 group, returns `Unsupported` before any check other than the encoding length, which the contract fixes and which therefore takes precedence.
The error names `KeyAgreement(Ffdh)` for ephemeral generation and `PrivateKeyLoading(Ffdh)` for loading.
Every modulus from 1024 to 8192 bits is processed, which covers the 1024, 2048, 3072 and 4096-bit sizes the contract requires.

## Exponent generation

Ephemeral exponents follow NIST SP 800-56A rev. 3 section 5.6.1.1.4, key-pair generation by testing candidates.
With N the bit length of B, each draw takes `ceil(N / 8)` bytes from the generator, clears the bits above N, and accepts the candidate c when `c <= B − 2`; the exponent is `c + 1`.
Each draw is accepted with probability close to one half or more, so generation returns `ProviderFailure` after 64 rejected draws rather than looping on a broken generator.
A generator error is returned unchanged.

## Secret handling

Private exponents, candidates and shared secrets go through no variable-time operation.
crypto-bigint 0.7.5, the version locked in `Cargo.lock`, provides the following:

- `BoxedUint::from_be_slice` copies every byte of the encoding without branching on its value (`src/uint/boxed/encoding.rs` and `fill_limbs_from_be_slice_truncated` in `src/uint/encoding.rs`), and range checks use `is_nonzero` and `ct_lt` (`src/uint/boxed.rs`, `src/uint/boxed/ct.rs` and `UintRef::lt` in `src/uint/ref_type/cmp.rs`);
- `BoxedUint::wrapping_add`, which turns an accepted candidate into the exponent, runs a fixed carry chain over every limb (`carrying_add` in `src/uint/boxed/add.rs`);
- `BoxedMontyForm::pow_bounded_exp` runs fixed 4-bit windows over the requested bit length with a constant-time table lookup (`pow_montgomery_form_amm` in `src/modular/pow.rs`), and its multiplications reduce with masked subtractions (`almost_montgomery_mul` and `almost_montgomery_reduce` in `src/modular/mul.rs`); the provider requests the bit length of B, which depends only on the group;
- `BoxedMontyForm::retrieve` and `BoxedUint::to_be_bytes` produce fixed-width results (`montgomery_retrieve_inner` in `src/modular/reduction.rs`, `src/uint/boxed/encoding.rs`), and the provider copies the last bytes of that fixed width.

Every secret the provider holds is wiped on drop, through `Zeroizing` and the `Zeroize` implementations that crypto-bigint's `zeroize` feature enables for `BoxedUint` (`src/uint/boxed.rs`) and `BoxedMontyForm` (`src/modular/boxed_monty_form.rs`).
The `BoxedMontyForm` implementation wipes the value but not the Montgomery parameters, which derive only from the public modulus, and the multiplier wipes its scratch product on drop (`BoxedMontyMultiplier` in `src/modular/boxed_monty_form/mul.rs`).
State inside crypto-bigint is wiped only as far as its own cleanup goes: `pow_montgomery_form_amm` (`src/modular/pow.rs`) leaves the window power it selects from the exponent unwiped.

## Conformance tests

The `picky-crypto-conformance` runner tests this provider as part of [picky-crypto-bundle], over the RustCrypto backend, through its `bundle` feature.
Initialize the published-vector submodule before running it:

```console
git submodule update --init
cargo test -p picky-crypto-conformance --features bundle
```

This crate's own tests cover only exponent sampling and the public value it yields, the size, encoding and private-value bounds the published vectors do not reach, the entries built from `base` and their FIPS reports.

[picky-crypto contract]: ../picky-crypto/CONTRACT.md
[picky-crypto-bundle]: ../picky-crypto-bundle/README.md
