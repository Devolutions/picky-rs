# picky-crypto

## Purpose

This crate defines the minimal cryptographic provider contract used by picky, picky-krb, sspi-rs and their downstream consumers (IronRDP, Devolutions Gateway).

It is expected to outlive picky's format modules.
JOSE, X.509 and DER handling may move to other crates over time; this contract is the durable part.
Its minimality and stability take priority over convenience.

Implementing a new backend must be as simple as implementing this contract on top of one library (RustCrypto, aws-lc-rs, ring, or a handle-based API such as PKCS#11 or Windows CNG).

## Design principle

**Require the weakest capability every library has, and pass the most information you have.**

An operation that one of the reference libraries (RustCrypto, aws-lc-rs, ring, a handle-based API) can only implement through a workaround is a contract defect.
`Unsupported` is an acceptable answer; a workaround is not.

A workaround is logic the adapter implements because the library lacks it: parsing or producing variable-length encodings, arithmetic on keys or values, padding, or any step of the algorithm.
Using another library to fill a gap is also a workaround; a backend's library is the set of crates it declares as such.
Chaining public library functions, filling fixed-layout structures, inserting algorithm-determined constants, and fixed-width transformations (splitting coordinates, stripping a fixed prefix byte, reversing byte order) are argument mapping, not workarounds.
The test: argument mapping never inspects the input beyond checking algorithm-fixed lengths and constant bytes.

In practice:

- Pass the message, not the digest.
  A handle-based backend can hash the message itself, but a library like ring only signs messages and can't accept a digest you hand it.
- Accept one standard encoding per key type: the one the reference libraries import natively, among those that import that key type at all.
  Converting from JWK `n`/`e` or SSH mpints is format code and belongs above the boundary.
  - Private keys: PKCS#8.
    Two exceptions, because the reference libraries do not import them from PKCS#8: X25519 private keys are the raw 32-byte RFC 7748 scalar, and FFDH private keys are the domain parameters (p, g, optional q) and the private exponent, each as an unsigned big-endian integer.
  - Public keys, including key-agreement peer keys: the contents of the SPKI `subjectPublicKey`: PKCS#1 `RSAPublicKey` for RSA, the uncompressed SEC1 point for EC, the raw 32 bytes for Ed25519 and X25519.
    The contract's algorithm already fixes the key type, curve and hash, so the SPKI wrapper adds nothing, and some reference libraries (ring) have no SPKI parser.
    Extracting the contents from an SPKI, and rejecting compressed EC points, is format code.
- Return owned buffers.
- Never require exporting a private key; export is an optional extra.
- Allow `Unsupported` for anything.
- Keep the surface at the level of standardized algorithms (HMAC-SHA256, AES-GCM, PBKDF2), not math building blocks.
  That's the minimality that holds up under FIPS.

## Minimality

Two ways of doing the same thing is a bug.

If an operation can be obtained by combining other operations of the contract, it does not belong in the contract.
It belongs in a separate crate or in a helper above the contract.

An operation that is derivable may stay in the contract only when composing it outside the backend would:

1. incur a non-negligible performance cost;
2. move the computation outside a validated module boundary (for FIPS, HMAC, HKDF, PBKDF2 and AES-GCM must execute as whole operations inside the module, even though they are derivable from lower-level primitives); or
3. lose a security property the backend provides (constant-time implementation, non-exportable keys).

Each such exception is justified in writing next to the operation's definition.

Protocol-specific constructions stay in their protocol crates: Kerberos n-fold, CTS and RFC 3961 key derivation in picky-krb; NTLM constructions in sspi-rs; JOSE and SSH framing in their respective modules.

## Provider shape

The provider is a value assembled from capability entries, in the spirit of rustls's `CryptoProvider`, not a single large trait.

Each capability entry implements exactly one algorithm from a closed, `#[non_exhaustive]` set of algorithm identifiers defined by this crate.
A provider containing two entries for the same algorithm cannot be constructed.

Entries are looked up by algorithm.
How they are stored is private to this crate.

Availability is queryable per algorithm.
Consumers determine whether they can operate by checking the algorithms they require (for example, NTLM requires MD4, MD5 and RC4) and fail with an error naming the missing algorithms.
Capability detection never relies on a FIPS flag.

`fips()` reports whether the backend's operations execute inside a FIPS module, as built and running in FIPS mode; whether a deployment matches a certificate is established outside the program.
It is an input to policy, not a capability query.

Policy is a transformation from provider to provider.
A FIPS policy keeps only approved entries and requires `fips()` to be true.

Composition of providers is explicit: performed by the binary, or fixed in a dedicated bundle crate.
Libraries never compose providers.
For example, a binary may add a fallback from one provider to another for algorithms the first does not support.
No provider ever falls back to another implicitly.

Private keys are trait objects.
Hardware and external keys (smartcards, PKCS#11, CNG, TPM) implement the private key trait directly, without going through a provider.

## Process-wide default

A binary installs the process-wide default provider once, before the first cryptographic operation.
Libraries never install a provider, except through a `rustcrypto` convenience feature that installs the RustCrypto bundle provider lazily when no provider was installed.

Using the default before one is installed is a programming error and panics with a message explaining how to install a provider; code that must not panic checks with `get_default` and returns an error.
Installing a default when one is already set returns an error.

An algorithm that the installed provider does not support is a data-dependent condition and is reported as an error, never as a panic.

## Invariants

- It has no dependency on any crypto library or crypto trait crate (`rand_core`, `digest`, `signature`, `cipher`, `elliptic-curve`).
  Only `zeroize` is allowed, checked with cargo-deny on that crate.
- It knows nothing about formats: no DER parsing, no OIDs, no JOSE or SSH names.
- Traits are object-safe, and consumers never use generics over the provider.
- The only allowed default method on provider traits is one that returns `Unsupported`.
- Errors are a small closed set.
  Verification failure carries no reason, and no backend error type crosses the boundary.
- What a provider advertises matches what it does.
  Unadvertised algorithms return `Unsupported`, and no input ever panics.

## Non-goals

- Parsing or encoding any format beyond carrying DER bytes opaquely.
- Protocol-specific constructions.
- Compile-time enforcement of FIPS-approved algorithms.
  Algorithm choice comes from parsed data; the build-time guarantee is the dependency ban, and the runtime guarantee is policy.
