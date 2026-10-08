# `picky-crypto` contract

This document specifies the `picky-crypto` cryptographic provider contract.
It is normative: a backend author can implement a backend from this document alone, and the conformance suite derives its expectations from it and from the published standards it cites.
`INTENT.md`, next to this file, states the purpose and invariants of the crate; this document turns them into a precise interface.
Appendix A gives the complete public API as Rust declarations; the sections below specify its behavior.

## 1. Scope

The contract consists of:

- algorithm identifiers (section 3);
- the closed error set (section 4);
- key, signature and secret encodings (section 5);
- capability traits, one entry per algorithm (section 6);
- the private key trait (`PrivateKey`), implemented by backends and directly by hardware or external keys (section 7);
- the provider value and its builder (section 8);
- the process-wide default (section 9).

Helpers (section 10) are free functions written only against that public API.
Backends never implement or override them.

The crate depends only on `zeroize`.
It parses no format: DER is carried opaquely in byte slices.

## 2. General rules

These rules apply to every operation and are not repeated.

1. **Owned, zeroizing outputs.**
   Every buffer the contract returns is wiped on drop, with no exception: digests, MAC tags, nonces, ciphertext and plaintext, RC4 output, signatures, derived keys, shared secrets, public values and generated keys.
   Variable-length outputs are a newly allocated `OutputBytes`, an opaque wrapper around `Zeroizing<Vec<u8>>`.
   Fixed-size values keep fixed-size types: the X25519 private key returned by `random_x25519_private_key` is an `X25519Scalar`, an opaque wrapper around `Zeroizing<[u8; 32]>`, which matches `PrivateKeyMaterial::X25519(&[u8; 32])`.
   Both dereference to their bytes, implement `AsRef<[u8]>`, and give back the `Zeroizing` value through `into_inner()`, never a plain buffer.
   Both implement `Clone`, which clones the inner `Zeroizing` value: a clone is itself wiped on drop, so a caller needing a copy has no reason to fall back to an unwiped `to_vec()`.
   Their `Debug` prints only the length, and they implement neither `Display` nor any comparison or hashing trait (`PartialEq`, `Eq`, `Hash`, `Ord`), so that no buffer is printed by accident.
   MAC results are `MacTag` and `MacVerifier` (section 6.2) rather than `OutputBytes`; `MacOutput` is their backend-side carrier.
   Whether an output is secret cannot be decided by operation: the NT hash is an MD4 digest, NTLMv2 and RFC 3961 derive keys from HMAC and hash outputs, and RC4 output is plaintext when decrypting; a uniform rule is fail-safe.
   `SecureRandom::fill` writes into the caller's buffer, which stays the caller's responsibility.
   Buffers the caller passes in, including `PrivateKeyMaterial`, belong to the caller, who is responsible for wiping them.
   Zeroizing is best effort: copies the caller makes, and reallocations of a buffer the caller grows, are not wiped.
   Secret state owned by a software implementation (private keys, MAC keys, cipher and keystream state in contexts, ephemeral secrets, and any copy of key material the adapter keeps) is also wiped on drop, best effort.
   The adapter always wipes its own copies.
   State inside the library is wiped only as far as the library's own cleanup does; some libraries do not guarantee this.
   Keys held by a device or an OS key store are outside this rule.
2. **No panics.**
   No input, however malformed, makes a backend panic.
   Some library APIs panic on out-of-range lengths; the adapter checks those bounds first and returns the error rule 4 prescribes.
3. **Advertised means implemented.**
   An entry identifies exactly one algorithm: the one its `algorithm()` returns (wrapped in `Algorithm`), or `PrivateKeyLoading(key_type())` for a `PrivateKeyLoader` entry, or `KeyAgreement(Ffdh)` for an `FfdhKeyAgreement` entry.
   `Mac`, `Cipher`, `Aead` and `KeyWrap` entries advertise only the protections their `supports()` reports (section 8); every other entry advertises every operation of its trait.
   Each advertised operation implements its algorithm for every input in its must-support set, except as allowed by rule 4 and by a policy's input narrowing (section 8.2).
   An algorithm with no provider entry cannot be reached through it: the lookup fails and the caller reports `Unsupported`.
   Private-key operations are advertised by the key itself (`PrivateKey::supports`, section 7), not by provider entries.
4. **Valid domain and must-support set.**
   Each operation defines a valid domain (inputs that are well-formed for the algorithm) and, within it, a must-support set.
   For an advertised operation:
   - An input outside the valid domain returns `InvalidKey` (key material) or `InvalidInput` (anything else), except that a verifier on a library with a single opaque failure may return `VerificationFailed` for an unusable public key (section 4).
   - An input inside the valid domain but outside the must-support set is either processed like an input in the must-support set or rejected with `Unsupported(algorithm)` (or, for such a verifier, `VerificationFailed`, section 4).
     For example, a backend may refuse RSA private keys other than 2048, 3072 or 4096-bit two-prime keys with equal-size primes, because some libraries accept only those.
   - An input in the must-support set never returns `Unsupported`, except for policy input narrowing (section 8.2).
   - Where an operation states no explicit domain for a length, any length is valid and lengths up to 2^31 − 1 bytes are in the must-support set.
   - Valid domains include the limits of the standard that defines the algorithm (for example RFC 8018's maximum derived-key length).
     Those limits are checked first, before allocation or any cryptographic processing, with overflow-safe arithmetic on `usize` arguments.
5. **No RNG parameter.**
   Operations that need randomness (key generation, ephemeral keys, ECDSA nonces, RSA encryption padding, AES-GCM seal nonces) use the backend's own secure random generator.
   No generator is passed in, because some libraries accept only their own.
6. **Lengths are checked.**
   For advertised operations, wrong key, IV, open nonce or tag lengths are reported as `InvalidKey` (for keys) or `InvalidInput` (for anything else), never truncated or padded silently.
7. **Thread safety and diagnostics.**
   Entries and private keys are `Send + Sync` (supertraits of their traits, so `dyn Trait` is the trait-object type used); contexts and ephemeral secrets are `Send`.
   `Debug` is not a supertrait: `picky-crypto` implements `Debug` for each capability and private-key trait object, printing only the algorithm (or key type) and `fips()`.
   `Box` and `Arc` of these trait objects are therefore `Debug`, so consumers can derive `Debug` on types that hold them.
   No backend's `Debug` output, which might reveal secret material, is reachable through the contract.
   Contexts and ephemeral secrets are not `Debug`.
   `algorithm()`, `key_type()`, `key_size_bits()`, `fips()` and `supports()` (sections 7 and 8, including `Mac`, `Cipher`, `Aead` and `KeyWrap`) are cheap and infallible and never access a device; the `Debug` implementations call `fips()`.
   `supports()` never performs the operation.
8. **State after an error.**
   An error returned by `HashContext::update`, `MacContext::update` or `StreamCipherContext::apply` leaves the context unusable: the caller drops it, and any further call on it returns `ProviderFailure` without panicking.
   Contexts are not transactional: a failed call may or may not have consumed input or keystream.
   After `SecureRandom::fill` fails, the destination content is unspecified and must not be used.
9. **Minimality exceptions.**
   An operation that can be derived from other operations of the contract is in the contract only if composing it outside the backend would cost performance (exception 1), move the computation outside a validated module boundary (exception 2), or lose a security property the backend provides (exception 3).
   Each such operation carries an "Exception" note naming the exception that applies.

## 3. Algorithm identifiers

There is one enum per capability category, plus a wrapping `Algorithm` enum.
Per-category enums make it a type error to ask a hash entry for an AEAD algorithm.
`Algorithm` is used where categories meet: provider lookup, availability lists, and `Error::Unsupported`.
All of these enums are `#[non_exhaustive]`, `Copy`, `Eq` and `Hash`.

| Enum | Variants |
|---|---|
| `HashAlgorithm` | `Md4`, `Md5`, `Sha1`, `Sha224`, `Sha256`, `Sha384`, `Sha512`, `Sha3_384`, `Sha3_512` |
| `MacAlgorithm` | `HmacSha1`, `HmacSha224`, `HmacSha256`, `HmacSha384`, `HmacSha512` |
| `PasswordKdfAlgorithm` | `Pbkdf2HmacSha1`, `Pbkdf2HmacSha224`, `Pbkdf2HmacSha256`, `Pbkdf2HmacSha384`, `Pbkdf2HmacSha512` |
| `KdfAlgorithm` | `OneStepSha1`, `OneStepSha256`, `OneStepSha384`, `OneStepSha512`, `CounterHmacSha1`, `CounterHmacSha256`, `CounterHmacSha384`, `CounterHmacSha512` |
| `CipherAlgorithm` | `Aes128Cbc`, `Aes192Cbc`, `Aes256Cbc`, `TdesEde3Cbc`, `Rc2Cbc` |
| `StreamCipherAlgorithm` | `Rc4` |
| `AeadAlgorithm` | `Aes128Gcm`, `Aes192Gcm`, `Aes256Gcm` |
| `KeyWrapAlgorithm` | `Aes128Kw`, `Aes192Kw`, `Aes256Kw` |
| `SignatureAlgorithm` | `RsaPkcs1v15Md5`, `RsaPkcs1v15Sha1`, `RsaPkcs1v15Sha224`, `RsaPkcs1v15Sha256`, `RsaPkcs1v15Sha384`, `RsaPkcs1v15Sha512`, `RsaPkcs1v15Sha3_384`, `RsaPkcs1v15Sha3_512`, `EcdsaP256Sha256`, `EcdsaP384Sha384`, `EcdsaP521Sha512`, `Ed25519` |
| `AsymmetricEncryptionAlgorithm` | `RsaPkcs1v15`, `RsaOaepSha1`, `RsaOaepSha256` |
| `KeyAgreementAlgorithm` | `EcdhP256`, `EcdhP384`, `EcdhP521`, `X25519`, `Ffdh` |
| `KeyType` | `Rsa`, `EcP256`, `EcP384`, `EcP521`, `Ed25519`, `X25519`, `Ffdh` |
| `KeyGenerationAlgorithm` | `Rsa2048`, `Rsa3072`, `Rsa4096`, `EcP256`, `EcP384`, `EcP521`, `Ed25519` |
| `RandomAlgorithm` | `SecureRandom` |

`Algorithm` has one variant per category: `Hash`, `Mac`, `PasswordKdf`, `Kdf`, `Cipher`, `StreamCipher`, `Aead`, `KeyWrap`, `Signature`, `AsymmetricEncryption`, `KeyAgreement`, `PrivateKeyLoading(KeyType)`, `KeyGeneration`, `Random`, plus `PublicKeyExport(KeyType)`.
`PublicKeyExport` is never a provider entry: it identifies `PrivateKey::public_key()` in `Error::Unsupported`, so that the error names the operation that is missing.

`HashAlgorithm::output_len()` is a `const fn` giving the digest length (16, 16, 20, 28, 32, 48, 64, 48, 64 bytes in the order above); it is metadata, not an operation.

The algorithm set is the one picky, picky-krb and sspi-rs need: every algorithm has a consumer, and algorithms are not added because a library offers them.
picky's `ssh` and `putty` features also use three primitives that the contract does not define, for encrypted private keys: bcrypt-pbkdf, AES-CTR and Argon2.
Those features do not go through the provider; bringing them under it means adding these primitives as capabilities (section 3.1), with AES-CTR as a single transform because encryption and decryption are the same operation.

### 3.1 Extensibility

The contract can gain algorithms and capability categories without a breaking change:

- every algorithm enum, `Algorithm`, `Entry`, `KeyType`, `KeyOperation`, `Protection`, `Requirement`, `PrivateKeyMaterial`, `Error` and `BuildError` is `#[non_exhaustive]`, so consumers and backends already match them with a wildcard arm;
- `FfdhParameters` and `Sealed` are `#[non_exhaustive]` and built with their `new` functions; `PublicKey` is a tuple struct over one slice;
- a new capability is a new trait plus a new `Entry` and `Algorithm` variant; existing traits are untouched;
- an optional `PrivateKey` operation gets a default that returns `Unsupported`.

## 4. Errors

The error set is closed: only the contract defines variants, never a backend, and no backend type crosses the boundary.
`Error` and `BuildError` are `#[non_exhaustive]` (section 3.1).

| Variant | Meaning |
|---|---|
| `Unsupported(Algorithm)` | The provider or key does not implement this algorithm, operation, size or parameter, or a policy refuses it (section 8.2). Data-dependent, never a panic. |
| `InvalidKey` | Key material is malformed, of the wrong type or size for the algorithm, or rejected by the library's key validation. |
| `InvalidInput` | A non-key input is malformed or out of range (except an RSA ciphertext value, see `VerificationFailed`): IV or open nonce length, data length not a multiple of the block size, output length out of range, zero iterations, invalid peer public value. |
| `VerificationFailed` | A signature does not verify, an AEAD tag or key-unwrap integrity check fails, or RSA decryption fails (invalid padding, or a modulus-length ciphertext whose value is not less than the modulus). It carries no reason, so the error does not reveal which check failed. |
| `ProviderFailure` | The backend failed for a reason that does not depend on the inputs: device removed, OS error, RNG failure, PIN required. Details stay in the backend. |

`BuildError` is a separate closed type returned only by `ProviderBuilder::build`: `Duplicate(Algorithm)` when two entries implement the same algorithm, and `Mismatched(Algorithm)` when an entry reports an algorithm that its `Entry` variant cannot implement (section 8).
`install_default` returns the rejected provider instead of an error value.

When both `InvalidKey` and `InvalidInput` could apply, report `InvalidKey`.
`ProviderFailure` includes "PIN required", which callers therefore cannot distinguish from other device failures; this is a known limit of the closed set, to revisit if a consumer needs to prompt for a PIN.
Some libraries report a single opaque failure for verification; a backend on such a library may report `VerificationFailed` for a public key it cannot use, including an RSA modulus outside its range.
Conformance tests therefore expect `InvalidKey` for a malformed public key, and accept either the result expected for a key in the must-support set or `Unsupported` for a well-formed public key outside it; for a backend on such a library they also accept `VerificationFailed` in both cases.
For a public key in the must-support set with a wrong signature, they expect only `VerificationFailed`.

## 5. Encodings

There is one standard encoding per key type: the one the reference libraries import natively, among those that import that key type at all (handle-based APIs such as PKCS#11 import no software key natively).
Converting from any other representation (SPKI, JWK `n`/`e`, SSH mpints, PPK fields, raw EC scalars, RFC 5958 documents with version field 1 for RSA and EC) is format code and belongs above the contract.
In this document, "version 0" and "version 1" are the values of the PKCS#8 version field (RFC 5958 names them v1 and v2).

### 5.1 Public keys, including key-agreement peer keys

Public keys are the contents of the SPKI `subjectPublicKey` BIT STRING:

- RSA: PKCS#1 `RSAPublicKey` DER;
- EC P-256, P-384, P-521: the uncompressed SEC1 point (`0x04 || X || Y`);
- Ed25519 and X25519: the 32 raw bytes (RFC 8410).

`PublicKey<'a>(&'a [u8])` carries them for verification and encryption; key agreement takes the same bytes as `peer_public_key`.
The algorithm of the operation fixes the key type, curve and hash, so the SPKI wrapper carries no extra information, and some libraries have no SPKI parser.
Extracting the contents from an SPKI, and rejecting compressed EC points, is format code.
Backends reject them too, so that no backend accepts a second encoding even when its library would: an EC point whose length is not the curve's uncompressed length, or whose first byte is not `0x04`, is outside the valid domain (rule 4) and gets the error section 4 assigns to a malformed public key or peer value.
These are checks of an algorithm-fixed length and a constant byte, not parsing.

### 5.2 Private keys

| Key type | Encoding |
|---|---|
| RSA | PKCS#8 (RFC 5208 `PrivateKeyInfo`, version field 0), `rsaEncryption`, two-prime `RSAPrivateKey` |
| EC P-256, P-384, P-521 | PKCS#8 version field 0, `id-ecPublicKey` with the named curve OID in the `AlgorithmIdentifier`, RFC 5915 `ECPrivateKey` that should include the optional `publicKey` |
| Ed25519 | PKCS#8 (RFC 8410), version field 0 (RFC 5208 `PrivateKeyInfo`) or 1 (RFC 5958 `OneAsymmetricKey` v2, with the outer `publicKey`) |
| X25519 | the raw 32-byte RFC 7748 scalar |
| FFDH | the domain parameters `p`, `g` and optional `q` (section 6.11) and the private exponent, each as an unsigned big-endian integer |

`PrivateKeyMaterial<'a>` carries exactly one of `Pkcs8(&[u8])` (the PKCS#8 DER), `X25519(&[u8; 32])` and `Ffdh { parameters, private_value }`.

The PKCS#8 encodings carry no `attributes` field.
A document with attributes is outside the valid domain, and consumers drop them above the contract.
As an exception to rule 4, whether a backend rejects such a document with `InvalidKey` or loads it ignoring the attributes is implementation-defined, because some libraries skip attributes and rejecting them would require parsing in the adapter.

RSA and EC documents in RFC 5958 version 1 form are not accepted, because some libraries reject them; consumers convert them above the contract (set the version to 0 and drop the outer `publicKey`, keeping the public key inside `ECPrivateKey` for EC).
Ed25519 accepts both versions because generators differ in which they emit; a loader must accept version 1, and a loader that cannot compute the public key returns `Unsupported` for version 0 (below).
X25519 and FFDH private keys are not PKCS#8 because the reference libraries do not import them from PKCS#8.
Static FFDH keys are needed, not only ephemeral ones, because some protocols (DPAPI) derive the private exponent.

When the optional public key is absent (EC without `publicKey`, Ed25519 version 0), a backend that can compute it does so; a backend that cannot returns `Unsupported(Algorithm::PrivateKeyLoading(key_type))`.

When the public key is present, it must match the private key.
A mismatch is outside the valid domain and loading returns `InvalidKey`.
This prevents a backend from exporting a public key under which its signatures do not verify.
For Ed25519 the check also protects the private key: the signature equation hashes the public key, and signing with a mismatched public key can reveal the private key.
An EC key whose `ECPrivateKey` carries the optional `parameters` field must name the same curve as the outer `AlgorithmIdentifier`; a different curve is `InvalidKey`, so that every backend interprets the key the same way.
The reference software libraries perform these checks when they load PKCS#8.
A backend that cannot perform them natively, including by chaining public library functions (parsing with the library, deriving the public key with the library, comparing fixed-length bytes), does not advertise loading for that key type, rather than skipping a check.

X25519 follows RFC 7748 section 5: every 32-byte scalar and every 32-byte peer value is in the must-support set.
The scalar is clamped, the peer value's most significant bit is masked, and a non-canonical u-coordinate is processed as if reduced modulo p.
These are steps of the algorithm, performed by the library and never by the adapter, so static X25519 private keys accept any 32-byte scalar as stored.
A backend whose library requires the caller to clamp, mask or reduce does not advertise X25519.
The one rejected case is a peer value that yields an all-zero shared secret, which is `InvalidInput` (section 6.11).

### 5.3 Key agreement public values

Peer and ephemeral public keys use the section 5.1 encodings.
FFDH, which has no SPKI form here, uses the public value `y` as an unsigned big-endian integer; ephemeral FFDH public values are output left-padded to the byte length of `p`.

### 5.4 Signatures

- RSASSA-PKCS1-v1_5: the signature integer as a big-endian octet string exactly as long as the modulus.
- ECDSA, for both signing and verification: fixed-width `r || s` (IEEE P1363), each half left-padded to the field size: 64, 96 or 132 bytes for P-256, P-384, P-521.
  It is the only encoding every reference library produces natively; handle-based APIs (PKCS#11, Windows CNG) produce nothing else.
  The DER `Ecdsa-Sig-Value` used by X.509 and CMS is format code above the contract.
- Ed25519: 64 bytes (RFC 8032).

## 6. Capability traits

Each capability trait is object-safe and has three kinds of methods: an identity method (`algorithm()`, or `key_type()` for `PrivateKeyLoader`), `fips()` (section 6.15), and the operations; `Mac`, `Cipher`, `Aead` and `KeyWrap` also report their protections with `supports(protection)` (section 8).
`FfdhKeyAgreement` has no identity method: its algorithm is always `KeyAgreementAlgorithm::Ffdh`.
No capability trait method has a default implementation.

### 6.1 Hash (`Hash`, `HashContext`)

- `Hash::start() -> Result<Box<dyn HashContext>, Error>`.
- `HashContext::update(&mut self, data)`: any number of calls, including zero, with any slice length including empty.
- `HashContext::finish(self: Box<Self>) -> Result<OutputBytes, Error>`: the digest, `output_len()` bytes.

The interface is streaming only, because consumers hash unbounded inputs (a PKCS#12 MAC over the whole authenticated safe, Kerberos and GSS messages, CMS content) and some already hash incrementally.
A one-shot digest is a helper (section 10).

Algorithms: MD4 (RFC 1320), MD5 (RFC 1321), SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (FIPS 180-4), SHA3-384, SHA3-512 (FIPS 202).
Valid domain: total input up to 2^64 − 1 bits for SHA-1, SHA-224 and SHA-256 and 2^128 − 1 bits for SHA-384 and SHA-512 (FIPS 180-4), unlimited for SHA3; for MD4 and MD5, which encode the length modulo 2^64, the contract uses the same 2^64 − 1-bit limit.
Must support: total input up to 2^32 bytes; an entry whose library cannot hash that much must not be advertised.
Above 2^32 bytes and inside the valid domain, an entry may return `Unsupported` where its library's own limit is reached.
Errors: `ProviderFailure`, `Unsupported` as above, and `InvalidInput` beyond the algorithm's limit.

### 6.2 MAC (`Mac`, `MacContext`, `MacGeneration`, `MacVerification`)

- `Mac::start(key, protection) -> Result<Box<dyn MacContext>, Error>`: `key` of any length, including empty and longer than the hash block size, with RFC 2104 semantics; `Unsupported(Algorithm::Mac(algorithm))` when `supports(protection)` is false (section 8).
- `MacContext::update`: as for hashes.
- `MacContext::finish(self: Box<Self>) -> Result<MacOutput, Error>`: the full, untruncated tag in an opaque, zeroizing backend-side carrier.
- `MacGeneration::start(mac, key)` and `MacVerification::start(mac, key)`: call `mac.start(key, Protection::Apply)` and `mac.start(key, Protection::Process)` respectively.
  Both expose `update` and consuming `finish`, returning `MacTag` for generation and `MacVerifier` for verification.
- `MacVerifier::verify(expected, len) -> bool`: compares the first `len` bytes of the tag with `expected` in constant time (best effort: Rust gives no constant-time guarantee).
  It returns false unless `expected.len() == len` and `1 <= len <= tag_len`, where `tag_len` is the full tag length.
  `len` comes from the protocol definition (for example 12 bytes for Kerberos HMAC-SHA1-96, 8 for NTLM checksums), never from the received message, so that a peer cannot shorten the comparison.
- `MacTag::into_inner() -> Zeroizing<Vec<u8>>`: the full tag, to emit a tag or derive from it.

`MacTag` and `MacVerifier` are wiped on drop, their `Debug` shows only the length, and their `Clone` clones the zeroizing storage.
Neither implements `Deref`, `AsRef`, `Display` or comparison traits; `MacTag` only exposes bytes through `into_inner()`, while `MacVerifier` only verifies.
`MacOutput` has length-only `Debug`, no `Clone` and no public byte access.
Only `picky-crypto` constructs `MacTag`, `MacVerifier`, `MacGeneration` and `MacVerification`; they have no public constructor from bytes.
The wrapping types and the verifier's comparison are implemented by `picky-crypto`, not by backends, and are not contract operations, so the minimality exceptions do not apply.

Valid domain: any key, and data such that every hash invocation of RFC 2104 (including the inner hash over the key block followed by the data, and the hashing of an over-long key) stays within the underlying hash's valid domain (section 6.1).
Must support: keys of 0 to 1024 bytes, and data as for hashes; an update that takes the total beyond the valid domain returns `InvalidInput`.

Algorithms: HMAC (RFC 2104, FIPS 198-1) with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
Generation and verification are separate operations, chosen at `start`: a composite entry must choose the serving member before processing data (section 8.1), and a policy may refuse generation while allowing verification (section 8.2).
A tag sent to a peer (a Kerberos checksum, a JWS HS256 signature, an NTLM signature) or used as key material comes from `MacGeneration` and is read with `MacTag::into_inner()`; truncation is protocol code over those bytes.
A received tag is always checked with `MacVerifier::verify`, the one way to check a MAC, with the protocol's `len`.
A backend never constructs `MacTag` or `MacVerifier`, so a policy refuses generation by refusing `start(key, Protection::Apply)`.
The split governs which services a provider offers, which is what a policy approves; it is not a confidentiality boundary against the calling code, which holds the key.
Code that supplies its own `Mac` entry to `MacGeneration`, or probes `verify` with chosen prefixes, can obtain a verification tag's bytes, and such use is outside any approved service.
Entries are trusted to report and behave honestly, as for `fips()` and `key_size_bits()`: the contract does not defend against a dishonest entry.
Probing `verify` is open only to the calling code; a remote party cannot use it as an oracle, because `len` comes from the protocol definition.

Exception 2: HMAC is derivable from the hash interface (key padding, inner and outer hash), but it is an approved algorithm that must run as a whole inside a validated module.

HMAC-MD5 is not offered: it is derivable from `Hash(Md5)` and none of the exceptions applies, because MD5 is not approved and composing it costs nothing.
A protocol that needs HMAC-MD5 composes it from `Hash(Md5)` in its own code, so it is unavailable exactly when MD5 is.
The construction is MD5-only: a generic HMAC over any hash would be a second HMAC-SHA path outside the validated module.

### 6.3 Password-based KDF (`PasswordKdf`)

`derive(password, salt, iterations, output_len) -> Result<OutputBytes, Error>`: PBKDF2 (RFC 8018 section 5.2) with HMAC-SHA-x as PRF.

Valid domain: any password and salt, `iterations >= 1`, `1 <= output_len <= (2^32 − 1) × hLen` (RFC 8018 section 5.2, step 1).
Must support: password and salt of 0 to 1024 bytes, `iterations` 1 to 10 000 000, `output_len` 1 to 1024.
`iterations == 0`, `output_len == 0` or `output_len` above the RFC 8018 maximum: `InvalidInput`.

Exception 2: PBKDF2 is derivable from HMAC, but it is an approved KDF that must run as a whole inside a validated module.

### 6.4 Key-based KDF (`Kdf`)

`derive(secret, fixed_info, output_len) -> Result<OutputBytes, Error>`.

| Algorithms | Definition |
|---|---|
| `OneStepSha1`, `OneStepSha256`, `OneStepSha384`, `OneStepSha512` | NIST SP 800-56C rev. 2 section 4.1, option 1: `K(i) = H(counter_i || Z || OtherInfo)` with a 32-bit big-endian counter starting at 1; `secret` = Z, `fixed_info` = OtherInfo (opaque); output truncated to `output_len` |
| `CounterHmacSha1`, `CounterHmacSha256`, `CounterHmacSha384`, `CounterHmacSha512` | NIST SP 800-108 rev. 1 section 4.1, counter mode, PRF = HMAC-SHA-x: `K(i) = PRF(K_IN, [i]_32 || FixedInfo)` with a 32-bit big-endian counter starting at 1 placed before the fixed input; `secret` = K_IN, `fixed_info` = the complete fixed input data (the caller encodes label, separator, context and length in it); output truncated to `output_len` |

Valid domain: `secret` of at least 1 byte, any `fixed_info`, `output_len` from 1 to `(2^32 − 1) × hash length`.
Must support: `secret` 1 to 1024 bytes, `fixed_info` 0 to 1024 bytes, `output_len` 1 to 64.
Empty `secret`, `output_len == 0`, or `output_len` above the valid domain: `InvalidInput`.

The counter-mode KDF takes the complete fixed input because its layout belongs to the protocol (for example, the MS-GKDI layout `Label || 0x00 || Context || [L]_32` is DPAPI format code).
A library that only builds its own fixed-input layout from a label and a context cannot implement this operation and reports `Unsupported`.

Exception 2: both KDFs are derivable from the hash and MAC interfaces, but they are approved KDFs.
Composed above the contract, they would run outside the validated module and be invisible to policy and to availability checks.
Where a backend's library lacks them, a provider that builds them from another provider's entries supplies them, reporting `fips() == false` (section 11): the one-step KDF from `Hash` entries, and the counter-mode KDF from `Mac` entries, taking each PRF block from a `MacGeneration` with `MacTag::into_inner()` and requiring `Protection::Apply`.
A policy judges `Kdf` entries by the rules for KDFs, independently of the `Mac` entries they build on.

### 6.5 Unauthenticated block cipher modes (`Cipher`)

`encrypt(key, iv, plaintext) -> Result<OutputBytes, Error>` and `decrypt(key, iv, ciphertext) -> Result<OutputBytes, Error>`: one-shot CBC (NIST SP 800-38A) without padding; the output has the same length as the input.
The entry reports its protections through `supports()` (section 8).

| Algorithm | Key | IV | Data |
|---|---|---|---|
| `Aes128Cbc`, `Aes192Cbc`, `Aes256Cbc` | 16, 24, 32 bytes respectively | 16 bytes | multiple of 16 bytes, may be empty |
| `TdesEde3Cbc` | 24 bytes (three DES keys, parity bits ignored) | 8 bytes | multiple of 8 bytes |
| `Rc2Cbc` | 1 to 128 bytes, must support 5 to 16 | 8 bytes | multiple of 8 bytes |

RC2's effective key bits (RFC 2268 `T1`) always equal 8 × the key length; every backend sets that parameter explicitly, never the library's default.
Wrong key length: `InvalidKey`; wrong IV or data length: `InvalidInput`.
Every 24-byte 3DES key is in the must-support set, except two cases where, as an exception to rule 4, rejecting the key with `InvalidKey` is implementation-defined, because some libraries refuse them: component keys that are not pairwise distinct (keying option 1 of NIST SP 800-67 requires three distinct keys), and component keys that are among the DES weak or semi-weak keys listed in NIST SP 800-67.
Must support: data up to 2^31 − 1 bytes.

Padding is above the contract: PKCS#7 padding (PKCS#12 PBES1 and PBES2) and Kerberos ciphertext stealing are consumer code; CBC decryption of padded data returns the padded plaintext.

These modes are not derivable from other operations: no other operation exposes the AES, 3DES or RC2 block function.
Conversely, a single-block CBC call with a zero IV is a raw block operation; Kerberos ciphertext stealing and RFC 3961 key derivation use exactly that, and it is why the AES modes below carry exception notes.

### 6.6 Stream cipher (`StreamCipher`, `StreamCipherContext`)

- `StreamCipher::start(key) -> Result<Box<dyn StreamCipherContext>, Error>`: RC4.
- `StreamCipherContext::apply(&mut self, data) -> Result<OutputBytes, Error>`: XORs `data` with the next `data.len()` keystream bytes; the state carries over to the next call.

Valid domain: keys of 1 to 256 bytes, any data.
Must support: keys of 5 to 256 bytes.

The context is stateful because NTLM seals successive messages with one continuing RC4 keystream per direction.
There is no state cloning: computing an NTLM MIC without advancing the state is done by restarting from the key and discarding the bytes already processed, so there is one way to reach a keystream position.

### 6.7 AEAD (`Aead`)

- `seal(key, aad, plaintext) -> Result<Sealed, Error>`: returns a `Sealed` with the generated `nonce` and `ciphertext_and_tag` (`ciphertext || tag`), named so that the two buffers cannot be swapped by position.
- `open(key, nonce, aad, ciphertext_and_tag) -> Result<OutputBytes, Error>`: returns the plaintext, or `VerificationFailed` without releasing any plaintext.

The entry reports its protections through `supports()` (section 8).

AES-GCM (NIST SP 800-38D): the key is exactly 16, 24 or 32 bytes for `Aes128Gcm`, `Aes192Gcm` and `Aes256Gcm` respectively (`InvalidKey` otherwise); the generated seal nonce and the open nonce are exactly 12 bytes; the tag is exactly 16 bytes.
Must support: plaintext up to 2^31 − 17 bytes, so that `ciphertext || tag` fits in 2^31 − 1 bytes, within the 32-bit `isize::MAX` allocation-size limit, and AAD up to 2^31 − 1 bytes (some handle-based APIs take the AAD length as a 32-bit integer).
`open` input shorter than 16 bytes: `InvalidInput`.
A detached tag (as in JOSE) is split and joined above the contract.

The backend's library generates the seal nonce from its own secure random generator, never from caller input or a `SecureRandom` entry passed in (rule 5).
Chaining the library's own nonce generation or RNG with its seal is argument mapping.
A backend whose library is a FIPS module seals only through the module's internal IV generation (NIST SP 800-38D section 8.2.2).
An IV passed into the module from outside, even one the module generated, is an external IV.
The contract requires internal generation because whether a module approves an external IV depends on its validated configuration (SP 800-38D section 8.2.2); the AWS-LC FIPS module, for example, approves AES-GCM encryption only with an internally generated IV.
A backend whose library cannot seal a key size through the required nonce generation reports `supports(Protection::Apply) == false` for that algorithm and keeps open.
For example, aws-lc-rs's `RandomizedNonceKey` has no AES-192-GCM, so that entry reports only `Protection::Process` in every build of the adapter.

With random 96-bit nonces, a key must be used for at most 2^32 seal calls (NIST SP 800-38D section 8.3).
The backend keeps no per-key state and cannot count calls, so the caller enforces this limit.
Generating the nonce removes caller-controlled nonce reuse, GCM's main failure mode.
A protocol needing a caller-chosen seal nonce (for example `aes256-gcm@openssh.com`) requires a separate, explicitly non-approved capability through a contract change; adding a capability is non-breaking (section 3.1).

Exception 2 and 3: GCM is derivable from single-block AES-CBC calls plus GHASH arithmetic above the contract.
It is an approved mode that must run as a whole inside a validated module, including internal IV generation under exception 2, and the backend provides constant-time GHASH and releases no plaintext before the tag is checked.

### 6.8 Key wrap (`KeyWrap`)

- `wrap(kek, key_data) -> Result<OutputBytes, Error>`: RFC 3394 with the default IV `A6A6A6A6A6A6A6A6`; the output is 8 bytes longer.
- `unwrap(kek, wrapped) -> Result<OutputBytes, Error>`: `VerificationFailed` if the integrity check fails.

The entry reports its protections through `supports()` (section 8).

KEK: exactly 16, 24 or 32 bytes for `Aes128Kw`, `Aes192Kw` and `Aes256Kw` respectively (`InvalidKey` otherwise); the wrapped `key_data` length is independent of the KEK size.
Valid domain and must-support set (they coincide): `key_data` of 16, 24 or 32 bytes, so `wrapped` of 24, 32 or 40 bytes.
`wrap` with another `key_data` length, or `unwrap` with another `wrapped` length: `InvalidInput`, checked before any cryptographic processing.
`unwrap` returns 16, 24 or 32 bytes; RFC 3394 values of other lengths are outside the contract even when their integrity check would pass.
Consumers wrap only AES content-encryption keys (JOSE, DPAPI), and some handle-based APIs wrap only key objects that are valid AES keys.

Exception 2 and 3: AES-KW is derivable from single-block AES-CBC calls (the RFC 3394 loops).
It is an approved mode (NIST SP 800-38F) that must run inside a validated module, and the integrity check stays inside the backend.

### 6.9 Signature verification (`SignatureVerifier`)

`verify(public_key, message, signature) -> Result<(), Error>`.
The message is passed, never a digest, because some libraries cannot verify a precomputed digest.

| Algorithm | Definition | Must support |
|---|---|---|
| `RsaPkcs1v15Md5`, `...Sha1`, `...Sha224`, `...Sha256`, `...Sha384`, `...Sha512`, `...Sha3_384`, `...Sha3_512` | RFC 8017 RSASSA-PKCS1-v1_5 with the named hash and its DigestInfo | modulus 2048 to 4096 bits, public exponent 65537 |
| `EcdsaP256Sha256`, `EcdsaP384Sha384`, `EcdsaP521Sha512` | FIPS 186-5 ECDSA with the named curve and hash, fixed `r || s` | valid public points of the curve |
| `Ed25519` | RFC 8032 pure Ed25519 | valid public keys |

Valid domain: public key bytes in the encoding of section 5.1 and any signature bytes; a key that does not decode as the algorithm's key type in that encoding, including a compressed EC point, is `InvalidKey` (or `VerificationFailed` on a library with a single opaque failure, section 4).

Acceptance profile:

- RSA: signatures are generated with the DigestInfo of RFC 8017 appendix A.2.4 with NULL parameters, for every hash; for SHA3-384 and SHA3-512 the hash OIDs are `2.16.840.1.101.3.4.2.9` and `2.16.840.1.101.3.4.2.10`.
  Whether a verifier also accepts a DigestInfo with absent parameters is not specified.
  RFC 9688 requires absent parameters for `id-sha3-*` AlgorithmIdentifiers in CMS fields; that is format code above the contract and does not concern the EMSA-PKCS1-v1_5 DigestInfo.
- ECDSA: every signature valid under FIPS 186-5 verifies, whether `s` is low or high: there is no normalization, which some protocols (for example Bitcoin) add on top of ECDSA.
  `r` or `s` equal to zero or not less than the group order is `VerificationFailed`.
- Ed25519: every signature valid under RFC 8032 section 5.1.7 with canonical `S < L` and canonical encodings of `A` and `R` verifies.
  Malformed inputs are errors: `S >= L`, an `R` that fails RFC 8032 section 5.1.3 decoding, or a wrong signature length is `VerificationFailed`; an `A` that fails that decoding is `InvalidKey` or `VerificationFailed` (section 4).
  Verification with a validly encoded small-order `A` or `R` is implementation-defined (cofactored or cofactorless equation); backends may disagree on it, so differential tests exclude these inputs and conformance tests check the allowed outcomes listed in section 12.

Result: `Ok(())`; `VerificationFailed` for a signature that does not verify, including a wrong length; `InvalidKey` for a key that is not a valid key of the expected type, with the opaque-failure tolerance of section 4.

### 6.10 Asymmetric encryption (`AsymmetricEncryptor`)

`encrypt(public_key, plaintext) -> Result<OutputBytes, Error>`.

| Algorithm | Definition |
|---|---|
| `RsaPkcs1v15` | RFC 8017 RSAES-PKCS1-v1_5 |
| `RsaOaepSha1` | RFC 8017 RSAES-OAEP, hash SHA-1, MGF1-SHA-1, empty label |
| `RsaOaepSha256` | RFC 8017 RSAES-OAEP, hash SHA-256, MGF1-SHA-256, empty label |

Valid domain: any public key bytes (`InvalidKey` if they do not decode as an RSA key), and plaintext up to the algorithm's limit for the modulus (`k − 11` bytes for PKCS#1 v1.5, `k − 2·hLen − 2` for OAEP).
Must support: modulus 2048 to 4096 bits with public exponent 65537.
Plaintext too long for the modulus: `InvalidInput`.
Decryption is `PrivateKey::decrypt` (section 7).

### 6.11 Key agreement (`KeyAgreement`, `FfdhKeyAgreement`, `EphemeralSecret`)

Ephemeral agreement:

- `KeyAgreement::generate_ephemeral() -> Result<Box<dyn EphemeralSecret>, Error>` for `EcdhP256`, `EcdhP384`, `EcdhP521`, `X25519`;
- `FfdhKeyAgreement::generate_ephemeral(parameters) -> Result<Box<dyn EphemeralSecret>, Error>` for `Ffdh` (its algorithm is always `KeyAgreementAlgorithm::Ffdh`);
- `EphemeralSecret::public_key() -> Result<OutputBytes, Error>`: section 5.3 encoding;
- `EphemeralSecret::agree(self: Box<Self>, peer_public_key) -> Result<OutputBytes, Error>`: single use.

Static agreement is `PrivateKey::agree` (section 7) on a key loaded by `PrivateKeyLoader`.

Shared secret encoding:

- ECDH (SEC1 section 3.3.1): the x-coordinate as a big-endian octet string of the field size (32, 48, 66 bytes).
- X25519: the 32-byte output of RFC 7748 `X25519(k, u)` as an octet string, unmodified.
  An all-zero output is `InvalidInput` (RFC 7748 section 6.1); every other 32-byte peer value is processed as section 5.2 states, including values on the twist and non-canonical values.
- FFDH: `y_peer^x mod p` as an unsigned big-endian integer left-padded to the byte length of `p` (the PKINIT `DHSharedSecret` form, RFC 4556 section 3.2.3.1).

Reversing a fixed-width secret is argument mapping: a backend whose library returns the secret little-endian reverses it.

Invalid peer value (for ECDH: not on the curve, wrong length or the identity; for X25519: a length other than 32 bytes or an all-zero shared secret; for FFDH: a value outside the range below): `InvalidInput`.

#### FFDH parameters and checks

FFDH domain parameters, `FfdhParameters { p, g, q }` (built with `FfdhParameters::new`), private values and public values are unsigned big-endian integers.
Leading zero bytes are accepted and ignored, but no encoding may be longer than the byte length of `p` plus one byte, so that its length is bounded by the group rather than by the input; an empty or longer encoding is invalid.
"The byte length of `p`" means `ceil(bit_length(p) / 8)` after leading zeros are ignored; it fixes the width of ephemeral public values, shared secrets and `ffdh_public_value`.
The parameters are arbitrary rather than named groups, because consumers take them from the protocol: PKINIT and PKU2U requests carry X9.42 domain parameters, and DPAPI takes the group from the key distribution service.

Valid domain (checks every backend performs):

- `p`: odd, at least 1024 bits;
- `g`: `1 < g < p − 1`;
- `q`, when given: `5 <= q < p`;
- static private value `x`: `1 <= x <= q − 1` when `q` is given, otherwise `1 <= x <= q' − 1` with `q' = (p − 1) / 2`; it is not reduced;
- peer public value `y_peer`: `1 < y_peer < p − 1`, and `y_peer^q mod p == 1` when `q` is given.

Parameters or private values outside the valid domain return `InvalidKey` when loading (`PrivateKeyLoader(Ffdh)`) and `InvalidInput` when generating an ephemeral secret; a peer value outside it returns `InvalidInput`.
Checks are never skipped: a library that cannot perform these checks for every input in the must-support set cannot back an advertised FFDH entry.
Secret values (the private exponent and the shared secret) are handled without variable-time operations, including in range checks, conversions and serialization.
Trusted, unchecked properties: `p` and `q` are prime, and `g` generates a subgroup of large order (of order `q` when `q` is given).
When `q` is absent, the backend cannot check that `y_peer` lies in `g`'s subgroup, and its range check excludes only the trivial elements `1` and `p − 1`.
If `p − 1` has other small factors, a peer can then send a value of small order and learn information about a reused static exponent.
Supplying `q` (or using a safe prime, whose only small subgroups have order 1 or 2) is therefore the protocol's responsibility whenever a static exponent is used with untrusted peers.
DPAPI, for example, receives its group (RFC 5114 section 2.3) without `q` from the key distribution service.
Trusting the group source does not make peer values trustworthy, so such a protocol accepts that risk for its static exponents.
Checking the trusted properties is the protocol's responsibility; with parameters that violate them the outputs are unspecified, but there is no panic.
Must support: `p` of 1024, 2048, 3072 and 4096 bits; other sizes may be `Unsupported` (rule 4).

An ephemeral private exponent is generated as in NIST SP 800-56A rev. 3 section 5.6.1.1.4 (key-pair generation by testing candidates) with `N = len(q)`, the bit length of `q` after leading zeros are ignored: `x` is uniform in `[1, q − 1]`, drawn from the backend's own secure random generator.
When `q` is absent, `q' = (p − 1) / 2` takes its place (with `N = len(q')`), as for the safe-prime groups of section 5.6.1.1.1 (the RFC 2409 and RFC 3526 groups used with PKINIT are safe primes).
For a group without `q` whose prime is not safe, this range is the contract's own choice rather than the cited procedure, and it relies on the trusted property that `g` generates a subgroup of large order.
This distribution is checked by review; conformance tests check the range of the public value and the round trip.
FFDH with arbitrary groups is not FIPS-approved.

Exception 3 for ephemeral agreement: it is derivable by producing a private key outside the backend (key generation for EC, the `random_x25519_private_key` helper for X25519, exponent sampling for FFDH), loading it, obtaining the public value and calling `agree()`.
That route serializes the private key, whereas the ephemeral route keeps it inside the backend; some libraries offer only the ephemeral route.
Static agreement is needed for decryption (the JOSE ECDH-ES recipient, DPAPI) and is not derivable from the ephemeral route.

### 6.12 Private key loading (`PrivateKeyLoader`)

`load(private_key: PrivateKeyMaterial) -> Result<Box<dyn PrivateKey>, Error>`: one loader per `KeyType`, section 5.2 encoding.
The loader checks that the material matches its key type (`InvalidKey` otherwise), and that an embedded public key matches the private key (section 5.2).

Loading does not select a signature algorithm.
A backend whose library binds the algorithm when it creates a key object (some bind curve, hash and signature format for ECDSA) keeps the encoded key and creates the library object per algorithm; each EC key type has exactly one signature algorithm in the contract, so this is never ambiguous.

### 6.13 Key generation (`KeyGenerator`)

`generate() -> Result<OutputBytes, Error>`: a fresh key in the section 5.2 PKCS#8 encoding.
RSA uses public exponent 65537 and the modulus size in the algorithm name, with two primes of half the modulus size.
EC output includes the public key in `ECPrivateKey`.
Ed25519 output is version 1 (RFC 5958 `OneAsymmetricKey` v2) with the outer `publicKey`, so that every loader can load a generated key, including loaders that cannot compute the public key from the seed.
The three RSA sizes are those every generating library supports.

There is no X25519 key generation: an X25519 private key is 32 bytes from `SecureRandom` with RFC 7748 section 5 clamping applied.
Clamping clears bits 0, 1, 2 of the first byte and bit 7 of the last byte, and sets bit 6 of the last byte.
The helper `random_x25519_private_key` (section 10) performs these steps.
Clamping does not change the key, because X25519 clamps when decoding.
There is no FFDH key generation: FFDH keys are ephemeral (section 6.11) or derived by the protocol (DPAPI).

Key generation is optional like every capability: a provider whose keys cannot be exported (hardware) does not advertise it.
Hardware key generation, which yields a handle rather than an encoding, is not part of the contract.

Exception 2 and 3 for EC and Ed25519: generation is derivable as random bytes, format code and loading (when the loader computes the public key).
Key generation must run inside a validated module (FIPS 186-5, SP 800-133), and the secret stays inside the backend until it is deliberately exported.
RSA generation is not derivable, because the contract offers no primality testing.

### 6.14 Random (`SecureRandom`)

`fill(dest) -> Result<(), Error>`: fills `dest` from a cryptographically secure generator (an OS CSPRNG or an SP 800-90A DRBG); `ProviderFailure` if it fails.
A provider has at most one `SecureRandom` entry (`RandomAlgorithm::SecureRandom`).
Integers in a range, protocol nonces other than AEAD seal nonces (section 6.7), confounders and salts are built on top by consumers.

### 6.15 `fips()`

Every entry reports `fips()`: true only if its operations run inside a FIPS 140 module, built as that module and running in FIPS mode.
For aws-lc-rs this is the runtime answer of `aws_lc_rs::try_fips_mode()` in its FIPS build, never a crate feature flag.
`false` means "not positively established": RustCrypto and ring entries always return false, and so do backends that cannot establish the module's status at runtime.
`fips()` reports how the module was built and is running, not certification: whether a deployed binary matches a CMVP certificate and its operating environment is established outside the program.
It is an input to policy, never a capability query.

## 7. Private keys (`PrivateKey`)

`PrivateKey` is the trait object for any private key: keys loaded by a provider, and hardware or external keys (PKCS#11 smartcards, CNG/NCrypt keys, TPM) that implement it directly without a provider.

| Method | Default | Semantics |
|---|---|---|
| `key_type()` | required | The key's type. |
| `key_size_bits()` | required | The key size in bits, as defined below; cheap, infallible and never accesses a device (rule 7). |
| `supports(operation)` | required | Whether the key implements `operation` (`KeyOperation::Sign(alg)`, `Decrypt(alg)`, `Agree(alg)`, `PublicKey`) over that operation's must-support set. Never performs the operation (no PIN prompt, no device access beyond cached capabilities). |
| `fips()` | required | As in section 6.15, for this key's operations. A key loaded by a provider entry reports that entry's `fips()`. A hardware key reports true only if every computation of its operations runs in a module whose status is established for the deployment (the token, by configuration or attestation, and, when it hashes in software, the `Hash` entry it uses), false otherwise. |
| `sign(algorithm, message)` | `Unsupported` | Section 6.9 algorithms; the message is passed and the key hashes it; output encoding per section 5.4. |
| `decrypt(algorithm, ciphertext)` | `Unsupported` | Section 6.10 algorithms. A modulus-length ciphertext whose integer value is not less than the modulus, and any padding or OAEP failure, is `VerificationFailed` (RFC 8017 sections 7.1.2 and 7.2.2 treat both as a decryption error; one error for all, so the error does not reveal which check failed). Ciphertext length other than the modulus length: `InvalidInput`. |
| `agree(algorithm, peer_public_key)` | `Unsupported` | Static agreement, encodings per section 6.11. |
| `public_key()` | `Unsupported(PublicKeyExport(key_type))` | Optional. The `subjectPublicKey` contents of the matching public key (section 5.1 encoding; 32 bytes for X25519). Not offered for FFDH keys, whose public value is `agree(Ffdh, g)` (the helper `ffdh_public_value`, section 10). |

When `supports` returns false, the operation always returns `Unsupported`: algorithms that do not match the key's type and algorithms its implementation does not offer.
When it returns true, the operation is available over its must-support set, subject to policy narrowing (section 8.2).
Inputs inside the valid domain but outside the must-support set may still return `Unsupported` (rule 4).
Cryptographically invalid inputs still fail with the specified error (for example `VerificationFailed` for a modulus-length ciphertext with invalid padding).
`supports` is how private-key availability is queried per algorithm: provider entries advertise verification, encryption, ephemeral agreement and loading, and a key advertises its own signing, decryption, static agreement and public-key export.
Conformance tests check every `KeyOperation` on unwrapped keys.
When `supports() == false`, the operation returns `Unsupported`.
When `supports() == true`, valid known-answer and round-trip cases succeed, no must-support input returns `Unsupported`, and invalid inputs return the specified error.
RSA keys with inconsistent components are checked as section 12 states.

`key_size_bits()` reports:

- RSA: the exact bit length of the modulus `n`, never a byte length times 8; a backend whose library returns only the modulus bytes measures their bit length, which is argument mapping (`INTENT.md`, "Design principle");
- EC P-256, P-384, P-521: the bit length of the curve's field prime, respectively 256, 384, 521;
- Ed25519 and X25519: 255, the bit length of the field prime 2^255 − 19;
- FFDH: the bit length of `p` after leading zeros are ignored (section 6.11).

A key type without a meaningful size returns 0, which every minimum-size check refuses.
There is no such type in the current `KeyType` set, but the enum is `#[non_exhaustive]`.
A hardware key reads its size when constructed and caches it like its capabilities.
This metadata lets policy restrict provider-loaded and hardware keys by size without exporting them.

Valid domain and must-support set:

- `sign` and `decrypt` with RSA: must support 2048, 3072 and 4096-bit two-prime keys with equal-size primes and public exponent 65537; other valid RSA keys may be refused at loading with `Unsupported`.
- `sign`: any message; `decrypt`: ciphertext exactly as long as the modulus.
- `agree`: section 6.11.

RSASSA-PKCS1-v1_5 signatures always encode NULL DigestInfo parameters (section 6.9).

RSA private-key results are checked: every signature or plaintext is the correct result under the key's public components (`n`, `e`), or the operation fails.
A backend never outputs a signature or plaintext computed from inconsistent key components, because a single faulty CRT signature reveals a prime factor of `n`.
Handling an RSA private key with inconsistent components (wrong `dP`, `dQ`, `qInv` or `d`) is implementation-defined.
It may be rejected at loading with `InvalidKey`, rejected at the first private-key operation with `InvalidKey`, or used with components the library recomputes from `n`, `e`, `d`, `p` and `q`.
Every one of these outcomes satisfies the property above.
This is an exception to rule 4, which would otherwise require rejection at loading.
An inconsistency detected during `sign` or `decrypt` returns `InvalidKey`, never the padding error `VerificationFailed`.
Conformance tests check these keys only as section 12 states.

Derivability:

- RSA signing and decryption are not derivable: the contract offers no raw RSA operation, because a raw primitive would let callers build arbitrary padding schemes, including insecure ones.
- `public_key()` for X25519 is derivable as `agree(X25519, base point 9)`.
  Exception 3: a key may allow exporting its public key without allowing agreement (key-use restriction).
  For FFDH the same derivation has no such restriction, so FFDH keys do not offer `public_key()`.
  For RSA, EC and Ed25519 it is not derivable.
- `public_key()` is optional because callers that hold a certificate do not need it, and handle-based keys cannot always return the encoding natively.

### 7.1 Hardware keys

A hardware key implements `PrivateKey` directly.
A PKCS#11 smartcard key implements `sign` with the token's hash-and-sign mechanism on the message (`CKM_SHA1_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_ECDSA_SHA256`, ...).
A token that offers `CKM_ECDSA` together with token-side hashing can hash on the token (`C_Digest`, then `C_Sign` on the digest).

A token that offers only `CKM_RSA_PKCS`, or `CKM_ECDSA` without token-side hashing, is handled inside the hardware key implementation: it hashes the message and, for RSA, adds the algorithm-constant DigestInfo prefix, then calls the token.
This is acceptable inside a hardware key implementation because the contract passes the message, so hashing is the key's implementation detail.
The hash comes from the contract, never from a crypto library: the key implementation is constructed with a `CryptoProvider` (normally the installed default) and uses its `Hash` entry, so policy applied to that provider governs it.
If that provider lacks the hash, `supports(Sign(alg))` is false and `sign` returns `Unsupported`.
A CNG/NCrypt key hashes and calls `NCryptSignHash` in the same way.

Restricting a hardware key under a policy (section 8.2) filters its operations and key size; it does not change the provider the key was constructed with, so a FIPS binary constructs hardware keys with its FIPS provider.
A binary using hardware keys composes its provider with a software fallback for the operations the token does not offer (for example verification); under FIPS, that fallback must itself be a FIPS provider behind the FIPS policy, because verification is a cryptographic service like any other.

## 8. Provider value

`CryptoProvider` is an immutable set of `Entry` values with at most one entry per `Algorithm`.
`Entry` is a `#[non_exhaustive]` enum with one variant per capability trait, each holding an `Arc<dyn Trait>`.
Entries are `Arc`s rather than `&'static` references, so that a provider can be composed at runtime from entries of other providers (fallback, policy, providers built from another provider's entries) without leaking memory.
Storage is private.

- `CryptoProvider::builder() -> ProviderBuilder`: the only way to start a provider.
- `ProviderBuilder::with(entry) -> ProviderBuilder`: the only way to add an entry.
- `ProviderBuilder::build() -> Result<CryptoProvider, BuildError>`: fails with `Duplicate(algorithm)` if two entries report the same algorithm, and with `Mismatched(algorithm)` if an entry reports an algorithm that its `Entry` variant cannot implement.
  Each `Entry` variant's trait returns its own per-category enum, so only one mismatch is possible: `KeyAgreement` and `FfdhKeyAgreement` share `KeyAgreementAlgorithm`, and a `KeyAgreement` entry reporting `Ffdh` is rejected.
  Without that check, `get` would report FFDH as available while `ffdh_key_agreement` returned `Unsupported`.
  Every other variant has its own algorithm enum (or `KeyType` for `PrivateKeyLoader`), and `Algorithm::PublicKeyExport` is never produced by an entry, so no other overlap exists.
- `CryptoProvider::get(algorithm) -> Option<&Entry>`: lookup by algorithm.
- `CryptoProvider::fips()` and `CryptoProvider::with_fallback(fallback)`: section 8.1.
- `CryptoProvider::entries()`: iteration in unspecified order.
  It is not derivable from `get`, because consumers cannot enumerate a `#[non_exhaustive]` algorithm set; policy and composition need it.

`get(algorithm).is_some()` means that the entry exists and performs at least one operation, not necessarily every operation of its trait.
For entries other than `Mac`, `Cipher`, `Aead` and `KeyWrap`, including loading, presence also means that every operation of the trait is advertised (rule 3).
A provider never consults another provider implicitly.

`Mac`, `Cipher`, `Aead` and `KeyWrap` require `supports(protection: Protection) -> bool`, with no default implementation and the metadata guarantees of rule 7.
`Protection` follows NIST SP 800-131A Rev. 2 section 1.2.3: "applying cryptographic protection" versus "processing already protected information".

| Capability | `Apply` | `Process` |
|---|---|---|
| `Mac` | tag generation | tag verification |
| `Cipher` | `encrypt` | `decrypt` |
| `Aead` | `seal` | `open` |
| `KeyWrap` | `wrap` | `unwrap` |

Signatures already separate the two: signing is a private-key operation (section 7), and verification is a provider entry.
Hashes, KDFs, random generation and key agreement have no protection.
Unlike `KeyOperation`, which includes an algorithm because a private key serves several algorithms, `Protection` names only the protection because an entry has one algorithm.
When `supports(protection)` is false, that operation (`start(key, protection)` for `Mac`) returns `Unsupported(algorithm)` for every input.
When it is true, rule 3 applies to that operation.
A directional entry supports at least one protection; an entry that supports neither is never part of a provider.

Provider-level availability is checked with `helpers::missing(provider, required: &[Requirement]) -> Vec<Requirement>` (section 10), which reports every unmet requirement:

- `Requirement::Algorithm(alg)` requires an entry that performs every operation of its trait, including both protections for `Mac`, `Cipher`, `Aead` and `KeyWrap`;
- `Requirement::Mac(alg, protection)`, `Requirement::Cipher(alg, protection)`, `Requirement::Aead(alg, protection)` and `Requirement::KeyWrap(alg, protection)` require an entry that supports the named protection.

`Requirement::from(alg)` is `Requirement::Algorithm(alg)`, so naming only an algorithm never treats a one-protection entry as a full one.
Input narrowing is visible only as `Unsupported` at call time (rule 4), not through availability queries.
Private-key availability remains `PrivateKey::supports` (section 7).

### 8.1 Composition

Composition is explicit: a binary composes providers, or a dedicated bundle crate fixes a composition (section 11); libraries never compose.
`CryptoProvider::with_fallback(&self, fallback)` keeps the entries of `self` and adds what `fallback` advertises and `self` does not.
Composition follows the granularity of advertisement: per algorithm, and per protection for `Mac`, `Cipher`, `Aead` and `KeyWrap`; never per input.
For an algorithm whose `self` entry does not support a protection that the `fallback` entry supports, the result holds one composite entry with the same algorithm: each protection is served by `self` when `self` supports it, and by `fallback` otherwise.
Its `supports(protection)` is true when either member's entry supports that protection.
Its `fips()` is true only if every member entry that serves one of its protections reports `fips()`.
For `Mac`, the composite starts each context on the member that serves the requested protection, so the member that computes the tag is the one whose approval counts.
A primary entry still shadows the fallback for every input of an operation it advertises, including inputs outside the must-support set it refuses (for example an aws-lc-rs loader refusing 1024-bit RSA keys, or a loader unable to compute a missing EC public key) and inputs refused under section 8.2.
Those calls return `Unsupported`, with no fallback.
Binaries choose the order.

`CryptoProvider::fips()` is true only if the provider has at least one entry, every entry reports `fips()`, and every provider it was composed from reported `fips()`.
A provider built with the builder computes it from its entries.
`with_fallback` returns `self.fips() && fallback.fips()`.
A composition with any non-FIPS member therefore reports false even when every entry of that member is shadowed, and nesting preserves it.

Exception: composition is not derivable from `entries()` and the builder, because a provider rebuilt from the retained entries would lose the status of shadowed members; keeping that status is what lets the FIPS policy reject a non-FIPS composition (section 8.2) instead of silently accepting it.

### 8.2 Policy

A policy is a function from provider to provider.

A policy may narrow the inputs an entry accepts below its must-support set.
A narrowed entry returns `Unsupported(algorithm)` for refused inputs: the input is valid for the algorithm but not permitted here, consistent with rule 4.
Conformance tests run against unwrapped providers; policy tests cover the narrowing.
Every threshold a policy applies cites its source (an SP 800-131A table, a module security policy) and its version.

A policy restricts operations through the availability queries:

- it wraps `Mac`, `Cipher`, `Aead` and `KeyWrap` entries so refused protections report `supports(protection) == false` and follow section 8's refusal behavior, for example keeping 3DES decryption and refusing encryption under NIST SP 800-131A Rev. 2;
  MAC policy can likewise restrict use, for example, allowing HMAC-SHA-1 verification and refusing generation (NIST SP 800-131A Rev. 3 draft, section 13, Table 14).
- it drops an entry if neither protection remains;
- it restricts keys through `PrivateKey::supports` (section 7);
- it restricts every other capability by dropping its entry or narrowing its inputs.

A policy may narrow signature verification by public-key size.
For RSA it uses the modulus bit length read from the `RSAPublicKey` bytes passed to the verifier; refused sizes return `Unsupported(algorithm)`.
Reading the size is format code in the policy, not in the contract.

The FIPS policy:

- rejects any provider whose `fips()` is false, instead of silently dropping entries, so that a non-FIPS fallback composition cannot pass for FIPS; the error names the non-FIPS entries it can see, and may name none when the only non-FIPS member was entirely shadowed by the fallback composition (only its status is kept);
- then, in a provider that reports `fips()`, keeps entries approved for at least one operation, narrowed to the approved protections and inputs (filtering unapproved algorithms is not the same as accepting non-FIPS entries);
- wraps each kept `PrivateKeyLoader` so that the keys it returns report `supports() == false` and return `Unsupported` for operations or key sizes the policy does not allow, using `key_size_bits()` (for example RSA signature generation below 2048 bits, disallowed by NIST SP 800-131A rev. 2, section 3);
- provides a key-restriction function for hardware keys, which do not come from a provider: it applies the same operation and key-size filters and rejects keys whose `fips()` is false.

The policy, not the backend, decides which algorithms are approved.
It lives outside `picky-crypto`, because its approved-algorithm table changes with NIST transitions (for example the end of SHA-1 signature generation) while the contract must stay stable.

## 9. Process-wide default

| Function | Semantics |
|---|---|
| `install_default(provider) -> Result<(), CryptoProvider>` | Installs the default. If a default is already installed, by any path, returns `Err(provider)` and changes nothing. Called once by the binary, before the first cryptographic operation. |
| `get_default() -> Option<&'static CryptoProvider>` | Returns the installed default, or `None`. Neither panics nor installs. Code that must not panic (FFI boundaries, libraries preferring an error) checks with it and returns an error. |
| `get_or_install_default(make: fn() -> CryptoProvider) -> &'static CryptoProvider` | Returns the installed default; if none is installed, calls `make` once, installs its result and returns it. Concurrent callers observe exactly one installed provider, and `make` runs at most once. |

`get_default` is not derivable from the other two: `install_default` consumes a provider and `get_or_install_default` installs one.
The panicking accessor `helpers::default_provider()` (section 10) is `get_default` followed by a panic with a message naming `picky_crypto::install_default` and the crates that provide a provider.
Explicit and lazy installation are distinct operations: one takes an owned provider and hands it back on conflict, the other takes a function that must not run when a provider is already installed.

`get_or_install_default` exists for the `rustcrypto` convenience feature of a consuming library, the single place where that library may name a backend.
The feature installs the provider of the RustCrypto bundle crate (section 11), whose composition is fixed, so every library that uses the same version of the bundle installs the same provider value whichever installs first:

```rust
// The only backend-specific cfg site in a consuming library.
fn provider() -> &'static picky_crypto::CryptoProvider {
    #[cfg(feature = "rustcrypto")]
    {
        picky_crypto::get_or_install_default(picky_crypto_rustcrypto_bundle::provider)
    }
    #[cfg(not(feature = "rustcrypto"))]
    {
        picky_crypto::helpers::default_provider()
    }
}
```

A binary that installs its own provider before first use is unaffected by the convenience feature.
A binary that installs after a library already installed the default gets `Err` back from `install_default` and must install earlier.
Convenience features are per crate: a crate built without its feature panics (through `default_provider`) if it uses cryptography before a crate with the feature has installed the bundle lazily, so a binary that mixes such crates installs a provider explicitly.
The same provider value is guaranteed only for one version of the bundle crate: a binary whose dependency graph contains more than one version of it installs a provider explicitly, so that availability does not depend on which library uses cryptography first.

## 10. Helpers

Helpers are free functions in `picky_crypto::helpers`, written only against the public API above.
Each is derivable, so none is a contract operation; they exist so that consumers share one implementation.
Fallible helpers return `Result<_, Error>` and propagate the underlying error unchanged; no helper panics except `default_provider`, by design.

| Helper | Derived from |
|---|---|
| `default_provider()` | `get_default`, panicking when it returns `None` |
| `entry_algorithm(entry)`, `entry_fips(entry)` | a match on `Entry` plus the trait's `algorithm()` / `key_type()` / `fips()` (`Algorithm::KeyAgreement(Ffdh)` for an `FfdhKeyAgreement` entry) |
| typed accessors, one per `Entry` variant: `hash(provider, alg) -> Result<&dyn Hash, Error>`, ..., `key_agreement(provider, alg)`, `ffdh_key_agreement(provider)` | `get` plus a match; `Unsupported(alg)` when absent; `key_agreement` with `KeyAgreementAlgorithm::Ffdh` returns `InvalidInput`, because the FFDH entry implements `FfdhKeyAgreement` and is reached through `ffdh_key_agreement` |
| `digest(provider, alg, data)` | `Hash::start`, `update`, `finish` |
| `compute_mac(provider, alg, key, data) -> Result<MacTag, Error>` | `MacGeneration::start`, `update`, `finish` |
| `verify_mac(provider, alg, key, data, expected, len) -> Result<bool, Error>` | `MacVerification::start`, `update`, `finish`, then `MacVerifier::verify` |
| `random_x25519_private_key(provider) -> Result<X25519Scalar, Error>` | `SecureRandom::fill`, then RFC 7748 clamping (section 6.13); `Unsupported(Random(SecureRandom))` if the provider has no RNG |
| `ffdh_public_value(key, parameters) -> Result<OutputBytes, Error>` | `PrivateKey::agree(Ffdh, g)`, whose result is `g^x mod p` left-padded to the length of `p`; precondition: `parameters` are those the key was loaded with, otherwise the result is unspecified (never a panic) |
| `missing(provider, required: &[Requirement]) -> Vec<Requirement>` | `get` plus `Mac::supports` / `Cipher::supports` / `Aead::supports` / `KeyWrap::supports`; reports every unmet requirement (section 8), so no provider method is needed |

Like `digest`, `compute_mac` and `verify_mac` are one-shot helpers derived from the streaming operations.

NTLM's MD4, MD5 and RC4 requirements use `Requirement::from(Algorithm::Hash(HashAlgorithm::Md4))`, `Requirement::from(Algorithm::Hash(HashAlgorithm::Md5))` and `Requirement::from(Algorithm::StreamCipher(StreamCipherAlgorithm::Rc4))`.

Protocol-specific constructions (Kerberos n-fold, ciphertext stealing and RFC 3961 key derivation; NTLM constructions; JOSE and SSH framing; the PKCS#12 key derivation) and format conversions stay in their consuming crates.

## 11. Providers built around the contract

The contract does not depend on any of the following; they are described here because the semantics above refer to their roles.

- **Providers built from other providers' entries.**
  A provider may build entries from another provider's contract entries, for algorithms that a backend's library lacks: the key-based KDFs (section 6.4), the one-step KDF from `Hash` entries and the counter-mode KDF from `Mac` entries.
  The counter-mode KDF takes each PRF block from a `MacGeneration` with `MacTag::into_inner()`, requiring `Protection::Apply` from those entries; policy judges the resulting `Kdf` entry independently (section 6.4).
  Such a provider takes the entries it builds on explicitly at construction, contains no other cryptographic code, and reports `fips() == false`, so the FIPS policy rejects any provider composed with it.
  An entry of this kind exists only while some backend's library lacks the algorithm natively.
- **FFDH provider.**
  Finite-field Diffie-Hellman, which the reference libraries do not offer in the form section 6.11 requires, comes from a provider implemented over a constant-time big-integer library.
  It takes another provider's `SecureRandom` entry at construction, because it has no randomness of its own, and reports `fips() == false`.
- **RustCrypto bundle.**
  A fixed, documented composition: the RustCrypto backend first, so a native entry always wins, then the entries built over it, then the FFDH provider.
  It contains no cryptographic code and reports `fips() == false`.
  It is what the `rustcrypto` convenience features install (section 9).
- **RSA CRT completion.**
  Completing an RSA private key from `n`, `e`, `d`, `p` and `q` (computing `dP`, `dQ`, `qInv`) is key-format completion, not a standardized algorithm, so it is not a contract operation.
  It lives outside the contract so that format code can produce PKCS#8 and FIPS binaries can exclude the arithmetic from their dependency graph.

## 12. Conformance testing

The conformance suite runs on unwrapped providers and keys and uses published vectors (Wycheproof, NIST CAVP, RFC test vectors).

The suite reads `supports()` on each `Mac`, `Cipher`, `Aead` and `KeyWrap` entry; an entry reporting neither protection fails.
For each protection `p`, `start(key, p)` for `Mac` or the corresponding operation returns `Unsupported(algorithm)` exactly when `supports(p)` is false on must-support inputs.
For each unsupported protection, the suite skips vector labels and checks that `missing` reports the directional requirement.

Before a vector's label is applied, its eligibility is decided by the rules above:

- for an absent entry or a key operation for which `supports()` is false, the suite asserts `Unsupported` and does not apply the label;
- MAC, cipher, AEAD and key-wrap vectors apply only to supported protections;
- for a vector whose inputs are in the operation's must-support set, the label is applied as below;
- for a vector whose inputs are inside the valid domain but outside the must-support set (for example a 1024-bit RSA key), `Unsupported` is also accepted, and so is `VerificationFailed` from a verifier on a library with a single opaque failure (section 4); any other result must match the label.

Labels follow Wycheproof:

- `valid` vectors must succeed and `invalid` vectors must fail with the error class of section 4;
- `acceptable` vectors only assert that nothing panics, unless this document pins the behavior, in which case the pinned behavior is asserted;
- X25519 vectors labeled `acceptable` (twist, non-canonical, high-bit and low-order public values, and unclamped private keys) assert the published shared secret, because section 5.2 puts every 32-byte input in the must-support set; those whose shared secret is all zero assert `InvalidInput` (section 6.11);
- where this document pins a behavior that a vector's label contradicts, this document wins: for example, ECDSA signatures with a high `s` are valid (section 6.9), and the Bitcoin-specific vectors that reject them do not apply.

AEAD seal output is not deterministic, so seal is verified only through round trips (open of seal output) and cross-backend opens, with `Protection::Apply` supported by the sealing entry and `Protection::Process` by the opening entry.
A round trip requires both protections on the same entry; known-answer AEAD tests run on open only.
The suite checks that the returned nonce is 12 bytes.

Behaviors left implementation-defined are excluded from differential tests between backends.
For each of them, conformance tests assert that nothing panics and that the result is one of the outcomes this document allows for that case:

- Ed25519 verification with a validly encoded small-order public key `A` (section 6.9): success, or an outcome section 4 accepts for an unusable public key (`InvalidKey`, `Unsupported` or `VerificationFailed`);
- Ed25519 verification with a validly encoded small-order `R` in the signature (section 6.9): success or `VerificationFailed`;
- RSA PKCS#1 v1.5 verification of a DigestInfo with absent parameters (section 6.9): success or `VerificationFailed`, the result section 6.9 gives for a signature that does not verify;
- loading a PKCS#8 document that carries `attributes` (section 5.2): success or `InvalidKey`;
- a 3DES key whose component keys are not pairwise distinct or are DES weak or semi-weak keys (section 6.5): success or `InvalidKey`;
- handling of an RSA private key with inconsistent components (section 7): loading returns `InvalidKey`, or every private-key operation either returns `InvalidKey` or produces a result that verifies under (`n`, `e`).
  For decryption, verification uses a round trip through the provider's encryptor, or through a reference encryptor supplied by the test harness when the implementation under test has no encryptor (for example a hardware key).
  In differential runs, the result is also verified with the other backend, but the outcomes themselves are not compared.

The inputs for that last property are derived from published keys, because the known published RSA test vectors contain no keys with inconsistent components:

- base keys come from cited published sources;
- an input is derived only by swapping or substituting whole encoded INTEGER fields between cited keys: `dP` with `dQ`, `p` with `q` leaving `qInv` unchanged, or `qInv` taken from another cited key of the same size; no arithmetic, no generated bytes and no randomness;
- round-trip control: splitting a base key into its fields and reassembling them unchanged must reproduce the cited key's exact bytes, otherwise the test fails;
- positive control: the unmodified base key loads and produces a result that verifies on the backend under test.

Provider-value property tests against mock providers check composition (section 8.1) for `Mac`, `Cipher`, `Aead` and `KeyWrap`: a fallback fills in a protection the primary does not support, the primary serves a protection both members support, and the composite entry's `fips()` and the composed provider's `fips()` follow section 8.1.
For `Mac`, each context starts on the member serving the requested protection.

The FFDH exponent distribution (section 6.11) is mandatory but not observable from outputs; it is verified by review, while the suite checks the range of the public value and the round trip.

For every returned `OutputBytes`, `X25519Scalar`, `MacTag`, `MacVerifier` and `Sealed` through its fields, the suite also asserts that the `Debug` output never contains the buffer's bytes.
For every loaded key, the suite checks `key_size_bits()` against the exact size section 7 defines, including RSA keys whose modulus length is not a multiple of 8 bits (for example 3071 or 4095 bits) when the backend loads them; such keys come from cited sources like every other key.
`MacVerifier::verify` is tested with the correct tag, a wrong tag, an `expected` whose length differs from `len`, `len` of 0 and greater than the tag length, and the truncated lengths used by Kerberos (12 bytes) and NTLM (8 bytes).
A `MacTag` and a `MacVerifier` computed on the same key and data agree: the tag's `into_inner()` bytes verify through the verifier.

A backend that fails a vector natively is a defect to investigate, not a reason to skip the vector or to patch the library's behavior in the adapter.

## 13. Design rationale

**One algorithm enum per category.**
Per-category enums let each capability trait take exactly the algorithms it implements, so a mismatch is a type error; the wrapping `Algorithm` serves lookup, availability lists and `Unsupported`.
The one exception is key agreement: `KeyAgreementAlgorithm` covers both `KeyAgreement` and `FfdhKeyAgreement` because `PrivateKey::agree` takes every agreement algorithm.
`ProviderBuilder::build` therefore rejects a `KeyAgreement` entry that reports `Ffdh` (section 8).
This avoids a second, narrower enum naming the same algorithms twice.

**A small closed error set.**
Five variants cover what a caller can act on: not available, bad key, bad input, failed check, provider failure.
Closed means contract-defined, not exhaustively matchable (section 4).

**Policy outside the contract, composition inside.**
The FIPS policy is derivable from the public API and changes with NIST transitions, so it lives in its own crate (section 8.2).
Fallback composition is in the contract, because only the provider value can carry the FIPS status of shadowed members (section 8.1).

**Availability per protection.**
One-protection refusal comes from a library that lacks internal-IV seal for a key size or a policy that permits legacy processing only, including MAC verification and key unwrap.
Per-algorithm availability alone would report a capability whose needed protection is refused: a Kerberos encryption type needs 3DES in both protections, but a policy may refuse 3DES encryption.
Consumers state the protections they need through `Requirement` (section 8), and composition can fill in a missing protection (section 8.1).

**Streaming hash and MAC.**
Consumers process unbounded inputs and some already hash incrementally, and every library streams the algorithms it has; a one-shot interface would force large buffers and is a helper on top.

**Owned buffers for ciphers and AEAD.**
Inputs are borrowed and outputs are owned, the weakest shape every library supports; in-place APIs would force some libraries to copy anyway.
AEAD seal returns the generated nonce separately from `ciphertext || tag`, the common native ciphertext layout (section 6.7).

**Optional key generation returning PKCS#8.**
Generation returns the contract's private-key encoding, so a generated key can be loaded by any backend; a provider whose keys cannot be exported simply does not advertise generation.

**Public keys as the `subjectPublicKey` contents.**
The algorithm already fixes the key type, curve and hash; some libraries have no SPKI parser, and these are the forms the reference libraries import natively, among those that import that key type at all.
`public_key()` returns the same encoding, so consumers wrap it in SPKI only when a format needs it.

**One RNG entry, no RNG parameters.**
Some libraries accept only their own generator, so operations draw from the backend's generator, and consumers needing random bytes use the `SecureRandom` entry.

**Messages, not digests.**
Some libraries cannot sign or verify a precomputed digest; a handle-based key can always hash the message itself (section 7.1).

**Hardware keys as `PrivateKey` implementations.**
A smartcard or OS key store implements the trait directly, advertises what the device offers through `supports`, and reports its deployment status through `fips()`; it does not need a provider.

**FFDH with explicit domain parameters.**
Consumers take the group from the protocol, so the operation takes `p`, `g` and an optional `q`, performs the checks of section 6.11, and generates exponents as SP 800-56A specifies, with the range of section 6.11 when `q` is absent.

**Non-FIPS algorithms as ordinary identifiers.**
MD4, MD5, RC4, RC2, 3DES and FFDH are ordinary algorithm identifiers, and backends that lack them return `Unsupported`.
The FIPS policy filters or narrows entries according to their approved uses (section 8.2), while rejecting a provider containing any non-FIPS entry (for example the FFDH provider, or a RustCrypto entry) outright.
There is no compile-time distinction, because algorithm choice comes from parsed data.

**Lazy installation for convenience features.**
`get_or_install_default` lets a library's convenience feature install the RustCrypto bundle lazily, only when no provider was installed, without racing other libraries.

**One provider per process.**
Consumers use the process-wide default, so a process has one provider, unlike TLS libraries whose configurations each carry their own.
This is intended for FIPS binaries, where one provider behind one policy governs every operation.
The default is a static of the `picky-crypto` crate, so the guarantee holds for one linked instance.
A binary that links two semver-incompatible versions, or loads Rust dynamic libraries that each link their own copy, has one default per instance.
A FIPS binary therefore links a single `picky-crypto` instance and checks it in its build (for example with cargo-deny's duplicate-crate check).
It also installs its provider in every dynamic library that carries its own copy.
Explicit provider parameters in consumer APIs would be a change to those APIs, not to the contract.

**Composition at the granularity of advertisement.**
A fallback is chosen per algorithm, and per protection for `Mac`, `Cipher`, `Aead` and `KeyWrap`, never per input (section 8.1).
Algorithms and protections are advertised and known when providers are composed, so the member that serves each operation is known from the provider value alone and a policy can judge it.
Inputs are not advertised, so composing on them would make the serving member depend on data.

**Zeroizing every output.**
Whether a buffer is secret depends on how the consumer uses it, not on the operation that produced it (section 2, rule 1), so every returned buffer is wiped on drop.
The returned types are opaque for the same reason: their `Debug` shows only the length.
MAC results are split into a generated `MacTag`, whose bytes are read only through `into_inner()`, and a `MacVerifier` that only verifies, in constant time and with a length fixed by the protocol (section 6.2).

## Appendix A. Public API

The complete public API as Rust declarations.
Bodies are placeholders (`unimplemented!()`), except the default methods that return `Unsupported`.
The declarations compile without warnings, including under `cargo clippy -- -D warnings`, with `zeroize` as the only dependency.

```rust
#![forbid(unsafe_code)]
// Placeholder bodies leave parameters and items unused.
#![allow(dead_code, unused_variables)]

use std::fmt;
use std::sync::Arc;

pub use zeroize::Zeroizing;

/// Every variable-length buffer an operation returns, except MAC results (section 6.2): wiped on drop, whatever the operation.
/// `Debug` prints only the length; `Clone` clones the zeroizing storage; no `Display` and no comparison or hashing traits.
#[derive(Clone)]
pub struct OutputBytes(Zeroizing<Vec<u8>>);

impl OutputBytes {
    /// Wraps zeroizing storage unchanged; backends build every returned variable-length buffer other than a MAC result with it.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl std::ops::Deref for OutputBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for OutputBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OutputBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputBytes").field("len", &self.0.len()).finish()
    }
}

/// An X25519 private scalar returned by the contract: wiped on drop.
/// `Debug` prints only the length; `Clone` clones the zeroizing storage; no `Display` and no comparison or hashing traits.
#[derive(Clone)]
pub struct X25519Scalar(Zeroizing<[u8; 32]>);

impl X25519Scalar {
    /// Wraps zeroizing storage unchanged; it does not clamp.
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    pub fn into_inner(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
}

impl std::ops::Deref for X25519Scalar {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for X25519Scalar {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for X25519Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519Scalar").field("len", &32usize).finish()
    }
}

/// Raw MAC output returned by a backend context: wiped on drop, `Debug` prints only the length.
/// It exposes no bytes outside `picky-crypto`; `MacGeneration` and `MacVerification` turn it into a `MacTag` or a `MacVerifier`.
pub struct MacOutput(Zeroizing<Vec<u8>>);

impl MacOutput {
    /// Wraps zeroizing storage unchanged; backends build every MAC result with it.
    pub fn new(tag: Zeroizing<Vec<u8>>) -> Self {
        Self(tag)
    }
}

impl fmt::Debug for MacOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacOutput").field("len", &self.0.len()).finish()
    }
}

/// A generated MAC tag: wiped on drop; `Debug` prints only the length; `Clone` clones the zeroizing storage.
/// No `Deref`, `AsRef`, `Display`, comparison or `verify`: emit it or derive from it with `into_inner`.
#[derive(Clone)]
pub struct MacTag(Zeroizing<Vec<u8>>);

impl MacTag {
    /// The full tag, to emit a tag or derive from it.
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for MacTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacTag").field("len", &self.0.len()).finish()
    }
}

/// A tag computed to check a received one: wiped on drop; `Debug` prints only the length; `Clone` clones the zeroizing storage.
/// No byte access, `Display` or comparison trait: the only operation is `verify`.
#[derive(Clone)]
pub struct MacVerifier(Zeroizing<Vec<u8>>);

impl MacVerifier {
    /// Compares the first `len` bytes of the tag with `expected` in constant time (best effort).
    /// Returns false unless `expected.len() == len` and `1 <= len <=` the full tag length.
    /// `len` comes from the protocol definition, never from the received message.
    pub fn verify(&self, expected: &[u8], len: usize) -> bool {
        unimplemented!()
    }
}

impl fmt::Debug for MacVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacVerifier").field("len", &self.0.len()).finish()
    }
}

/// The output of `Aead::seal` (section 6.7): wiped on drop, `Debug` prints only lengths.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Sealed {
    /// The nonce generated by the backend's library: 12 bytes for AES-GCM.
    pub nonce: OutputBytes,
    /// `ciphertext || tag`.
    pub ciphertext_and_tag: OutputBytes,
}

impl Sealed {
    pub fn new(nonce: OutputBytes, ciphertext_and_tag: OutputBytes) -> Self {
        Self { nonce, ciphertext_and_tag }
    }
}

// ---------------------------------------------------------------------------
// Algorithm identifiers: one enum per capability category, plus `Algorithm`.
// ---------------------------------------------------------------------------

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Md4,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_384,
    Sha3_512,
}

impl HashAlgorithm {
    /// Digest length in bytes (metadata, not an operation).
    pub const fn output_len(self) -> usize {
        match self {
            Self::Md4 | Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MacAlgorithm {
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PasswordKdfAlgorithm {
    Pbkdf2HmacSha1,
    Pbkdf2HmacSha224,
    Pbkdf2HmacSha256,
    Pbkdf2HmacSha384,
    Pbkdf2HmacSha512,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
    /// NIST SP 800-56C rev. 2 one-step KDF ("Concat KDF"), auxiliary function = hash.
    OneStepSha1,
    OneStepSha256,
    OneStepSha384,
    OneStepSha512,
    /// NIST SP 800-108 rev. 1 KDF in counter mode, PRF = HMAC, 32-bit counter before the fixed input.
    CounterHmacSha1,
    CounterHmacSha256,
    CounterHmacSha384,
    CounterHmacSha512,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherAlgorithm {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    TdesEde3Cbc,
    Rc2Cbc,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamCipherAlgorithm {
    Rc4,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyWrapAlgorithm {
    Aes128Kw,
    Aes192Kw,
    Aes256Kw,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    RsaPkcs1v15Md5,
    RsaPkcs1v15Sha1,
    RsaPkcs1v15Sha224,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha512,
    RsaPkcs1v15Sha3_384,
    RsaPkcs1v15Sha3_512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    Ed25519,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AsymmetricEncryptionAlgorithm {
    RsaPkcs1v15,
    RsaOaepSha1,
    RsaOaepSha256,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyAgreementAlgorithm {
    EcdhP256,
    EcdhP384,
    EcdhP521,
    X25519,
    /// Finite-field Diffie-Hellman over caller-supplied domain parameters.
    Ffdh,
}

/// Private key types that can be loaded.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa,
    EcP256,
    EcP384,
    EcP521,
    Ed25519,
    X25519,
    Ffdh,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyGenerationAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcP256,
    EcP384,
    EcP521,
    Ed25519,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RandomAlgorithm {
    /// The backend's cryptographically secure random generator.
    SecureRandom,
}

/// An algorithm a provider can advertise (used for lookup, availability and `Error::Unsupported`), or, for `PublicKeyExport`, a private-key operation that only `Error::Unsupported` names.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Hash(HashAlgorithm),
    Mac(MacAlgorithm),
    PasswordKdf(PasswordKdfAlgorithm),
    Kdf(KdfAlgorithm),
    Cipher(CipherAlgorithm),
    StreamCipher(StreamCipherAlgorithm),
    Aead(AeadAlgorithm),
    KeyWrap(KeyWrapAlgorithm),
    Signature(SignatureAlgorithm),
    AsymmetricEncryption(AsymmetricEncryptionAlgorithm),
    KeyAgreement(KeyAgreementAlgorithm),
    PrivateKeyLoading(KeyType),
    KeyGeneration(KeyGenerationAlgorithm),
    Random(RandomAlgorithm),
    /// Never a provider entry; identifies `PrivateKey::public_key` in `Error::Unsupported`.
    PublicKeyExport(KeyType),
}

/// Whether an operation applies cryptographic protection or processes protected data (NIST SP 800-131A).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protection {
    Apply,
    Process,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Requirement {
    Algorithm(Algorithm),
    Mac(MacAlgorithm, Protection),
    Cipher(CipherAlgorithm, Protection),
    Aead(AeadAlgorithm, Protection),
    KeyWrap(KeyWrapAlgorithm, Protection),
}

impl From<Algorithm> for Requirement {
    fn from(algorithm: Algorithm) -> Self {
        Self::Algorithm(algorithm)
    }
}

// ---------------------------------------------------------------------------
// Errors (closed to backend-defined variants; extensible by the contract)
// ---------------------------------------------------------------------------

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The algorithm, operation, key size or parameter is unavailable or refused by policy.
    Unsupported(Algorithm),
    /// Key material is malformed, of the wrong type or size, or rejected by key validation.
    InvalidKey,
    /// A non-key input is malformed or out of range.
    InvalidInput,
    /// A signature, tag, unwrap integrity check or decryption check failed.
    /// No reason is given.
    VerificationFailed,
    /// The backend failed for a reason that does not depend on the inputs.
    ProviderFailure,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl std::error::Error for Error {}

/// Returned by `ProviderBuilder::build`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// Two entries implement the same algorithm.
    Duplicate(Algorithm),
    /// An entry reports an algorithm that its `Entry` variant cannot implement (a `KeyAgreement` entry reporting `KeyAgreementAlgorithm::Ffdh`).
    Mismatched(Algorithm),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!()
    }
}

impl std::error::Error for BuildError {}

// ---------------------------------------------------------------------------
// Key inputs and outputs
// ---------------------------------------------------------------------------

/// A public key: the contents of the SPKI `subjectPublicKey` BIT STRING.
///
/// PKCS#1 `RSAPublicKey` DER for RSA, the uncompressed SEC1 point for EC, the 32 raw bytes for Ed25519.
/// The algorithm of the operation fixes the key type, curve and hash.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey<'a>(pub &'a [u8]);

/// Finite-field Diffie-Hellman domain parameters, as unsigned big-endian integers.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct FfdhParameters<'a> {
    pub p: &'a [u8],
    pub g: &'a [u8],
    /// Order of the subgroup generated by `g`, when known.
    pub q: Option<&'a [u8]>,
}

impl<'a> FfdhParameters<'a> {
    pub fn new(p: &'a [u8], g: &'a [u8], q: Option<&'a [u8]>) -> Self {
        Self { p, g, q }
    }
}

/// Private key material in the contract's encoding for its key type.
/// `Debug` is implemented by hand and never prints secret bytes.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum PrivateKeyMaterial<'a> {
    /// RSA, EC and Ed25519: the PKCS#8 DER (section 5.2).
    Pkcs8(&'a [u8]),
    /// X25519: the raw RFC 7748 scalar.
    X25519(&'a [u8; 32]),
    /// Finite-field DH: domain parameters and the private exponent (unsigned big-endian).
    Ffdh { parameters: FfdhParameters<'a>, private_value: &'a [u8] },
}

impl fmt::Debug for PrivateKeyMaterial<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unimplemented!("prints the variant name only")
    }
}

/// An operation on a private key, as queried with `PrivateKey::supports`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyOperation {
    Sign(SignatureAlgorithm),
    Decrypt(AsymmetricEncryptionAlgorithm),
    Agree(KeyAgreementAlgorithm),
    PublicKey,
}

// ---------------------------------------------------------------------------
// Capability traits: an entry implements exactly one algorithm.
// `algorithm()`, `key_type()`, `fips()` and `supports()` are cheap, infallible and never access a device.
// ---------------------------------------------------------------------------

pub trait Hash: Send + Sync {
    fn algorithm(&self) -> HashAlgorithm;
    fn fips(&self) -> bool;
    fn start(&self) -> Result<Box<dyn HashContext>, Error>;
}

pub trait HashContext: Send {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finish(self: Box<Self>) -> Result<OutputBytes, Error>;
}

pub trait Mac: Send + Sync {
    fn algorithm(&self) -> MacAlgorithm;
    fn fips(&self) -> bool;
    fn supports(&self, protection: Protection) -> bool;
    /// Returns `Unsupported(Algorithm::Mac(algorithm))` when `supports(protection)` is false.
    fn start(&self, key: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error>;
}

pub trait MacContext: Send {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    /// The full, untruncated tag.
    fn finish(self: Box<Self>) -> Result<MacOutput, Error>;
}

/// Streaming tag generation (`Protection::Apply`), implemented by `picky-crypto` over a `Mac` entry.
pub struct MacGeneration(Box<dyn MacContext>);

impl MacGeneration {
    pub fn start(mac: &dyn Mac, key: &[u8]) -> Result<Self, Error> {
        unimplemented!()
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn finish(self) -> Result<MacTag, Error> {
        unimplemented!()
    }
}

/// Streaming tag verification (`Protection::Process`), implemented by `picky-crypto` over a `Mac` entry.
pub struct MacVerification(Box<dyn MacContext>);

impl MacVerification {
    pub fn start(mac: &dyn Mac, key: &[u8]) -> Result<Self, Error> {
        unimplemented!()
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        unimplemented!()
    }

    pub fn finish(self) -> Result<MacVerifier, Error> {
        unimplemented!()
    }
}

pub trait PasswordKdf: Send + Sync {
    fn algorithm(&self) -> PasswordKdfAlgorithm;
    fn fips(&self) -> bool;
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_len: usize,
    ) -> Result<OutputBytes, Error>;
}

pub trait Kdf: Send + Sync {
    fn algorithm(&self) -> KdfAlgorithm;
    fn fips(&self) -> bool;
    /// `secret` is Z (one-step) or K_IN (counter mode); `fixed_info` is OtherInfo (one-step) or the complete SP 800-108 fixed input data (counter mode).
    fn derive(&self, secret: &[u8], fixed_info: &[u8], output_len: usize) -> Result<OutputBytes, Error>;
}

/// Unauthenticated block cipher mode, one-shot, no padding.
pub trait Cipher: Send + Sync {
    fn algorithm(&self) -> CipherAlgorithm;
    fn fips(&self) -> bool;
    fn supports(&self, protection: Protection) -> bool;
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<OutputBytes, Error>;
    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<OutputBytes, Error>;
}

pub trait StreamCipher: Send + Sync {
    fn algorithm(&self) -> StreamCipherAlgorithm;
    fn fips(&self) -> bool;
    fn start(&self, key: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error>;
}

pub trait StreamCipherContext: Send {
    /// Applies the next `data.len()` keystream bytes; the state carries over to the next call.
    fn apply(&mut self, data: &[u8]) -> Result<OutputBytes, Error>;
}

pub trait Aead: Send + Sync {
    fn algorithm(&self) -> AeadAlgorithm;
    fn fips(&self) -> bool;
    fn supports(&self, protection: Protection) -> bool;
    /// Returns the 12-byte nonce generated by the backend's library and `ciphertext || tag`.
    /// Section 6.7 defines internal IV generation and the caller's per-key limit.
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, Error>;
    /// Takes a 12-byte nonce and `ciphertext || tag`; returns no plaintext unless authentication succeeds.
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<OutputBytes, Error>;
}

pub trait KeyWrap: Send + Sync {
    fn algorithm(&self) -> KeyWrapAlgorithm;
    fn fips(&self) -> bool;
    fn supports(&self, protection: Protection) -> bool;
    fn wrap(&self, kek: &[u8], key_data: &[u8]) -> Result<OutputBytes, Error>;
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<OutputBytes, Error>;
}

pub trait SignatureVerifier: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn fips(&self) -> bool;
    fn verify(&self, public_key: PublicKey<'_>, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

pub trait AsymmetricEncryptor: Send + Sync {
    fn algorithm(&self) -> AsymmetricEncryptionAlgorithm;
    fn fips(&self) -> bool;
    fn encrypt(&self, public_key: PublicKey<'_>, plaintext: &[u8]) -> Result<OutputBytes, Error>;
}

pub trait KeyAgreement: Send + Sync {
    /// Never `KeyAgreementAlgorithm::Ffdh`: `ProviderBuilder::build` rejects such an entry.
    fn algorithm(&self) -> KeyAgreementAlgorithm;
    fn fips(&self) -> bool;
    fn generate_ephemeral(&self) -> Result<Box<dyn EphemeralSecret>, Error>;
}

/// Finite-field Diffie-Hellman: the ephemeral counterpart of `KeyAgreement` with explicit parameters.
/// Its algorithm is always `KeyAgreementAlgorithm::Ffdh`, so the trait has no `algorithm()` method.
pub trait FfdhKeyAgreement: Send + Sync {
    fn fips(&self) -> bool;
    fn generate_ephemeral(&self, parameters: FfdhParameters<'_>) -> Result<Box<dyn EphemeralSecret>, Error>;
}

pub trait EphemeralSecret: Send {
    /// Uncompressed SEC1 point, the 32 RFC 7748 bytes for X25519, or the FFDH public value (big-endian, left-padded to the length of `p`).
    fn public_key(&self) -> Result<OutputBytes, Error>;
    /// Single use.
    fn agree(self: Box<Self>, peer_public_key: &[u8]) -> Result<OutputBytes, Error>;
}

pub trait PrivateKeyLoader: Send + Sync {
    fn key_type(&self) -> KeyType;
    fn fips(&self) -> bool;
    fn load(&self, private_key: PrivateKeyMaterial<'_>) -> Result<Box<dyn PrivateKey>, Error>;
}

pub trait KeyGenerator: Send + Sync {
    fn algorithm(&self) -> KeyGenerationAlgorithm;
    fn fips(&self) -> bool;
    fn generate(&self) -> Result<OutputBytes, Error>;
}

pub trait SecureRandom: Send + Sync {
    fn algorithm(&self) -> RandomAlgorithm;
    fn fips(&self) -> bool;
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error>;
}

/// A private key: loaded by a provider, or a hardware/external key implementing this trait directly.
pub trait PrivateKey: Send + Sync {
    fn key_type(&self) -> KeyType;

    /// Key size in bits (section 7); cheap, infallible, cached for hardware keys, with 0 for no meaningful size.
    fn key_size_bits(&self) -> usize;

    /// Whether the key implements `operation`.
    /// Never performs the operation.
    fn supports(&self, operation: KeyOperation) -> bool;

    /// Sections 6.15 and 7.
    fn fips(&self) -> bool;

    fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::Signature(algorithm)))
    }

    fn decrypt(
        &self,
        algorithm: AsymmetricEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::AsymmetricEncryption(algorithm)))
    }

    fn agree(
        &self,
        algorithm: KeyAgreementAlgorithm,
        peer_public_key: &[u8],
    ) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::KeyAgreement(algorithm)))
    }

    /// Optional: the `subjectPublicKey` contents of the matching public key (not offered for FFDH).
    fn public_key(&self) -> Result<OutputBytes, Error> {
        Err(Error::Unsupported(Algorithm::PublicKeyExport(self.key_type())))
    }
}

// ---------------------------------------------------------------------------
// Debug for trait objects: the contract's format, never a backend's
// ---------------------------------------------------------------------------

impl fmt::Debug for dyn Hash + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hash").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn Mac + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mac").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn PasswordKdf + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordKdf").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn Kdf + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kdf").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn Cipher + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cipher").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn StreamCipher + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamCipher").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn Aead + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Aead").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn KeyWrap + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyWrap").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn SignatureVerifier + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureVerifier").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn AsymmetricEncryptor + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsymmetricEncryptor").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn KeyAgreement + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyAgreement").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn FfdhKeyAgreement + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FfdhKeyAgreement").field("algorithm", &KeyAgreementAlgorithm::Ffdh).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn PrivateKeyLoader + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyLoader").field("key_type", &self.key_type()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn KeyGenerator + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGenerator").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn SecureRandom + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureRandom").field("algorithm", &self.algorithm()).field("fips", &self.fips()).finish()
    }
}

impl fmt::Debug for dyn PrivateKey + '_ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey").field("key_type", &self.key_type()).field("fips", &self.fips()).finish()
    }
}

// ---------------------------------------------------------------------------
// Provider value
// ---------------------------------------------------------------------------

/// One capability entry.
/// Entries are `Arc`s so that a provider can be composed at runtime from entries of other providers.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Entry {
    Hash(Arc<dyn Hash>),
    Mac(Arc<dyn Mac>),
    PasswordKdf(Arc<dyn PasswordKdf>),
    Kdf(Arc<dyn Kdf>),
    Cipher(Arc<dyn Cipher>),
    StreamCipher(Arc<dyn StreamCipher>),
    Aead(Arc<dyn Aead>),
    KeyWrap(Arc<dyn KeyWrap>),
    SignatureVerifier(Arc<dyn SignatureVerifier>),
    AsymmetricEncryptor(Arc<dyn AsymmetricEncryptor>),
    KeyAgreement(Arc<dyn KeyAgreement>),
    FfdhKeyAgreement(Arc<dyn FfdhKeyAgreement>),
    PrivateKeyLoader(Arc<dyn PrivateKeyLoader>),
    KeyGenerator(Arc<dyn KeyGenerator>),
    SecureRandom(Arc<dyn SecureRandom>),
}

/// An immutable set of entries, at most one per algorithm.
#[derive(Clone, Debug)]
pub struct CryptoProvider {
    _private: (),
}

impl CryptoProvider {
    pub fn builder() -> ProviderBuilder {
        unimplemented!()
    }

    /// The entry for `algorithm`, if present; it performs at least one operation (section 8).
    pub fn get(&self, algorithm: Algorithm) -> Option<&Entry> {
        unimplemented!()
    }

    /// All entries, in unspecified order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        // Placeholder body: this listing has no storage.
        std::iter::empty()
    }

    /// True only if the provider has at least one entry, every entry reports `fips()`, and every provider it was composed from reported `fips()` (section 8.1).
    pub fn fips(&self) -> bool {
        unimplemented!()
    }

    /// Entries of `self`, plus what `fallback` advertises and `self` does not: algorithms, and protections of `Mac`, `Cipher`, `Aead` and `KeyWrap` entries (section 8.1).
    /// The result's `fips()` is `self.fips() && fallback.fips()`.
    pub fn with_fallback(&self, fallback: &CryptoProvider) -> CryptoProvider {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct ProviderBuilder {
    _private: (),
}

impl ProviderBuilder {
    pub fn with(self, entry: Entry) -> Self {
        unimplemented!()
    }

    pub fn build(self) -> Result<CryptoProvider, BuildError> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Process-wide default
// ---------------------------------------------------------------------------

/// Installs the process-wide default.
/// Returns the provider back if one is already installed.
pub fn install_default(provider: CryptoProvider) -> Result<(), CryptoProvider> {
    unimplemented!()
}

/// Returns the installed default; if none is installed, installs `make()` first (called at most once).
pub fn get_or_install_default(make: fn() -> CryptoProvider) -> &'static CryptoProvider {
    unimplemented!()
}

/// Returns the installed default, or `None`.
/// Never panics and never installs.
pub fn get_default() -> Option<&'static CryptoProvider> {
    unimplemented!()
}

// ---------------------------------------------------------------------------
// Helpers above the contract: free functions over the public API only.
// ---------------------------------------------------------------------------

pub mod helpers {
    use super::*;

    /// The installed default.
    /// Panics with installation instructions if none is installed.
    /// Equivalent to `get_default` followed by a panic when it returns `None`.
    pub fn default_provider() -> &'static CryptoProvider {
        unimplemented!()
    }

    pub fn entry_algorithm(entry: &Entry) -> Algorithm {
        unimplemented!()
    }

    pub fn entry_fips(entry: &Entry) -> bool {
        unimplemented!()
    }

    // Typed accessors: `get` plus a match on `Entry`; `Unsupported(algorithm)` when absent.

    pub fn hash(provider: &CryptoProvider, algorithm: HashAlgorithm) -> Result<&dyn Hash, Error> {
        unimplemented!()
    }

    pub fn mac(provider: &CryptoProvider, algorithm: MacAlgorithm) -> Result<&dyn Mac, Error> {
        unimplemented!()
    }

    pub fn password_kdf(provider: &CryptoProvider, algorithm: PasswordKdfAlgorithm) -> Result<&dyn PasswordKdf, Error> {
        unimplemented!()
    }

    pub fn kdf(provider: &CryptoProvider, algorithm: KdfAlgorithm) -> Result<&dyn Kdf, Error> {
        unimplemented!()
    }

    pub fn cipher(provider: &CryptoProvider, algorithm: CipherAlgorithm) -> Result<&dyn Cipher, Error> {
        unimplemented!()
    }

    pub fn stream_cipher(provider: &CryptoProvider, algorithm: StreamCipherAlgorithm) -> Result<&dyn StreamCipher, Error> {
        unimplemented!()
    }

    pub fn aead(provider: &CryptoProvider, algorithm: AeadAlgorithm) -> Result<&dyn Aead, Error> {
        unimplemented!()
    }

    pub fn key_wrap(provider: &CryptoProvider, algorithm: KeyWrapAlgorithm) -> Result<&dyn KeyWrap, Error> {
        unimplemented!()
    }

    pub fn signature_verifier(provider: &CryptoProvider, algorithm: SignatureAlgorithm) -> Result<&dyn SignatureVerifier, Error> {
        unimplemented!()
    }

    pub fn asymmetric_encryptor(provider: &CryptoProvider, algorithm: AsymmetricEncryptionAlgorithm) -> Result<&dyn AsymmetricEncryptor, Error> {
        unimplemented!()
    }

    /// ECDH and X25519 entries; `KeyAgreementAlgorithm::Ffdh` returns `InvalidInput` (use `ffdh_key_agreement`).
    pub fn key_agreement(provider: &CryptoProvider, algorithm: KeyAgreementAlgorithm) -> Result<&dyn KeyAgreement, Error> {
        unimplemented!()
    }

    pub fn private_key_loader(provider: &CryptoProvider, algorithm: KeyType) -> Result<&dyn PrivateKeyLoader, Error> {
        unimplemented!()
    }

    pub fn key_generator(provider: &CryptoProvider, algorithm: KeyGenerationAlgorithm) -> Result<&dyn KeyGenerator, Error> {
        unimplemented!()
    }

    pub fn secure_random(provider: &CryptoProvider, algorithm: RandomAlgorithm) -> Result<&dyn SecureRandom, Error> {
        unimplemented!()
    }

    /// `KeyAgreementAlgorithm::Ffdh` entry.
    pub fn ffdh_key_agreement(provider: &CryptoProvider) -> Result<&dyn FfdhKeyAgreement, Error> {
        unimplemented!()
    }

    pub fn digest(provider: &CryptoProvider, algorithm: HashAlgorithm, data: &[u8]) -> Result<OutputBytes, Error> {
        unimplemented!()
    }

    pub fn compute_mac(
        provider: &CryptoProvider,
        algorithm: MacAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<MacTag, Error> {
        unimplemented!()
    }

    pub fn verify_mac(
        provider: &CryptoProvider,
        algorithm: MacAlgorithm,
        key: &[u8],
        data: &[u8],
        expected: &[u8],
        len: usize,
    ) -> Result<bool, Error> {
        unimplemented!()
    }

    /// 32 bytes from `SecureRandom` with RFC 7748 clamping applied: a new X25519 private key.
    pub fn random_x25519_private_key(provider: &CryptoProvider) -> Result<X25519Scalar, Error> {
        unimplemented!()
    }

    /// The FFDH public value `g^x mod p` of `key`, computed as `key.agree(Ffdh, g)`.
    pub fn ffdh_public_value(key: &dyn PrivateKey, parameters: FfdhParameters<'_>) -> Result<OutputBytes, Error> {
        unimplemented!()
    }

    /// Every unmet requirement, using `get` and the entry's `supports` (section 8).
    pub fn missing(provider: &CryptoProvider, required: &[Requirement]) -> Vec<Requirement> {
        unimplemented!()
    }
}
```
