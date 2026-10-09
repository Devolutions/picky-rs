# `picky-crypto` contract

This document specifies the `picky-crypto` cryptographic provider contract.
It is normative: a backend author can implement a backend from this document alone, and the conformance suite derives its expectations from it and from the published standards it cites.
`INTENT.md`, next to this file, states the purpose and invariants of the crate; this document turns them into a precise interface.
The crate documentation and source give the public Rust declarations; the sections below specify their behavior.

## 1. Scope

The contract consists of:

- algorithm identifiers (section 3);
- the closed error set (section 4);
- key, signature and secret encodings (section 5);
- capability traits, one entry per algorithm (section 6);
- the private key trait ([`PrivateKey`]), implemented by backends and directly by hardware or external keys (section 7);
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
   Variable-length outputs are a newly allocated [`OutputBytes`], an opaque wrapper around [`Zeroizing<Vec<u8>>`](Zeroizing).
   Fixed-size values keep fixed-size types: the X25519 private key returned by [`helpers::random_x25519_private_key`] is an [`X25519Scalar`], an opaque wrapper around [`Zeroizing<[u8; 32]>`](Zeroizing), which matches the fixed 32-byte scalar borrowed by [`PrivateKeyMaterial::X25519`].
   [`OutputBytes::new`] and [`X25519Scalar::new`] wrap zeroizing storage unchanged; [`X25519Scalar::new`] does not clamp.
   Both dereference to their bytes, implement [`AsRef<[u8]>`](std::convert::AsRef), and give back the [`Zeroizing`] value through [`OutputBytes::into_inner`] and [`X25519Scalar::into_inner`] respectively, never a plain buffer.
   Both implement [`Clone`](std::clone::Clone), which clones the inner [`Zeroizing`] value: a clone is itself wiped on drop, so a caller needing a copy has no reason to fall back to an unwiped [`slice::to_vec`].
   Their [`Debug`](std::fmt::Debug) prints only the length, and they implement neither [`Display`](std::fmt::Display) nor any comparison or hashing trait ([`PartialEq`](std::cmp::PartialEq), [`Eq`](std::cmp::Eq), [`Hash`](std::hash::Hash), [`Ord`](std::cmp::Ord)), so that no buffer is printed by accident.
   MAC results are [`MacTag`] and [`MacVerifier`] (section 6.2) rather than [`OutputBytes`]; [`MacOutput`] is their backend-side carrier.
   Whether an output is secret cannot be decided by operation: the NT hash is an MD4 digest, NTLMv2 and RFC 3961 derive keys from HMAC and hash outputs, and RC4 output is plaintext when decrypting; a uniform rule is fail-safe.
   [`SecureRandom::fill`] writes into the caller's buffer, which stays the caller's responsibility.
   Buffers the caller passes in, including [`PrivateKeyMaterial`], belong to the caller, who is responsible for wiping them.
   Zeroizing is best effort: copies the caller makes, and reallocations of a buffer the caller grows, are not wiped.
   Secret state owned by a software implementation (private keys, MAC keys, cipher and keystream state in contexts, ephemeral secrets, and any copy of key material the adapter keeps) is also wiped on drop, best effort.
   The adapter always wipes its own copies.
   State inside the library is wiped only as far as the library's own cleanup does; some libraries do not guarantee this.
   Keys held by a device or an OS key store are outside this rule.
2. **No panics.**
   No input, however malformed, makes a backend panic.
   Some library APIs panic on out-of-range lengths; the adapter checks those bounds first and returns the error rule 4 prescribes.
3. **Advertised means implemented.**
   An entry identifies exactly one algorithm: the one returned by its identity method (wrapped in [`Algorithm`]), or [`Algorithm::PrivateKeyLoading`] with the key type returned by [`PrivateKeyLoader::key_type`] for a [`PrivateKeyLoader`] entry, or [`Algorithm::KeyAgreement`] with [`KeyAgreementAlgorithm::Ffdh`] for an [`FfdhKeyAgreement`] entry.
   [`Mac::supports`], [`Cipher::supports`], [`Aead::supports`] and [`KeyWrap::supports`] report the only protections advertised by their entries (section 8); every other entry advertises every operation of its trait.
   Each advertised operation implements its algorithm for every input in its must-support set, except as allowed by rule 4 and by a policy's input narrowing (section 8.2).
   An algorithm with no provider entry cannot be reached through it: the lookup fails and the caller reports [`Error::Unsupported`].
   Private-key operations are advertised by the key itself ([`PrivateKey::supports`], section 7), not by provider entries.
4. **Valid domain and must-support set.**
   Each operation defines a valid domain (inputs that are well-formed for the algorithm) and, within it, a must-support set.
   For an advertised operation:
   - An input outside the valid domain returns [`Error::InvalidKey`] (key material) or [`Error::InvalidInput`] (anything else), except that a verifier on a library with a single opaque failure may return [`Error::VerificationFailed`] for an unusable public key (section 4).
   - An input inside the valid domain but outside the must-support set is either processed like an input in the must-support set or rejected with [`Error::Unsupported`] naming the algorithm (or, for such a verifier, [`Error::VerificationFailed`], section 4).
     For example, a backend may refuse RSA private keys other than 2048, 3072 or 4096-bit two-prime keys with equal-size primes, because some libraries accept only those.
   - An input in the must-support set never returns [`Error::Unsupported`], except for policy input narrowing (section 8.2).
   - Where an operation states no explicit domain for a length, any length is valid and lengths up to 2^31 − 1 bytes are in the must-support set.
   - Valid domains include the limits of the standard that defines the algorithm (for example RFC 8018's maximum derived-key length).
     Those limits are checked first, before allocation or any cryptographic processing, with overflow-safe arithmetic on [`usize`] arguments.
5. **No RNG parameter.**
   Operations that need randomness (key generation, ephemeral keys, ECDSA nonces, RSA encryption padding, AES-GCM seal nonces) use the backend's own secure random generator.
   No generator is passed in, because some libraries accept only their own.
6. **Lengths are checked.**
   For advertised operations, wrong key, IV, open nonce or tag lengths are reported as [`Error::InvalidKey`] (for keys) or [`Error::InvalidInput`] (for anything else), never truncated or padded silently.
7. **Thread safety and diagnostics.**
   Entries and private keys are `Send + Sync` (supertraits of their traits, so `dyn Trait` is the trait-object type used); contexts and ephemeral secrets are [`Send`](std::marker::Send).
   [`Debug`](std::fmt::Debug) is not a supertrait: `picky-crypto` implements [`Debug`](std::fmt::Debug) for each capability and private-key trait object, printing only the algorithm (or key type) and the FIPS report, the result of the trait's FIPS-reporting method (for example [`Hash::fips`] or [`PrivateKey::fips`], section 6.15).
   [`Box`](std::boxed::Box) and [`Arc`](std::sync::Arc) of these trait objects are therefore [`Debug`](std::fmt::Debug), so consumers can derive [`Debug`](std::fmt::Debug) on types that hold them.
   No backend's [`Debug`](std::fmt::Debug) output, which might reveal secret material, is reachable through the contract.
   Contexts and ephemeral secrets are not [`Debug`](std::fmt::Debug).
   The identity methods (each capability trait's algorithm method, [`PrivateKeyLoader::key_type`] and [`PrivateKey::key_type`]), [`PrivateKey::key_size_bits`], the FIPS-reporting methods, and the protection and key-operation queries ([`Mac::supports`], [`Cipher::supports`], [`Aead::supports`], [`KeyWrap::supports`] and [`PrivateKey::supports`], sections 7 and 8) are cheap and infallible and never access a device; the [`Debug`](std::fmt::Debug) implementations call the FIPS-reporting method.
   Protection and key-operation queries never perform the operation.
8. **State after an error.**
   An error returned by [`HashContext::update`], [`MacContext::update`] or [`StreamCipherContext::apply`] leaves the context unusable: the caller drops it, and any further call on it returns [`Error::ProviderFailure`] without panicking.
   Contexts are not transactional: a failed call may or may not have consumed input or keystream.
   After [`SecureRandom::fill`] fails, the destination content is unspecified and must not be used.
9. **Minimality exceptions.**
   An operation that can be derived from other operations of the contract is in the contract only if composing it outside the backend would cost performance (exception 1), move the computation outside a validated module boundary (exception 2), or lose a security property the backend provides (exception 3).
   Each such operation carries an "Exception" note naming the exception that applies.

## 3. Algorithm identifiers

There is one enum per capability category, plus a wrapping [`Algorithm`] enum.
Per-category enums make it a type error to ask a hash entry for an AEAD algorithm.
[`Algorithm`] is used where categories meet: provider lookup, availability lists, and [`Error::Unsupported`].
All of these enums are `#[non_exhaustive]`, [`Copy`](std::marker::Copy), [`Eq`](std::cmp::Eq) and [`Hash`](std::hash::Hash).

| Enum | Variants |
|---|---|
| [`HashAlgorithm`] | [`HashAlgorithm::Md4`], [`HashAlgorithm::Md5`], [`HashAlgorithm::Sha1`], [`HashAlgorithm::Sha224`], [`HashAlgorithm::Sha256`], [`HashAlgorithm::Sha384`], [`HashAlgorithm::Sha512`], [`HashAlgorithm::Sha3_384`], [`HashAlgorithm::Sha3_512`] |
| [`MacAlgorithm`] | [`MacAlgorithm::HmacSha1`], [`MacAlgorithm::HmacSha224`], [`MacAlgorithm::HmacSha256`], [`MacAlgorithm::HmacSha384`], [`MacAlgorithm::HmacSha512`] |
| [`PasswordKdfAlgorithm`] | [`PasswordKdfAlgorithm::Pbkdf2HmacSha1`], [`PasswordKdfAlgorithm::Pbkdf2HmacSha224`], [`PasswordKdfAlgorithm::Pbkdf2HmacSha256`], [`PasswordKdfAlgorithm::Pbkdf2HmacSha384`], [`PasswordKdfAlgorithm::Pbkdf2HmacSha512`] |
| [`KdfAlgorithm`] | [`KdfAlgorithm::OneStepSha1`], [`KdfAlgorithm::OneStepSha256`], [`KdfAlgorithm::OneStepSha384`], [`KdfAlgorithm::OneStepSha512`], [`KdfAlgorithm::CounterHmacSha1`], [`KdfAlgorithm::CounterHmacSha256`], [`KdfAlgorithm::CounterHmacSha384`], [`KdfAlgorithm::CounterHmacSha512`] |
| [`CipherAlgorithm`] | [`CipherAlgorithm::Aes128Cbc`], [`CipherAlgorithm::Aes192Cbc`], [`CipherAlgorithm::Aes256Cbc`], [`CipherAlgorithm::TdesEde3Cbc`], [`CipherAlgorithm::Rc2Cbc`] |
| [`StreamCipherAlgorithm`] | [`StreamCipherAlgorithm::Rc4`] |
| [`AeadAlgorithm`] | [`AeadAlgorithm::Aes128Gcm`], [`AeadAlgorithm::Aes192Gcm`], [`AeadAlgorithm::Aes256Gcm`] |
| [`KeyWrapAlgorithm`] | [`KeyWrapAlgorithm::Aes128Kw`], [`KeyWrapAlgorithm::Aes192Kw`], [`KeyWrapAlgorithm::Aes256Kw`] |
| [`SignatureAlgorithm`] | [`SignatureAlgorithm::RsaPkcs1v15Md5`], [`SignatureAlgorithm::RsaPkcs1v15Sha1`], [`SignatureAlgorithm::RsaPkcs1v15Sha224`], [`SignatureAlgorithm::RsaPkcs1v15Sha256`], [`SignatureAlgorithm::RsaPkcs1v15Sha384`], [`SignatureAlgorithm::RsaPkcs1v15Sha512`], [`SignatureAlgorithm::RsaPkcs1v15Sha3_384`], [`SignatureAlgorithm::RsaPkcs1v15Sha3_512`], [`SignatureAlgorithm::EcdsaP256Sha256`], [`SignatureAlgorithm::EcdsaP384Sha384`], [`SignatureAlgorithm::EcdsaP521Sha512`], [`SignatureAlgorithm::Ed25519`] |
| [`AsymmetricEncryptionAlgorithm`] | [`AsymmetricEncryptionAlgorithm::RsaPkcs1v15`], [`AsymmetricEncryptionAlgorithm::RsaOaepSha1`], [`AsymmetricEncryptionAlgorithm::RsaOaepSha256`] |
| [`KeyAgreementAlgorithm`] | [`KeyAgreementAlgorithm::EcdhP256`], [`KeyAgreementAlgorithm::EcdhP384`], [`KeyAgreementAlgorithm::EcdhP521`], [`KeyAgreementAlgorithm::X25519`], [`KeyAgreementAlgorithm::Ffdh`] |
| [`KeyType`] | [`KeyType::Rsa`], [`KeyType::EcP256`], [`KeyType::EcP384`], [`KeyType::EcP521`], [`KeyType::Ed25519`], [`KeyType::X25519`], [`KeyType::Ffdh`] |
| [`KeyGenerationAlgorithm`] | [`KeyGenerationAlgorithm::Rsa2048`], [`KeyGenerationAlgorithm::Rsa3072`], [`KeyGenerationAlgorithm::Rsa4096`], [`KeyGenerationAlgorithm::EcP256`], [`KeyGenerationAlgorithm::EcP384`], [`KeyGenerationAlgorithm::EcP521`], [`KeyGenerationAlgorithm::Ed25519`] |
| [`RandomAlgorithm`] | [`RandomAlgorithm::SecureRandom`] |

[`Algorithm`] has one variant per category: [`Algorithm::Hash`], [`Algorithm::Mac`], [`Algorithm::PasswordKdf`], [`Algorithm::Kdf`], [`Algorithm::Cipher`], [`Algorithm::StreamCipher`], [`Algorithm::Aead`], [`Algorithm::KeyWrap`], [`Algorithm::Signature`], [`Algorithm::AsymmetricEncryption`], [`Algorithm::KeyAgreement`], [`Algorithm::PrivateKeyLoading`] carrying a [`KeyType`], [`Algorithm::KeyGeneration`], [`Algorithm::Random`], plus [`Algorithm::PublicKeyExport`] carrying a [`KeyType`].
[`Algorithm::PublicKeyExport`] is never a provider entry: it identifies [`PrivateKey::public_key`] in [`Error::Unsupported`], so that the error names the operation that is missing.

[`HashAlgorithm::output_len`] is a `const fn` giving the digest length (16, 16, 20, 28, 32, 48, 64, 48, 64 bytes in the order above); it is metadata, not an operation.

The algorithm set is the one picky, picky-krb and sspi-rs need: every algorithm has a consumer, and algorithms are not added because a library offers them.
picky's `ssh` and `putty` features also use three primitives that the contract does not define, for encrypted private keys: bcrypt-pbkdf, AES-CTR and Argon2.
Those features do not go through the provider; bringing them under it means adding these primitives as capabilities (section 3.1), with AES-CTR as a single transform because encryption and decryption are the same operation.

### 3.1 Extensibility

The contract can gain algorithms and capability categories without a breaking change:

- every algorithm enum, [`Algorithm`], [`Entry`], [`KeyType`], [`KeyOperation`], [`Protection`], [`Requirement`], [`PrivateKeyMaterial`], [`Error`] and [`BuildError`] is `#[non_exhaustive]`, so consumers and backends already match them with a wildcard arm;
- [`FfdhParameters`] and [`Sealed`] are `#[non_exhaustive]` and built with [`FfdhParameters::new`] and [`Sealed::new`] respectively; [`PublicKey`] is a tuple struct over one slice;
- a new capability is a new trait plus a new [`Entry`] and [`Algorithm`] variant; existing traits are untouched;
- an optional [`PrivateKey`] operation gets a default that returns [`Error::Unsupported`].

## 4. Errors

The error set is closed: only the contract defines variants, never a backend, and no backend type crosses the boundary.
[`Error`] and [`BuildError`] are `#[non_exhaustive]` (section 3.1).

| Variant | Meaning |
|---|---|
| [`Error::Unsupported`] with an [`Algorithm`] | The provider or key does not implement this algorithm, operation, size or parameter, or a policy refuses it (section 8.2). Data-dependent, never a panic. |
| [`Error::InvalidKey`] | Key material is malformed, of the wrong type or size for the algorithm, or rejected by the library's key validation. |
| [`Error::InvalidInput`] | A non-key input is malformed or out of range (except an RSA ciphertext value, see [`Error::VerificationFailed`]): IV or open nonce length, data length not a multiple of the block size, output length out of range, zero iterations, invalid peer public value. |
| [`Error::VerificationFailed`] | A signature does not verify, an AEAD tag or key-unwrap integrity check fails, or RSA decryption fails (invalid padding, or a modulus-length ciphertext whose value is not less than the modulus). It carries no reason, so the error does not reveal which check failed. |
| [`Error::ProviderFailure`] | The backend failed for a reason that does not depend on the inputs: device removed, OS error, RNG failure, PIN required. Details stay in the backend. |

[`BuildError`] is a separate closed type returned only by [`ProviderBuilder::build`]: [`BuildError::Duplicate`] naming the duplicated algorithm when two entries implement the same algorithm, [`BuildError::Mismatched`] naming the mismatched algorithm when an entry reports an algorithm that its [`Entry`] variant cannot implement, and [`BuildError::NoProtection`] naming the algorithm when a [`Mac`], [`Cipher`], [`Aead`] or [`KeyWrap`] entry supports neither protection (section 8).
[`install_default`] returns the rejected provider instead of an error value.

When both [`Error::InvalidKey`] and [`Error::InvalidInput`] could apply, report [`Error::InvalidKey`].
[`Error::ProviderFailure`] includes "PIN required", which callers therefore cannot distinguish from other device failures; this is a known limit of the closed set, to revisit if a consumer needs to prompt for a PIN.
Some libraries report a single opaque failure for verification; a backend on such a library may report [`Error::VerificationFailed`] for a public key it cannot use, including an RSA modulus outside its range.
Conformance tests therefore expect [`Error::InvalidKey`] for a malformed public key, and accept either the result expected for a key in the must-support set or [`Error::Unsupported`] for a well-formed public key outside it; for a backend on such a library they also accept [`Error::VerificationFailed`] in both cases.
For a public key in the must-support set with a wrong signature, they expect only [`Error::VerificationFailed`].

## 5. Encodings

There is one standard encoding per key type: the one the reference libraries import natively, among those that import that key type at all (handle-based APIs such as PKCS#11 import no software key natively).
Converting from any other representation (SPKI, JWK `n`/`e`, SSH mpints, PPK fields, raw EC scalars, RFC 5958 documents with version field 1 for RSA and EC) is format code and belongs above the contract.
In this document, "version 0" and "version 1" are the values of the PKCS#8 version field (RFC 5958 names them v1 and v2).

### 5.1 Public keys, including key-agreement peer keys

Public keys are the contents of the SPKI `subjectPublicKey` BIT STRING:

- RSA: PKCS#1 `RSAPublicKey` DER;
- EC P-256, P-384, P-521: the uncompressed SEC1 point (`0x04 || X || Y`);
- Ed25519 and X25519: the 32 raw bytes (RFC 8410).

[`PublicKey`] carries them for verification and encryption; key agreement takes the same bytes as `peer_public_key`.
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

[`PrivateKeyMaterial`] carries exactly one of [`PrivateKeyMaterial::Pkcs8`] (the PKCS#8 DER), [`PrivateKeyMaterial::X25519`] (the raw 32-byte scalar) and [`PrivateKeyMaterial::Ffdh`] (domain parameters and the private exponent).

The PKCS#8 encodings carry no `attributes` field.
A document with attributes is outside the valid domain, and consumers drop them above the contract.
As an exception to rule 4, whether a backend rejects such a document with [`Error::InvalidKey`] or loads it ignoring the attributes is implementation-defined, because some libraries skip attributes and rejecting them would require parsing in the adapter.

RSA and EC documents in RFC 5958 version 1 form are not accepted, because some libraries reject them; consumers convert them above the contract (set the version to 0 and drop the outer `publicKey`, keeping the public key inside `ECPrivateKey` for EC).
Ed25519 accepts both versions because generators differ in which they emit; a loader must accept version 1, and a loader that cannot compute the public key returns [`Error::Unsupported`] for version 0 (below).
X25519 and FFDH private keys are not PKCS#8 because the reference libraries do not import them from PKCS#8.
Static FFDH keys are needed, not only ephemeral ones, because some protocols (DPAPI) derive the private exponent.

When the optional public key is absent (EC without `publicKey`, Ed25519 version 0), a backend that can compute it does so; a backend that cannot returns [`Error::Unsupported`] naming [`Algorithm::PrivateKeyLoading`] and the key type.

When the public key is present, it must match the private key.
A mismatch is outside the valid domain and loading returns [`Error::InvalidKey`].
This prevents a backend from exporting a public key under which its signatures do not verify.
For Ed25519 the check also protects the private key: the signature equation hashes the public key, and signing with a mismatched public key can reveal the private key.
An EC key whose `ECPrivateKey` carries the optional `parameters` field must name the same curve as the outer `AlgorithmIdentifier`; a different curve is [`Error::InvalidKey`], so that every backend interprets the key the same way.
The reference software libraries perform these checks when they load PKCS#8.
A backend that cannot perform them natively, including by chaining public library functions (parsing with the library, deriving the public key with the library, comparing fixed-length bytes), does not advertise loading for that key type, rather than skipping a check.

X25519 follows RFC 7748 section 5: every 32-byte scalar and every 32-byte peer value is in the must-support set.
The scalar is clamped, the peer value's most significant bit is masked, and a non-canonical u-coordinate is processed as if reduced modulo p.
These are steps of the algorithm, performed by the library and never by the adapter, so static X25519 private keys accept any 32-byte scalar as stored.
A backend whose library requires the caller to clamp, mask or reduce does not advertise X25519.
The one rejected case is a peer value that yields an all-zero shared secret, which is [`Error::InvalidInput`] (section 6.11).

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

Each capability trait is object-safe and has three kinds of methods: an algorithm identity method (or [`PrivateKeyLoader::key_type`] for [`PrivateKeyLoader`]), a FIPS-reporting method (section 6.15), and the operations; [`Mac::supports`], [`Cipher::supports`], [`Aead::supports`] and [`KeyWrap::supports`] also report their entries' protections (section 8).
[`FfdhKeyAgreement`] has no identity method: its algorithm is always [`KeyAgreementAlgorithm::Ffdh`].
No capability trait method has a default implementation.

### 6.1 Hash ([`Hash`], [`HashContext`])

- [`Hash::start`] starts a context.
- [`HashContext::update`]: any number of calls, including zero, with any slice length including empty.
- [`HashContext::finish`] consumes the context and returns the digest, with the byte length given by [`HashAlgorithm::output_len`].

The interface is streaming only, because consumers hash unbounded inputs (a PKCS#12 MAC over the whole authenticated safe, Kerberos and GSS messages, CMS content) and some already hash incrementally.
A one-shot digest is a helper (section 10).

Algorithms: MD4 (RFC 1320), MD5 (RFC 1321), SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (FIPS 180-4), SHA3-384, SHA3-512 (FIPS 202).
Valid domain: total input up to 2^64 − 1 bits for SHA-1, SHA-224 and SHA-256 and 2^128 − 1 bits for SHA-384 and SHA-512 (FIPS 180-4), unlimited for SHA3; for MD4 and MD5, which encode the length modulo 2^64, the contract uses the same 2^64 − 1-bit limit.
Must support: total input up to 2^32 bytes; an entry whose library cannot hash that much must not be advertised.
Above 2^32 bytes and inside the valid domain, an entry may return [`Error::Unsupported`] where its library's own limit is reached.
Errors: [`Error::ProviderFailure`], [`Error::Unsupported`] as above, and [`Error::InvalidInput`] beyond the algorithm's limit.

### 6.2 MAC ([`Mac`], [`MacContext`], [`MacGeneration`], [`MacVerification`])

- [`Mac::start`], with `key` and `protection`: `key` of any length, including empty and longer than the hash block size, with RFC 2104 semantics; [`Error::Unsupported`] naming [`Algorithm::Mac`] and the entry's algorithm when [`Mac::supports`] is false for that protection (section 8).
- [`MacContext::update`]: as for hashes.
- [`MacContext::finish`] consumes the context and returns the full, untruncated tag in [`MacOutput`], an opaque, zeroizing backend-side carrier.
- [`MacGeneration::start`] and [`MacVerification::start`], with `mac` and `key`: call [`Mac::start`] as `mac.start(key, Protection::Apply)` and `mac.start(key, Protection::Process)` respectively.
  Both expose update methods ([`MacGeneration::update`], [`MacVerification::update`]) and consuming finish methods ([`MacGeneration::finish`], [`MacVerification::finish`]), returning [`MacTag`] for generation and [`MacVerifier`] for verification.
- [`MacVerifier::verify`]: compares the first `len` bytes of the tag with `expected` in constant time (best effort: Rust gives no constant-time guarantee).
  It returns false unless `expected.len() == len` and `1 <= len <= tag_len`, where `tag_len` is the full tag length.
  `len` comes from the protocol definition (for example 12 bytes for Kerberos HMAC-SHA1-96, 8 for NTLM checksums), never from the received message, so that a peer cannot shorten the comparison.
- [`MacTag::into_inner`] consumes the tag and returns the full tag in zeroizing storage, to emit a tag or derive from it.

[`MacTag`] and [`MacVerifier`] are wiped on drop, their [`Debug`](std::fmt::Debug) shows only the length, and their [`Clone`](std::clone::Clone) clones the zeroizing storage.
Neither implements [`Deref`](std::ops::Deref), [`AsRef`](std::convert::AsRef), [`Display`](std::fmt::Display) or comparison traits; [`MacTag`] only exposes bytes through [`MacTag::into_inner`], while [`MacVerifier`] only verifies.
[`MacOutput`] has length-only [`Debug`](std::fmt::Debug), no [`Clone`](std::clone::Clone) and no public byte access.
Only `picky-crypto` constructs [`MacTag`], [`MacVerifier`], [`MacGeneration`] and [`MacVerification`]; they have no public constructor from bytes.
The wrapping types and the verifier's comparison are implemented by `picky-crypto`, not by backends, and are not contract operations, so the minimality exceptions do not apply.

Valid domain: any key, and data such that every hash invocation of RFC 2104 (including the inner hash over the key block followed by the data, and the hashing of an over-long key) stays within the underlying hash's valid domain (section 6.1).
Must support: keys of 0 to 1024 bytes, and data as for hashes; an update that takes the total beyond the valid domain returns [`Error::InvalidInput`].

Algorithms: HMAC (RFC 2104, FIPS 198-1) with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
Generation and verification are separate operations, chosen at [`Mac::start`]: a composite entry must choose the serving member before processing data (section 8.1), and a policy may refuse generation while allowing verification (section 8.2).
A tag sent to a peer (a Kerberos checksum, a JWS HS256 signature, an NTLM signature) or used as key material comes from [`MacGeneration`] and is read with [`MacTag::into_inner`]; truncation is protocol code over those bytes.
A received tag is always checked with [`MacVerifier::verify`], the one way to check a MAC, with the protocol's `len`.
A backend never constructs [`MacTag`] or [`MacVerifier`], so a policy refuses generation by refusing [`Mac::start`] with `start(key, Protection::Apply)`.
The split governs which services a provider offers, which is what a policy approves; it is not a confidentiality boundary against the calling code, which holds the key.
Code that supplies its own [`Mac`] entry to [`MacGeneration`], or probes [`MacVerifier::verify`] with chosen prefixes, can obtain a verification tag's bytes, and such use is outside any approved service.
Entries are trusted to report and behave honestly, as for their FIPS reports and [`PrivateKey::key_size_bits`]: the contract does not defend against a dishonest entry.
Probing [`MacVerifier::verify`] is open only to the calling code; a remote party cannot use it as an oracle, because `len` comes from the protocol definition.

Exception 2: HMAC is derivable from the hash interface (key padding, inner and outer hash), but it is an approved algorithm that must run as a whole inside a validated module.

HMAC-MD5 is not offered: it is derivable from a [`Hash`] entry for [`HashAlgorithm::Md5`] and none of the exceptions applies, because MD5 is not approved and composing it costs nothing.
A protocol that needs HMAC-MD5 composes it from a [`Hash`] entry for [`HashAlgorithm::Md5`] in its own code, so it is unavailable exactly when MD5 is.
The construction is MD5-only: a generic HMAC over any hash would be a second HMAC-SHA path outside the validated module.

### 6.3 Password-based KDF ([`PasswordKdf`])

[`PasswordKdf::derive`], with inputs `password`, `salt`, `iterations` and `output_len`: PBKDF2 (RFC 8018 section 5.2) with HMAC-SHA-x as PRF.

Valid domain: any password and salt, `iterations >= 1`, `1 <= output_len <= (2^32 − 1) × hLen` (RFC 8018 section 5.2, step 1).
Must support: password and salt of 0 to 1024 bytes, `iterations` 1 to 10 000 000, `output_len` 1 to 1024.
`iterations == 0`, `output_len == 0` or `output_len` above the RFC 8018 maximum: [`Error::InvalidInput`].

Exception 2: PBKDF2 is derivable from HMAC, but it is an approved KDF that must run as a whole inside a validated module.

### 6.4 Key-based KDF ([`Kdf`])

[`Kdf::derive`], with inputs `secret`, `fixed_info` and `output_len`.

| Algorithms | Definition |
|---|---|
| [`KdfAlgorithm::OneStepSha1`], [`KdfAlgorithm::OneStepSha256`], [`KdfAlgorithm::OneStepSha384`], [`KdfAlgorithm::OneStepSha512`] | NIST SP 800-56C rev. 2 section 4.1, option 1: `K(i) = H(counter_i \|\| Z \|\| OtherInfo)` with a 32-bit big-endian counter starting at 1; `secret` = Z, `fixed_info` = OtherInfo (opaque); output truncated to `output_len` |
| [`KdfAlgorithm::CounterHmacSha1`], [`KdfAlgorithm::CounterHmacSha256`], [`KdfAlgorithm::CounterHmacSha384`], [`KdfAlgorithm::CounterHmacSha512`] | NIST SP 800-108 rev. 1 section 4.1, counter mode, PRF = HMAC-SHA-x: `K(i) = PRF(K_IN, [i]_32 \|\| FixedInfo)` with a 32-bit big-endian counter starting at 1 placed before the fixed input; `secret` = K_IN, `fixed_info` = the complete fixed input data (the caller encodes label, separator, context and length in it); output truncated to `output_len` |

Valid domain: `secret` of at least 1 byte, any `fixed_info`, `output_len` from 1 to `(2^32 − 1) × hash length`.
Must support: `secret` 1 to 1024 bytes, `fixed_info` 0 to 1024 bytes, `output_len` 1 to 64.
Empty `secret`, `output_len == 0`, or `output_len` above the valid domain: [`Error::InvalidInput`].

The counter-mode KDF takes the complete fixed input because its layout belongs to the protocol (for example, the MS-GKDI layout `Label || 0x00 || Context || [L]_32` is DPAPI format code).
A library that only builds its own fixed-input layout from a label and a context cannot implement this operation and reports [`Error::Unsupported`].

Exception 2: both KDFs are derivable from the hash and MAC interfaces, but they are approved KDFs.
Composed above the contract, they would run outside the validated module and be invisible to policy and to availability checks.
Where a backend's library lacks them, a provider that builds them from another provider's entries supplies them, reporting false through [`CryptoProvider::fips`] (section 11): the one-step KDF from [`Hash`] entries, and the counter-mode KDF from [`Mac`] entries, taking each PRF block from a [`MacGeneration`] with [`MacTag::into_inner`] and requiring [`Protection::Apply`].
A policy judges [`Kdf`] entries by the rules for KDFs, independently of the [`Mac`] entries they build on.

### 6.5 Unauthenticated block cipher modes ([`Cipher`])

[`Cipher::encrypt`] and [`Cipher::decrypt`]: one-shot CBC (NIST SP 800-38A) without padding; the output has the same length as the input.
The entry reports its protections through [`Cipher::supports`] (section 8).

| Algorithm | Key | IV | Data |
|---|---|---|---|
| [`CipherAlgorithm::Aes128Cbc`], [`CipherAlgorithm::Aes192Cbc`], [`CipherAlgorithm::Aes256Cbc`] | 16, 24, 32 bytes respectively | 16 bytes | multiple of 16 bytes, may be empty |
| [`CipherAlgorithm::TdesEde3Cbc`] | 24 bytes (three DES keys, parity bits ignored) | 8 bytes | multiple of 8 bytes |
| [`CipherAlgorithm::Rc2Cbc`] | 1 to 128 bytes, must support 5 to 16 | 8 bytes | multiple of 8 bytes |

RC2's effective key bits (RFC 2268 `T1`) always equal 8 × the key length; every backend sets that parameter explicitly, never the library's default.
Wrong key length: [`Error::InvalidKey`]; wrong IV or data length: [`Error::InvalidInput`].
Every 24-byte 3DES key is in the must-support set, except two cases where, as an exception to rule 4, rejecting the key with [`Error::InvalidKey`] is implementation-defined, because some libraries refuse them: component keys that are not pairwise distinct (keying option 1 of NIST SP 800-67 requires three distinct keys), and component keys that are among the DES weak or semi-weak keys listed in NIST SP 800-67.
Must support: data up to 2^31 − 1 bytes.

Padding is above the contract: PKCS#7 padding (PKCS#12 PBES1 and PBES2) and Kerberos ciphertext stealing are consumer code; CBC decryption of padded data returns the padded plaintext.

These modes are not derivable from other operations: no other operation exposes the AES, 3DES or RC2 block function.
Conversely, a single-block CBC call with a zero IV is a raw block operation; Kerberos ciphertext stealing and RFC 3961 key derivation use exactly that, and it is why the AES modes below carry exception notes.

### 6.6 Stream cipher ([`StreamCipher`], [`StreamCipherContext`])

- [`StreamCipher::start`]: RC4 with `key`.
- [`StreamCipherContext::apply`]: XORs `data` with the next `data.len()` keystream bytes; the state carries over to the next call.

Valid domain: keys of 1 to 256 bytes, any data.
Must support: keys of 5 to 256 bytes.

The context is stateful because NTLM seals successive messages with one continuing RC4 keystream per direction.
There is no state cloning: computing an NTLM MIC without advancing the state is done by restarting from the key and discarding the bytes already processed, so there is one way to reach a keystream position.

### 6.7 AEAD ([`Aead`])

- [`Aead::seal`]: returns a [`Sealed`] with the generated [`Sealed::nonce`] and [`Sealed::ciphertext_and_tag`] (`ciphertext || tag`), named so that the two buffers cannot be swapped by position.
- [`Aead::open`]: returns the plaintext, or [`Error::VerificationFailed`] without releasing any plaintext.

The entry reports its protections through [`Aead::supports`] (section 8).

AES-GCM (NIST SP 800-38D): the key is exactly 16, 24 or 32 bytes for [`AeadAlgorithm::Aes128Gcm`], [`AeadAlgorithm::Aes192Gcm`] and [`AeadAlgorithm::Aes256Gcm`] respectively ([`Error::InvalidKey`] otherwise); the generated seal nonce and the open nonce are exactly 12 bytes; the tag is exactly 16 bytes.
Must support: plaintext up to 2^31 − 17 bytes, so that `ciphertext || tag` fits in 2^31 − 1 bytes, within the 32-bit [`isize::MAX`] allocation-size limit, and AAD up to 2^31 − 1 bytes (some handle-based APIs take the AAD length as a 32-bit integer).
[`Aead::open`] input shorter than 16 bytes: [`Error::InvalidInput`].
A detached tag (as in JOSE) is split and joined above the contract.

The backend's library generates the seal nonce from its own secure random generator, never from caller input or a [`SecureRandom`] entry passed in (rule 5).
Chaining the library's own nonce generation or RNG with its seal is argument mapping.
A backend whose library is a FIPS module seals only through the module's internal IV generation (NIST SP 800-38D section 8.2.2).
An IV passed into the module from outside, even one the module generated, is an external IV.
The contract requires internal generation because whether a module approves an external IV depends on its validated configuration (SP 800-38D section 8.2.2); the AWS-LC FIPS module, for example, approves AES-GCM encryption only with an internally generated IV.
A backend whose library cannot seal a key size through the required nonce generation reports `supports(Protection::Apply) == false` through [`Aead::supports`] for that algorithm and keeps open.
For example, aws-lc-rs's `RandomizedNonceKey` has no AES-192-GCM, so that entry reports only [`Protection::Process`] in every build of the adapter.

With random 96-bit nonces, a key must be used for at most 2^32 seal calls (NIST SP 800-38D section 8.3).
The backend keeps no per-key state and cannot count calls, so the caller enforces this limit.
Generating the nonce removes caller-controlled nonce reuse, GCM's main failure mode.
A protocol needing a caller-chosen seal nonce (for example `aes256-gcm@openssh.com`) requires a separate, explicitly non-approved capability through a contract change; adding a capability is non-breaking (section 3.1).

Exception 2 and 3: GCM is derivable from single-block AES-CBC calls plus GHASH arithmetic above the contract.
It is an approved mode that must run as a whole inside a validated module, including internal IV generation under exception 2, and the backend provides constant-time GHASH and releases no plaintext before the tag is checked.

### 6.8 Key wrap ([`KeyWrap`])

- [`KeyWrap::wrap`]: wraps `key_data` using RFC 3394 with the default IV `A6A6A6A6A6A6A6A6`; the output is 8 bytes longer.
- [`KeyWrap::unwrap`]: unwraps `wrapped`, with [`Error::VerificationFailed`] if the integrity check fails.

The entry reports its protections through [`KeyWrap::supports`] (section 8).

KEK: exactly 16, 24 or 32 bytes for [`KeyWrapAlgorithm::Aes128Kw`], [`KeyWrapAlgorithm::Aes192Kw`] and [`KeyWrapAlgorithm::Aes256Kw`] respectively ([`Error::InvalidKey`] otherwise); the wrapped `key_data` length is independent of the KEK size.
Valid domain and must-support set (they coincide): `key_data` of 16, 24 or 32 bytes, so `wrapped` of 24, 32 or 40 bytes.
[`KeyWrap::wrap`] with another `key_data` length, or [`KeyWrap::unwrap`] with another `wrapped` length: [`Error::InvalidInput`], checked before any cryptographic processing.
[`KeyWrap::unwrap`] returns 16, 24 or 32 bytes; RFC 3394 values of other lengths are outside the contract even when their integrity check would pass.
Consumers wrap only AES content-encryption keys (JOSE, DPAPI), and some handle-based APIs wrap only key objects that are valid AES keys.

Exception 2 and 3: AES-KW is derivable from single-block AES-CBC calls (the RFC 3394 loops).
It is an approved mode (NIST SP 800-38F) that must run inside a validated module, and the integrity check stays inside the backend.

### 6.9 Signature verification ([`SignatureVerifier`])

[`SignatureVerifier::verify`]: the message is passed, never a digest, because some libraries cannot verify a precomputed digest.

| Algorithm | Definition | Must support |
|---|---|---|
| [`SignatureAlgorithm::RsaPkcs1v15Md5`], [`SignatureAlgorithm::RsaPkcs1v15Sha1`], [`SignatureAlgorithm::RsaPkcs1v15Sha224`], [`SignatureAlgorithm::RsaPkcs1v15Sha256`], [`SignatureAlgorithm::RsaPkcs1v15Sha384`], [`SignatureAlgorithm::RsaPkcs1v15Sha512`], [`SignatureAlgorithm::RsaPkcs1v15Sha3_384`], [`SignatureAlgorithm::RsaPkcs1v15Sha3_512`] | RFC 8017 RSASSA-PKCS1-v1_5 with the named hash and its DigestInfo | modulus 2048 to 4096 bits, public exponent 65537 |
| [`SignatureAlgorithm::EcdsaP256Sha256`], [`SignatureAlgorithm::EcdsaP384Sha384`], [`SignatureAlgorithm::EcdsaP521Sha512`] | FIPS 186-5 ECDSA with the named curve and hash, fixed `r \|\| s` | valid public points of the curve |
| [`SignatureAlgorithm::Ed25519`] | RFC 8032 pure Ed25519 | valid public keys |

Valid domain: public key bytes in the encoding of section 5.1 and any signature bytes; a key that does not decode as the algorithm's key type in that encoding, including a compressed EC point, is [`Error::InvalidKey`] (or [`Error::VerificationFailed`] on a library with a single opaque failure, section 4).

Acceptance profile:

- RSA: signatures are generated with the DigestInfo of RFC 8017 appendix A.2.4 with NULL parameters, for every hash; for SHA3-384 and SHA3-512 the hash OIDs are `2.16.840.1.101.3.4.2.9` and `2.16.840.1.101.3.4.2.10`.
  Whether a verifier also accepts a DigestInfo with absent parameters is not specified.
  RFC 9688 requires absent parameters for `id-sha3-*` AlgorithmIdentifiers in CMS fields; that is format code above the contract and does not concern the EMSA-PKCS1-v1_5 DigestInfo.
- ECDSA: every signature valid under FIPS 186-5 verifies, whether `s` is low or high: there is no normalization, which some protocols (for example Bitcoin) add on top of ECDSA.
  `r` or `s` equal to zero or not less than the group order is [`Error::VerificationFailed`].
- Ed25519: every signature valid under RFC 8032 section 5.1.7 with canonical `S < L` and canonical encodings of `A` and `R` verifies.
  Malformed inputs are errors: `S >= L`, an `R` that fails RFC 8032 section 5.1.3 decoding, or a wrong signature length is [`Error::VerificationFailed`]; an `A` that fails that decoding is [`Error::InvalidKey`] or [`Error::VerificationFailed`] (section 4).
  Verification with a validly encoded small-order `A` or `R` is implementation-defined (cofactored or cofactorless equation); backends may disagree on it, so differential tests exclude these inputs and conformance tests check the allowed outcomes listed in section 12.

Result: `Ok(())`; [`Error::VerificationFailed`] for a signature that does not verify, including a wrong length; [`Error::InvalidKey`] for a key that is not a valid key of the expected type, with the opaque-failure tolerance of section 4.

### 6.10 Asymmetric encryption ([`AsymmetricEncryptor`])

[`AsymmetricEncryptor::encrypt`].

| Algorithm | Definition |
|---|---|
| [`AsymmetricEncryptionAlgorithm::RsaPkcs1v15`] | RFC 8017 RSAES-PKCS1-v1_5 |
| [`AsymmetricEncryptionAlgorithm::RsaOaepSha1`] | RFC 8017 RSAES-OAEP, hash SHA-1, MGF1-SHA-1, empty label |
| [`AsymmetricEncryptionAlgorithm::RsaOaepSha256`] | RFC 8017 RSAES-OAEP, hash SHA-256, MGF1-SHA-256, empty label |

Valid domain: any public key bytes ([`Error::InvalidKey`] if they do not decode as an RSA key), and plaintext up to the algorithm's limit for the modulus (`k − 11` bytes for PKCS#1 v1.5, `k − 2·hLen − 2` for OAEP).
Must support: modulus 2048 to 4096 bits with public exponent 65537.
Plaintext too long for the modulus: [`Error::InvalidInput`].
Decryption is [`PrivateKey::decrypt`] (section 7).

### 6.11 Key agreement ([`KeyAgreement`], [`FfdhKeyAgreement`], [`EphemeralSecret`])

Ephemeral agreement:

- [`KeyAgreement::generate_ephemeral`] for [`KeyAgreementAlgorithm::EcdhP256`], [`KeyAgreementAlgorithm::EcdhP384`], [`KeyAgreementAlgorithm::EcdhP521`], [`KeyAgreementAlgorithm::X25519`];
- [`FfdhKeyAgreement::generate_ephemeral`] with `parameters` for [`KeyAgreementAlgorithm::Ffdh`] (its algorithm is always [`KeyAgreementAlgorithm::Ffdh`]);
- [`EphemeralSecret::public_key`]: section 5.3 encoding;
- [`EphemeralSecret::agree`] consumes the secret to agree with `peer_public_key`: single use.

Static agreement is [`PrivateKey::agree`] (section 7) on a key loaded by [`PrivateKeyLoader`].

Shared secret encoding:

- ECDH (SEC1 section 3.3.1): the x-coordinate as a big-endian octet string of the field size (32, 48, 66 bytes).
- X25519: the 32-byte output of RFC 7748 `X25519(k, u)` as an octet string, unmodified.
  An all-zero output is [`Error::InvalidInput`] (RFC 7748 section 6.1); every other 32-byte peer value is processed as section 5.2 states, including values on the twist and non-canonical values.
- FFDH: `y_peer^x mod p` as an unsigned big-endian integer left-padded to the byte length of `p` (the PKINIT `DHSharedSecret` form, RFC 4556 section 3.2.3.1).

Reversing a fixed-width secret is argument mapping: a backend whose library returns the secret little-endian reverses it.

Invalid peer value (for ECDH: not on the curve, wrong length or the identity; for X25519: a length other than 32 bytes or an all-zero shared secret; for FFDH: a value outside the range below): [`Error::InvalidInput`].

#### FFDH parameters and checks

FFDH domain parameters are carried by [`FfdhParameters`], with [`FfdhParameters::p`], [`FfdhParameters::g`] and optional [`FfdhParameters::q`], and built with [`FfdhParameters::new`].
Parameters, private values and public values are unsigned big-endian integers.
Leading zero bytes are accepted and ignored, but no encoding may be longer than the byte length of `p` plus one byte, so that its length is bounded by the group rather than by the input; an empty or longer encoding is invalid.
"The byte length of `p`" means `ceil(bit_length(p) / 8)` after leading zeros are ignored; it fixes the width of ephemeral public values, shared secrets and [`helpers::ffdh_public_value`].
The parameters are arbitrary rather than named groups, because consumers take them from the protocol: PKINIT and PKU2U requests carry X9.42 domain parameters, and DPAPI takes the group from the key distribution service.

Valid domain (checks every backend performs):

- `p`: odd, at least 1024 bits;
- `g`: `1 < g < p − 1`;
- `q`, when given: `5 <= q < p`;
- static private value `x`: `1 <= x <= q − 1` when `q` is given, otherwise `1 <= x <= q' − 1` with `q' = (p − 1) / 2`; it is not reduced;
- peer public value `y_peer`: `1 < y_peer < p − 1`, and `y_peer^q mod p == 1` when `q` is given.

Parameters or private values outside the valid domain return [`Error::InvalidKey`] when loading ([`PrivateKeyLoader::load`] for [`KeyType::Ffdh`]) and [`Error::InvalidInput`] when generating an ephemeral secret; a peer value outside it returns [`Error::InvalidInput`].
Checks are never skipped: a library that cannot perform these checks for every input in the must-support set cannot back an advertised FFDH entry.
Secret values (the private exponent and the shared secret) are handled without variable-time operations, including in range checks, conversions and serialization.
Trusted, unchecked properties: `p` and `q` are prime, and `g` generates a subgroup of large order (of order `q` when `q` is given).
When `q` is absent, the backend cannot check that `y_peer` lies in `g`'s subgroup, and its range check excludes only the trivial elements `1` and `p − 1`.
If `p − 1` has other small factors, a peer can then send a value of small order and learn information about a reused static exponent.
Supplying `q` (or using a safe prime, whose only small subgroups have order 1 or 2) is therefore the protocol's responsibility whenever a static exponent is used with untrusted peers.
DPAPI, for example, receives its group (RFC 5114 section 2.3) without `q` from the key distribution service.
Trusting the group source does not make peer values trustworthy, so such a protocol accepts that risk for its static exponents.
Checking the trusted properties is the protocol's responsibility; with parameters that violate them the outputs are unspecified, but there is no panic.
Must support: `p` of 1024, 2048, 3072 and 4096 bits; other sizes may be [`Error::Unsupported`] (rule 4).

An ephemeral private exponent is generated as in NIST SP 800-56A rev. 3 section 5.6.1.1.4 (key-pair generation by testing candidates) with `N = len(q)`, the bit length of `q` after leading zeros are ignored: `x` is uniform in `[1, q − 1]`, drawn from the backend's own secure random generator.
When `q` is absent, `q' = (p − 1) / 2` takes its place (with `N = len(q')`), as for the safe-prime groups of section 5.6.1.1.1 (the RFC 2409 and RFC 3526 groups used with PKINIT are safe primes).
For a group without `q` whose prime is not safe, this range is the contract's own choice rather than the cited procedure, and it relies on the trusted property that `g` generates a subgroup of large order.
This distribution is checked by review; conformance tests check the range of the public value and the round trip.
FFDH with arbitrary groups is not FIPS-approved.

Exception 3 for ephemeral agreement: it is derivable by producing a private key outside the backend (key generation for EC, the [`helpers::random_x25519_private_key`] helper for X25519, exponent sampling for FFDH), loading it, obtaining the public value and calling [`PrivateKey::agree`].
That route serializes the private key, whereas the ephemeral route keeps it inside the backend; some libraries offer only the ephemeral route.
Static agreement is needed for decryption (the JOSE ECDH-ES recipient, DPAPI) and is not derivable from the ephemeral route.

### 6.12 Private key loading ([`PrivateKeyLoader`])

[`PrivateKeyLoader::load`]: one loader per [`KeyType`], section 5.2 encoding.
The loader checks that the material matches its key type ([`Error::InvalidKey`] otherwise), and that an embedded public key matches the private key (section 5.2).

Loading does not select a signature algorithm.
A backend whose library binds the algorithm when it creates a key object (some bind curve, hash and signature format for ECDSA) keeps the encoded key and creates the library object per algorithm; each EC key type has exactly one signature algorithm in the contract, so this is never ambiguous.

### 6.13 Key generation ([`KeyGenerator`])

[`KeyGenerator::generate`]: a fresh key in the section 5.2 PKCS#8 encoding.
RSA uses public exponent 65537 and the modulus size in the algorithm name, with two primes of half the modulus size.
EC output includes the public key in `ECPrivateKey`.
Ed25519 output is version 1 (RFC 5958 `OneAsymmetricKey` v2) with the outer `publicKey`, so that every loader can load a generated key, including loaders that cannot compute the public key from the seed.
The three RSA sizes are those every generating library supports.

There is no X25519 key generation: an X25519 private key is 32 bytes from [`SecureRandom`] with RFC 7748 section 5 clamping applied.
Clamping clears bits 0, 1, 2 of the first byte and bit 7 of the last byte, and sets bit 6 of the last byte.
The helper [`helpers::random_x25519_private_key`] (section 10) performs these steps.
Clamping does not change the key, because X25519 clamps when decoding.
There is no FFDH key generation: FFDH keys are ephemeral (section 6.11) or derived by the protocol (DPAPI).

Key generation is optional like every capability: a provider whose keys cannot be exported (hardware) does not advertise it.
Hardware key generation, which yields a handle rather than an encoding, is not part of the contract.

Exception 2 and 3 for EC and Ed25519: generation is derivable as random bytes, format code and loading (when the loader computes the public key).
Key generation must run inside a validated module (FIPS 186-5, SP 800-133), and the secret stays inside the backend until it is deliberately exported.
RSA generation is not derivable, because the contract offers no primality testing.

### 6.14 Random ([`SecureRandom`])

[`SecureRandom::fill`]: fills `dest` from a cryptographically secure generator (an OS CSPRNG or an SP 800-90A DRBG); [`Error::ProviderFailure`] if it fails.
A provider has at most one [`SecureRandom`] entry ([`RandomAlgorithm::SecureRandom`]).
Integers in a range, protocol nonces other than AEAD seal nonces (section 6.7), confounders and salts are built on top by consumers.

### 6.15 FIPS reports

Every entry's FIPS report is true only if its operations run inside a FIPS 140 module, built as that module and running in FIPS mode.
For aws-lc-rs this is the runtime answer of `aws_lc_rs::try_fips_mode()` in its FIPS build, never a crate feature flag.
`false` means "not positively established": RustCrypto and ring entries always return false, and so do backends that cannot establish the module's status at runtime.
The FIPS report describes how the module was built and is running, not certification: whether a deployed binary matches a CMVP certificate and its operating environment is established outside the program.
It is an input to policy, never a capability query.

## 7. Private keys ([`PrivateKey`])

[`PrivateKey`] is the trait object for any private key: keys loaded by a provider, and hardware or external keys (PKCS#11 smartcards, CNG/NCrypt keys, TPM) that implement it directly without a provider.

| Method | Default | Semantics |
|---|---|---|
| [`PrivateKey::key_type`] | required | The key's type. |
| [`PrivateKey::key_size_bits`] | required | The key size in bits, as defined below; cheap, infallible and never accesses a device (rule 7). |
| [`PrivateKey::supports`] | required | Whether the key implements `operation` ([`KeyOperation::Sign`], [`KeyOperation::Decrypt`] or [`KeyOperation::Agree`] with the operation's algorithm, or [`KeyOperation::PublicKey`]) over that operation's must-support set. Never performs the operation (no PIN prompt, no device access beyond cached capabilities). |
| [`PrivateKey::fips`] | required | As in section 6.15, for this key's operations. A key loaded by a provider entry reports that entry's [`PrivateKeyLoader::fips`]. A hardware key reports true only if every computation of its operations runs in a module whose status is established for the deployment (the token, by configuration or attestation, and, when it hashes in software, the [`Hash`] entry it uses), false otherwise. |
| [`PrivateKey::sign`] | [`Error::Unsupported`] | Section 6.9 algorithms; the message is passed and the key hashes it; output encoding per section 5.4. |
| [`PrivateKey::decrypt`] | [`Error::Unsupported`] | Section 6.10 algorithms. A modulus-length ciphertext whose integer value is not less than the modulus, and any padding or OAEP failure, is [`Error::VerificationFailed`] (RFC 8017 sections 7.1.2 and 7.2.2 treat both as a decryption error; one error for all, so the error does not reveal which check failed). Ciphertext length other than the modulus length: [`Error::InvalidInput`]. |
| [`PrivateKey::agree`] | [`Error::Unsupported`] | Static agreement, encodings per section 6.11. |
| [`PrivateKey::public_key`] | [`Error::Unsupported`] naming [`Algorithm::PublicKeyExport`] and the key type | Optional. The `subjectPublicKey` contents of the matching public key (section 5.1 encoding; 32 bytes for X25519). Not offered for FFDH keys, whose public value is [`PrivateKey::agree`] with `agree(Ffdh, g)` (the helper [`helpers::ffdh_public_value`], section 10). |

When [`PrivateKey::supports`] returns false, the operation always returns [`Error::Unsupported`]: algorithms that do not match the key's type and algorithms its implementation does not offer.
When it returns true, the operation is available over its must-support set, subject to policy narrowing (section 8.2).
Inputs inside the valid domain but outside the must-support set may still return [`Error::Unsupported`] (rule 4).
Cryptographically invalid inputs still fail with the specified error (for example [`Error::VerificationFailed`] for a modulus-length ciphertext with invalid padding).
[`PrivateKey::supports`] is how private-key availability is queried per algorithm: provider entries advertise verification, encryption, ephemeral agreement and loading, and a key advertises its own signing, decryption, static agreement and public-key export.
Conformance tests check every [`KeyOperation`] on unwrapped keys.
When [`PrivateKey::supports`] is false, the operation returns [`Error::Unsupported`].
When [`PrivateKey::supports`] is true, valid known-answer and round-trip cases succeed, no must-support input returns [`Error::Unsupported`], and invalid inputs return the specified error.
RSA keys with inconsistent components are checked as section 12 states.

[`PrivateKey::key_size_bits`] reports:

- RSA: the exact bit length of the modulus `n`, never a byte length times 8; a backend whose library returns only the modulus bytes measures their bit length, which is argument mapping (`INTENT.md`, "Design principle");
- EC P-256, P-384, P-521: the bit length of the curve's field prime, respectively 256, 384, 521;
- Ed25519 and X25519: 255, the bit length of the field prime 2^255 − 19;
- FFDH: the bit length of `p` after leading zeros are ignored (section 6.11).

A key type without a meaningful size returns 0, which every minimum-size check refuses.
There is no such type in the current [`KeyType`] set, but the enum is `#[non_exhaustive]`.
A hardware key reads its size when constructed and caches it like its capabilities.
This metadata lets policy restrict provider-loaded and hardware keys by size without exporting them.

Valid domain and must-support set:

- [`PrivateKey::sign`] and [`PrivateKey::decrypt`] with RSA: must support 2048, 3072 and 4096-bit two-prime keys with equal-size primes and public exponent 65537; other valid RSA keys may be refused at loading with [`Error::Unsupported`].
- [`PrivateKey::sign`]: any message; [`PrivateKey::decrypt`]: ciphertext exactly as long as the modulus.
- [`PrivateKey::agree`]: section 6.11.

RSASSA-PKCS1-v1_5 signatures always encode NULL DigestInfo parameters (section 6.9).

RSA private-key results are checked: every signature or plaintext is the correct result under the key's public components (`n`, `e`), or the operation fails.
A backend never outputs a signature or plaintext computed from inconsistent key components, because a single faulty CRT signature reveals a prime factor of `n`.
Handling an RSA private key with inconsistent components (wrong `dP`, `dQ`, `qInv` or `d`) is implementation-defined.
It may be rejected at loading with [`Error::InvalidKey`], rejected at the first private-key operation with [`Error::InvalidKey`], or used with components the library recomputes from `n`, `e`, `d`, `p` and `q`.
Every one of these outcomes satisfies the property above.
This is an exception to rule 4, which would otherwise require rejection at loading.
An inconsistency detected during [`PrivateKey::sign`] or [`PrivateKey::decrypt`] returns [`Error::InvalidKey`], never the padding error [`Error::VerificationFailed`].
Conformance tests check these keys only as section 12 states.

Derivability:

- RSA signing and decryption are not derivable: the contract offers no raw RSA operation, because a raw primitive would let callers build arbitrary padding schemes, including insecure ones.
- [`PrivateKey::public_key`] for X25519 is derivable through [`PrivateKey::agree`] as `agree(X25519, base point 9)`.
  Exception 3: a key may allow exporting its public key without allowing agreement (key-use restriction).
  For FFDH the same derivation has no such restriction, so FFDH keys do not offer [`PrivateKey::public_key`].
  For RSA, EC and Ed25519 it is not derivable.
- [`PrivateKey::public_key`] is optional because callers that hold a certificate do not need it, and handle-based keys cannot always return the encoding natively.

### 7.1 Hardware keys

A hardware key implements [`PrivateKey`] directly.
A PKCS#11 smartcard key implements [`PrivateKey::sign`] with the token's hash-and-sign mechanism on the message (`CKM_SHA1_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_ECDSA_SHA256`, ...).
A token that offers `CKM_ECDSA` together with token-side hashing can hash on the token (`C_Digest`, then `C_Sign` on the digest).

A token that offers only `CKM_RSA_PKCS`, or `CKM_ECDSA` without token-side hashing, is handled inside the hardware key implementation: it hashes the message and, for RSA, adds the algorithm-constant DigestInfo prefix, then calls the token.
This is acceptable inside a hardware key implementation because the contract passes the message, so hashing is the key's implementation detail.
The hash comes from the contract, never from a crypto library: the key implementation is constructed with a [`CryptoProvider`] (normally the installed default) and uses its [`Hash`] entry, so policy applied to that provider governs it.
If that provider lacks the hash, [`PrivateKey::supports`] is false for [`KeyOperation::Sign`] with that algorithm and [`PrivateKey::sign`] returns [`Error::Unsupported`].
A CNG/NCrypt key hashes and calls `NCryptSignHash` in the same way.

Restricting a hardware key under a policy (section 8.2) filters its operations and key size; it does not change the provider the key was constructed with, so a FIPS binary constructs hardware keys with its FIPS provider.
A binary using hardware keys composes its provider with a software fallback for the operations the token does not offer (for example verification); under FIPS, that fallback must itself be a FIPS provider behind the FIPS policy, because verification is a cryptographic service like any other.

## 8. Provider value

[`CryptoProvider`] is an immutable set of [`Entry`] values with at most one entry per [`Algorithm`].
[`Entry`] is a `#[non_exhaustive]` enum with one variant per capability trait, each holding an [`Arc<dyn Trait>`](std::sync::Arc).
Entries are [`Arc`](std::sync::Arc)s rather than `&'static` references, so that a provider can be composed at runtime from entries of other providers (fallback, policy, providers built from another provider's entries) without leaking memory.
Storage is private.

- [`CryptoProvider::builder`]: the only way to start a provider.
- [`ProviderBuilder::with`]: the only way to add an entry.
- [`ProviderBuilder::build`]: fails with [`BuildError::Duplicate`] naming the duplicated algorithm if two entries report the same algorithm, [`BuildError::Mismatched`] naming the mismatched algorithm if an entry reports an algorithm that its [`Entry`] variant cannot implement, and [`BuildError::NoProtection`] naming the algorithm if a [`Mac`], [`Cipher`], [`Aead`] or [`KeyWrap`] entry supports neither protection.
  Each [`Entry`] variant's trait returns its own per-category enum, so only one mismatch is possible: [`KeyAgreement`] and [`FfdhKeyAgreement`] share [`KeyAgreementAlgorithm`], and a [`KeyAgreement`] entry reporting [`KeyAgreementAlgorithm::Ffdh`] is rejected.
  Without that check, [`CryptoProvider::get`] would report FFDH as available while [`helpers::ffdh_key_agreement`] returned [`Error::Unsupported`].
  Every other variant has its own algorithm enum (or [`KeyType`] for [`PrivateKeyLoader`]), and [`Algorithm::PublicKeyExport`] is never produced by an entry, so no other overlap exists.
- [`CryptoProvider::get`]: lookup by `algorithm`.
- [`CryptoProvider::fips`] and [`CryptoProvider::with_fallback`]: section 8.1.
- [`CryptoProvider::entries`]: iteration in unspecified order.
  It is not derivable from [`CryptoProvider::get`], because consumers cannot enumerate a `#[non_exhaustive]` algorithm set; policy and composition need it.

For [`CryptoProvider::get`], `get(algorithm).is_some()` means that the entry exists and performs at least one operation, not necessarily every operation of its trait.
For entries other than [`Mac`], [`Cipher`], [`Aead`] and [`KeyWrap`], including loading, presence also means that every operation of the trait is advertised (rule 3).
A provider never consults another provider implicitly.

[`Mac::supports`], [`Cipher::supports`], [`Aead::supports`] and [`KeyWrap::supports`] must report whether the requested `protection` is supported, with no default implementation and the metadata guarantees of rule 7.
[`Protection`] follows NIST SP 800-131A Rev. 2 section 1.2.3: "applying cryptographic protection" versus "processing already protected information".

| Capability | [`Protection::Apply`] | [`Protection::Process`] |
|---|---|---|
| [`Mac`] | tag generation | tag verification |
| [`Cipher`] | [`Cipher::encrypt`] | [`Cipher::decrypt`] |
| [`Aead`] | [`Aead::seal`] | [`Aead::open`] |
| [`KeyWrap`] | [`KeyWrap::wrap`] | [`KeyWrap::unwrap`] |

Signatures already separate the two: signing is a private-key operation (section 7), and verification is a provider entry.
Hashes, KDFs, random generation and key agreement have no protection.
Unlike [`KeyOperation`], which includes an algorithm because a private key serves several algorithms, [`Protection`] names only the protection because an entry has one algorithm.
When `supports(protection)` is false, that operation ([`Mac::start`] with `start(key, protection)` for [`Mac`]) returns [`Error::Unsupported`] naming the algorithm for every input.
When it is true, rule 3 applies to that operation.
A directional entry supports at least one protection: [`ProviderBuilder::build`] rejects an entry that supports neither with [`BuildError::NoProtection`] naming the algorithm.

Provider-level availability is checked with [`helpers::missing`] (section 10), which reports every unmet requirement in `required`:

- [`Requirement::Algorithm`] with an algorithm requires an entry that performs every operation of its trait, including both protections for [`Mac`], [`Cipher`], [`Aead`] and [`KeyWrap`];
- [`Requirement::Mac`], [`Requirement::Cipher`], [`Requirement::Aead`] and [`Requirement::KeyWrap`], each with an algorithm and protection, require an entry that supports the named protection.

[`Requirement::from`] converts an algorithm to [`Requirement::Algorithm`] with that algorithm, so naming only an algorithm never treats a one-protection entry as a full one.
Input narrowing is visible only as [`Error::Unsupported`] at call time (rule 4), not through availability queries.
Private-key availability remains [`PrivateKey::supports`] (section 7).

### 8.1 Composition

Composition is explicit: a binary composes providers, or a dedicated bundle crate fixes a composition (section 11); libraries never compose.
[`CryptoProvider::with_fallback`] keeps the entries of `self` and adds what its parameter `fallback` advertises and `self` does not.
Composition follows the granularity of advertisement: per algorithm, and per protection for [`Mac`], [`Cipher`], [`Aead`] and [`KeyWrap`]; never per input.
For an algorithm whose `self` entry does not support a protection that the `fallback` entry supports, the result holds one composite entry with the same algorithm: each protection is served by `self` when `self` supports it, and by `fallback` otherwise.
Its protection query returns true for a protection when either member's entry supports that protection.
Its FIPS report is true only if every member entry that serves one of its protections reports true.
For [`Mac`], the composite starts each context on the member that serves the requested protection, so the member that computes the tag is the one whose approval counts.
A primary entry still shadows the fallback for every input of an operation it advertises, including inputs outside the must-support set it refuses (for example an aws-lc-rs loader refusing 1024-bit RSA keys, or a loader unable to compute a missing EC public key) and inputs refused under section 8.2.
Those calls return [`Error::Unsupported`], with no fallback.
Binaries choose the order.

[`CryptoProvider::fips`] is true only if the provider has at least one entry, every entry's FIPS report is true, and every provider it was composed from reported true through [`CryptoProvider::fips`].
A provider built with the builder computes it from its entries.
[`CryptoProvider::with_fallback`] returns `self.fips() && fallback.fips()`.
A composition with any non-FIPS member therefore reports false even when every entry of that member is shadowed, and nesting preserves it.

Exception: composition is not derivable from [`CryptoProvider::entries`] and the builder, because a provider rebuilt from the retained entries would lose the status of shadowed members; keeping that status is what lets the FIPS policy reject a non-FIPS composition (section 8.2) instead of silently accepting it.

### 8.2 Policy

A policy is a function from provider to provider.

A policy may narrow the inputs an entry accepts below its must-support set.
A narrowed entry returns [`Error::Unsupported`] naming the algorithm for refused inputs: the input is valid for the algorithm but not permitted here, consistent with rule 4.
Conformance tests run against unwrapped providers; policy tests cover the narrowing.
Every threshold a policy applies cites its source (an SP 800-131A table, a module security policy) and its version.

A policy restricts operations through the availability queries:

- it wraps [`Mac`], [`Cipher`], [`Aead`] and [`KeyWrap`] entries so refused protections report `supports(protection) == false` and follow section 8's refusal behavior, for example keeping 3DES decryption and refusing encryption under NIST SP 800-131A Rev. 2;
  MAC policy can likewise restrict use, for example, allowing HMAC-SHA-1 verification and refusing generation (NIST SP 800-131A Rev. 3 draft, section 13, Table 14).
- it drops an entry if neither protection remains;
- it restricts keys through [`PrivateKey::supports`] (section 7);
- it restricts every other capability by dropping its entry or narrowing its inputs.

A policy may narrow signature verification by public-key size.
For RSA it uses the modulus bit length read from the `RSAPublicKey` bytes passed to the verifier; refused sizes return [`Error::Unsupported`] naming the algorithm.
Reading the size is format code in the policy, not in the contract.

The FIPS policy:

- rejects any provider whose [`CryptoProvider::fips`] is false, instead of silently dropping entries, so that a non-FIPS fallback composition cannot pass for FIPS; the error names the non-FIPS entries it can see, and may name none when the only non-FIPS member was entirely shadowed by the fallback composition (only its status is kept);
- then, in a provider that reports true through [`CryptoProvider::fips`], keeps entries approved for at least one operation, narrowed to the approved protections and inputs (filtering unapproved algorithms is not the same as accepting non-FIPS entries);
- wraps each kept [`PrivateKeyLoader`] so that the keys it returns report false through [`PrivateKey::supports`] and return [`Error::Unsupported`] for operations or key sizes the policy does not allow, using [`PrivateKey::key_size_bits`] (for example RSA signature generation below 2048 bits, disallowed by NIST SP 800-131A rev. 2, section 3);
- provides a key-restriction function for hardware keys, which do not come from a provider: it applies the same operation and key-size filters and rejects keys whose [`PrivateKey::fips`] is false.

The policy, not the backend, decides which algorithms are approved.
It lives outside `picky-crypto`, because its approved-algorithm table changes with NIST transitions (for example the end of SHA-1 signature generation) while the contract must stay stable.

## 9. Process-wide default

| Function | Semantics |
|---|---|
| [`install_default`] | Installs `provider` as the process-wide default. If a default is already installed, by any path, returns `Err(provider)` and changes nothing. Called once by the binary, before the first cryptographic operation. |
| [`get_default`] | Returns the installed process-wide provider, or [`None`](Option::None). Neither panics nor installs. Code that must not panic (FFI boundaries, libraries preferring an error) checks with it and returns an error. |
| [`get_or_install_default`] | Returns the installed process-wide provider; if none is installed, calls the factory `make`, installs its result and returns it. Concurrent callers observe exactly one installed provider; at most one maker runs at a time and at most one succeeds. |

A maker runs only when no provider is installed.
If `make` panics, the panic propagates and that call installs nothing; a later call runs its maker again if no provider has been installed, as with [`std::sync::OnceLock::get_or_init`].
A maker must not call [`get_or_install_default`] or [`install_default`]: re-entrant initialization deadlocks or panics.
Threads calling [`get_or_install_default`] while a maker runs wait for it; if it panics, one of them runs its own maker while no provider is installed.
An explicit [`install_default`] racing a running maker either installs first or returns its provider as an error.

[`get_default`] is not derivable from the other two: [`install_default`] consumes a provider and [`get_or_install_default`] installs one.
The panicking accessor [`helpers::default_provider`] (section 10) is [`get_default`] followed by a panic with a message naming [`install_default`] and the crates that provide a provider.
Explicit and lazy installation are distinct operations: one takes an owned provider and hands it back on conflict, the other takes a function that must not run when a provider is already installed.

[`get_or_install_default`] exists for the `rustcrypto` convenience feature of a consuming library, the single place where that library may name a backend.
The feature installs the provider of the RustCrypto bundle crate (section 11), whose composition is fixed, so every library that uses the same version of the bundle installs the same provider value whichever installs first:

The convenience-feature accessor calls [`get_or_install_default`] with the RustCrypto bundle's provider factory when enabled, and otherwise calls [`helpers::default_provider`].
The crate documentation for [`get_or_install_default`] gives the Rust example.

A binary that installs its own provider before first use is unaffected by the convenience feature.
A binary that installs after a library already installed the default gets [`Err`](Result::Err) back from [`install_default`] and must install earlier.
Convenience features are per crate: a crate built without its feature panics (through [`helpers::default_provider`]) if it uses cryptography before a crate with the feature has installed the bundle lazily, so a binary that mixes such crates installs a provider explicitly.
The same provider value is guaranteed only for one version of the bundle crate: a binary whose dependency graph contains more than one version of it installs a provider explicitly, so that availability does not depend on which library uses cryptography first.

## 10. Helpers

Helpers are free functions in [`helpers`], written only against the public API above.
Each is derivable, so none is a contract operation; they exist so that consumers share one implementation.
Fallible helpers return [`Result<_, Error>`](Result) with [`Error`] and propagate the underlying error unchanged; no helper panics except [`helpers::default_provider`], by design.

| Helper | Derived from |
|---|---|
| [`helpers::default_provider`] | [`get_default`], panicking when it returns [`None`](Option::None) |
| [`helpers::entry_algorithm`], [`helpers::entry_fips`] | a match on [`Entry`] plus the trait's identity or FIPS-reporting method ([`Algorithm::KeyAgreement`] with [`KeyAgreementAlgorithm::Ffdh`] for an [`FfdhKeyAgreement`] entry) |
| typed accessors, one per [`Entry`] variant: [`helpers::hash`], ..., [`helpers::key_agreement`], [`helpers::ffdh_key_agreement`] | [`CryptoProvider::get`] plus a match; [`Error::Unsupported`] naming the algorithm when absent; [`helpers::key_agreement`] with [`KeyAgreementAlgorithm::Ffdh`] returns [`Error::InvalidInput`], because the FFDH entry implements [`FfdhKeyAgreement`] and is reached through [`helpers::ffdh_key_agreement`] |
| [`helpers::digest`] | [`Hash::start`], [`HashContext::update`], [`HashContext::finish`] |
| [`helpers::compute_mac`] | [`MacGeneration::start`], [`MacGeneration::update`], [`MacGeneration::finish`]; returns [`MacTag`] |
| [`helpers::verify_mac`] | [`MacVerification::start`], [`MacVerification::update`], [`MacVerification::finish`], then [`MacVerifier::verify`]; returns a boolean |
| [`helpers::random_x25519_private_key`] | [`SecureRandom::fill`], then RFC 7748 clamping (section 6.13); returns [`X25519Scalar`]; [`Error::Unsupported`] naming [`Algorithm::Random`] with [`RandomAlgorithm::SecureRandom`] if the provider has no RNG |
| [`helpers::ffdh_public_value`] | [`PrivateKey::agree`] with [`KeyAgreementAlgorithm::Ffdh`] and peer value `g`, whose result is `g^x mod p` left-padded to the length of `p`; precondition: `parameters` are those the key was loaded with, otherwise the result is unspecified (never a panic) |
| [`helpers::missing`] | [`CryptoProvider::get`] plus [`Mac::supports`] / [`Cipher::supports`] / [`Aead::supports`] / [`KeyWrap::supports`]; reports every unmet requirement (section 8), so no provider method is needed |

Like [`helpers::digest`], [`helpers::compute_mac`] and [`helpers::verify_mac`] are one-shot helpers derived from the streaming operations.

NTLM's MD4, MD5 and RC4 requirements use [`Requirement::from`] on [`Algorithm::Hash`] with [`HashAlgorithm::Md4`], [`Algorithm::Hash`] with [`HashAlgorithm::Md5`] and [`Algorithm::StreamCipher`] with [`StreamCipherAlgorithm::Rc4`] respectively.

Protocol-specific constructions (Kerberos n-fold, ciphertext stealing and RFC 3961 key derivation; NTLM constructions; JOSE and SSH framing; the PKCS#12 key derivation) and format conversions stay in their consuming crates.

## 11. Providers built around the contract

The contract does not depend on any of the following; they are described here because the semantics above refer to their roles.

- **Providers built from other providers' entries.**
  A provider may build entries from another provider's contract entries, for algorithms that a backend's library lacks: the key-based KDFs (section 6.4), the one-step KDF from [`Hash`] entries and the counter-mode KDF from [`Mac`] entries.
  The counter-mode KDF takes each PRF block from a [`MacGeneration`] with [`MacTag::into_inner`], requiring [`Protection::Apply`] from those entries; policy judges the resulting [`Kdf`] entry independently (section 6.4).
  Such a provider takes the entries it builds on explicitly at construction, contains no other cryptographic code, and reports false through [`CryptoProvider::fips`], so the FIPS policy rejects any provider composed with it.
  An entry of this kind exists only while some backend's library lacks the algorithm natively.
- **FFDH provider.**
  Finite-field Diffie-Hellman, which the reference libraries do not offer in the form section 6.11 requires, comes from a provider implemented over a constant-time big-integer library.
  It takes another provider's [`SecureRandom`] entry at construction, because it has no randomness of its own, and reports false through [`CryptoProvider::fips`].
- **RustCrypto bundle.**
  A fixed, documented composition: the RustCrypto backend first, so a native entry always wins, then the entries built over it, then the FFDH provider.
  It contains no cryptographic code and reports false through [`CryptoProvider::fips`].
  It is what the `rustcrypto` convenience features install (section 9).
- **RSA CRT completion.**
  Completing an RSA private key from `n`, `e`, `d`, `p` and `q` (computing `dP`, `dQ`, `qInv`) is key-format completion, not a standardized algorithm, so it is not a contract operation.
  It lives outside the contract so that format code can produce PKCS#8 and FIPS binaries can exclude the arithmetic from their dependency graph.

## 12. Conformance testing

The conformance suite runs on unwrapped providers and keys and uses published vectors (Wycheproof, NIST CAVP, RFC test vectors).

The suite queries [`Mac::supports`], [`Cipher::supports`], [`Aead::supports`] and [`KeyWrap::supports`] on each corresponding entry; an entry reporting neither protection fails.
For each protection `p`, [`Mac::start`] with `start(key, p)` for [`Mac`] or the corresponding operation returns [`Error::Unsupported`] naming the algorithm exactly when `supports(p)` is false on must-support inputs.
For each unsupported protection, the suite skips vector labels and checks that [`helpers::missing`] reports the directional requirement.

Before a vector's label is applied, its eligibility is decided by the rules above:

- for an absent entry or a key operation for which [`PrivateKey::supports`] is false, the suite asserts [`Error::Unsupported`] and does not apply the label;
- MAC, cipher, AEAD and key-wrap vectors apply only to supported protections;
- for a vector whose inputs are in the operation's must-support set, the label is applied as below;
- for a vector whose inputs are inside the valid domain but outside the must-support set (for example a 1024-bit RSA key), [`Error::Unsupported`] is also accepted, and so is [`Error::VerificationFailed`] from a verifier on a library with a single opaque failure (section 4); any other result must match the label.

Labels follow Wycheproof:

- `valid` vectors must succeed and `invalid` vectors must fail with the error class of section 4;
- `acceptable` vectors only assert that nothing panics, unless this document pins the behavior, in which case the pinned behavior is asserted;
- X25519 vectors labeled `acceptable` (twist, non-canonical, high-bit and low-order public values, and unclamped private keys) assert the published shared secret, because section 5.2 puts every 32-byte input in the must-support set; those whose shared secret is all zero assert [`Error::InvalidInput`] (section 6.11);
- where this document pins a behavior that a vector's label contradicts, this document wins: for example, ECDSA signatures with a high `s` are valid (section 6.9), and the Bitcoin-specific vectors that reject them do not apply.

AEAD seal output is not deterministic, so seal is verified only through round trips (open of seal output) and cross-backend opens, with [`Protection::Apply`] supported by the sealing entry and [`Protection::Process`] by the opening entry.
A round trip requires both protections on the same entry; known-answer AEAD tests run on open only.
The suite checks that the returned nonce is 12 bytes.

Behaviors left implementation-defined are excluded from differential tests between backends.
For each of them, conformance tests assert that nothing panics and that the result is one of the outcomes this document allows for that case:

- Ed25519 verification with a validly encoded small-order public key `A` (section 6.9): success, or an outcome section 4 accepts for an unusable public key ([`Error::InvalidKey`], [`Error::Unsupported`] or [`Error::VerificationFailed`]);
- Ed25519 verification with a validly encoded small-order `R` in the signature (section 6.9): success or [`Error::VerificationFailed`];
- RSA PKCS#1 v1.5 verification of a DigestInfo with absent parameters (section 6.9): success or [`Error::VerificationFailed`], the result section 6.9 gives for a signature that does not verify;
- loading a PKCS#8 document that carries `attributes` (section 5.2): success or [`Error::InvalidKey`];
- a 3DES key whose component keys are not pairwise distinct or are DES weak or semi-weak keys (section 6.5): success or [`Error::InvalidKey`];
- handling of an RSA private key with inconsistent components (section 7): loading returns [`Error::InvalidKey`], or every private-key operation either returns [`Error::InvalidKey`] or produces a result that verifies under (`n`, `e`).
  For decryption, verification uses a round trip through the provider's encryptor, or through a reference encryptor supplied by the test harness when the implementation under test has no encryptor (for example a hardware key).
  In differential runs, the result is also verified with the other backend, but the outcomes themselves are not compared.

The inputs for that last property are derived from published keys, because the known published RSA test vectors contain no keys with inconsistent components:

- base keys come from cited published sources;
- an input is derived only by swapping or substituting whole encoded INTEGER fields between cited keys: `dP` with `dQ`, `p` with `q` leaving `qInv` unchanged, or `qInv` taken from another cited key of the same size; no arithmetic, no generated bytes and no randomness;
- round-trip control: splitting a base key into its fields and reassembling them unchanged must reproduce the cited key's exact bytes, otherwise the test fails;
- positive control: the unmodified base key loads and produces a result that verifies on the backend under test.

Provider-value property tests against mock providers check composition (section 8.1) for [`Mac`], [`Cipher`], [`Aead`] and [`KeyWrap`]: a fallback fills in a protection the primary does not support, the primary serves a protection both members support, and the composite entry's FIPS report and the composed provider's [`CryptoProvider::fips`] follow section 8.1.
For [`Mac`], each context starts on the member serving the requested protection.

The FFDH exponent distribution (section 6.11) is mandatory but not observable from outputs; it is verified by review, while the suite checks the range of the public value and the round trip.

For every returned [`OutputBytes`], [`X25519Scalar`], [`MacTag`], [`MacVerifier`] and [`Sealed`] through its fields, the suite also asserts that the [`Debug`](std::fmt::Debug) output never contains the buffer's bytes.
For every loaded key, the suite checks [`PrivateKey::key_size_bits`] against the exact size section 7 defines, including RSA keys whose modulus length is not a multiple of 8 bits (for example 3071 or 4095 bits) when the backend loads them; such keys come from cited sources like every other key.
[`MacVerifier::verify`] is tested with the correct tag, a wrong tag, an `expected` whose length differs from `len`, `len` of 0 and greater than the tag length, and the truncated lengths used by Kerberos (12 bytes) and NTLM (8 bytes).
A [`MacTag`] and a [`MacVerifier`] computed on the same key and data agree: the tag's [`MacTag::into_inner`] bytes verify through the verifier.

A backend that fails a vector natively is a defect to investigate, not a reason to skip the vector or to patch the library's behavior in the adapter.

## 13. Design rationale

**One algorithm enum per category.**
Per-category enums let each capability trait take exactly the algorithms it implements, so a mismatch is a type error; the wrapping [`Algorithm`] serves lookup, availability lists and [`Error::Unsupported`].
The one exception is key agreement: [`KeyAgreementAlgorithm`] covers both [`KeyAgreement`] and [`FfdhKeyAgreement`] because [`PrivateKey::agree`] takes every agreement algorithm.
[`ProviderBuilder::build`] therefore rejects a [`KeyAgreement`] entry that reports [`KeyAgreementAlgorithm::Ffdh`] (section 8).
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
Consumers state the protections they need through [`Requirement`] (section 8), and composition can fill in a missing protection (section 8.1).

**Streaming hash and MAC.**
Consumers process unbounded inputs and some already hash incrementally, and every library streams the algorithms it has; a one-shot interface would force large buffers and is a helper on top.

**Owned buffers for ciphers and AEAD.**
Inputs are borrowed and outputs are owned, the weakest shape every library supports; in-place APIs would force some libraries to copy anyway.
AEAD seal returns the generated nonce separately from `ciphertext || tag`, the common native ciphertext layout (section 6.7).

**Optional key generation returning PKCS#8.**
Generation returns the contract's private-key encoding, so a generated key can be loaded by any backend; a provider whose keys cannot be exported simply does not advertise generation.

**Public keys as the `subjectPublicKey` contents.**
The algorithm already fixes the key type, curve and hash; some libraries have no SPKI parser, and these are the forms the reference libraries import natively, among those that import that key type at all.
[`PrivateKey::public_key`] returns the same encoding, so consumers wrap it in SPKI only when a format needs it.

**One RNG entry, no RNG parameters.**
Some libraries accept only their own generator, so operations draw from the backend's generator, and consumers needing random bytes use the [`SecureRandom`] entry.

**Messages, not digests.**
Some libraries cannot sign or verify a precomputed digest; a handle-based key can always hash the message itself (section 7.1).

**Hardware keys as [`PrivateKey`] implementations.**
A smartcard or OS key store implements the trait directly, advertises what the device offers through [`PrivateKey::supports`], and reports its deployment status through [`PrivateKey::fips`]; it does not need a provider.

**FFDH with explicit domain parameters.**
Consumers take the group from the protocol, so the operation takes `p`, `g` and an optional `q`, performs the checks of section 6.11, and generates exponents as SP 800-56A specifies, with the range of section 6.11 when `q` is absent.

**Non-FIPS algorithms as ordinary identifiers.**
MD4, MD5, RC4, RC2, 3DES and FFDH are ordinary algorithm identifiers, and backends that lack them return [`Error::Unsupported`].
The FIPS policy filters or narrows entries according to their approved uses (section 8.2), while rejecting a provider containing any non-FIPS entry (for example the FFDH provider, or a RustCrypto entry) outright.
There is no compile-time distinction, because algorithm choice comes from parsed data.

**Lazy installation for convenience features.**
[`get_or_install_default`] lets a library's convenience feature install the RustCrypto bundle lazily, only when no provider was installed, without racing other libraries.

**One provider per process.**
Consumers use the process-wide default, so a process has one provider, unlike TLS libraries whose configurations each carry their own.
This is intended for FIPS binaries, where one provider behind one policy governs every operation.
The default is a static of the `picky-crypto` crate, so the guarantee holds for one linked instance.
A binary that links two semver-incompatible versions, or loads Rust dynamic libraries that each link their own copy, has one default per instance.
A FIPS binary therefore links a single `picky-crypto` instance and checks it in its build (for example with cargo-deny's duplicate-crate check).
It also installs its provider in every dynamic library that carries its own copy.
Explicit provider parameters in consumer APIs would be a change to those APIs, not to the contract.

**Composition at the granularity of advertisement.**
A fallback is chosen per algorithm, and per protection for [`Mac`], [`Cipher`], [`Aead`] and [`KeyWrap`], never per input (section 8.1).
Algorithms and protections are advertised and known when providers are composed, so the member that serves each operation is known from the provider value alone and a policy can judge it.
Inputs are not advertised, so composing on them would make the serving member depend on data.

**Zeroizing every output.**
Whether a buffer is secret depends on how the consumer uses it, not on the operation that produced it (section 2, rule 1), so every returned buffer is wiped on drop.
The returned types are opaque for the same reason: their [`Debug`](std::fmt::Debug) shows only the length.
MAC results are split into a generated [`MacTag`], whose bytes are read only through [`MacTag::into_inner`], and a [`MacVerifier`] that only verifies, in constant time and with a length fixed by the protocol (section 6.2).

## Appendix A. Public API

The Rust declarations and their documentation are in the `picky-crypto` crate documentation and source.
This document specifies their behavior.
