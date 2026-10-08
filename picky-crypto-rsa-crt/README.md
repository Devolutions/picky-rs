# picky-crypto-rsa-crt

Complete the CRT parameters `dP`, `dQ`, and `qInv` from `n`, `e`, `d`, `p`, and `q` for a two-prime RSA private key.
This `no_std` crate requires an allocator and uses the [PKCS #1 definitions]: `dP = d mod (p − 1)`, `dQ = d mod (q − 1)`, and `qInv = q⁻¹ mod p`.
It does not factor `n`, generate keys, or perform RSA operations, and is not FIPS-capable.

## Encoding and checks

Inputs are unsigned big-endian integers and may include leading zero bytes.
Outputs are unsigned big-endian integers padded with zeros to the input encoding lengths: `dP` and `qInv` have `p.len()` bytes, and `dQ` has `q.len()` bytes.

`complete_crt_params` returns `Error::InvalidLength` when `n` is empty, its value exceeds 16384 bits, its encoding exceeds 2049 bytes, or any other input is longer than `n`.
At 2049 bytes, `n` must start with a zero sign byte.
The limit bounds allocation and arithmetic work.
It returns `Error::InconsistentKey` unless all of these checks hold:

- `p` and `q` are odd and at least 3.
- `p × q = n`, without overflow.
- `q` is invertible modulo `p`.
- `e × dP ≡ 1 (mod p − 1)` and `e × dQ ≡ 1 (mod q − 1)`.

These are consistency checks, not primality tests or a complete RSA key validation policy.
The exponent checks accept private exponents derived modulo either φ(n) or λ(n).

## Secret handling

Arithmetic uses constant-time `crypto-bigint` operations with a shared precision determined by `n.len()`.
`n`, `e`, and all input lengths are treated as public.
Consistency checks are aggregated before a single error branch, and outputs are not trimmed according to their values.
Owned secret intermediates and outputs are zeroized on drop, and `CrtParams` debug output is redacted.
Callers remain responsible for clearing input buffers.

### Limitations

`crypto-bigint` does not zeroize all internal arithmetic temporaries, including safegcd inversion state, multiplication scratch space, and stack copies used by division and encoding.
This crate cannot guarantee that every copy of secret material is erased.

[PKCS #1 definitions]: https://www.rfc-editor.org/rfc/rfc8017#section-3.2
