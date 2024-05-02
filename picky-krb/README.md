[![Crates.io](https://img.shields.io/crates/v/picky-krb.svg)](https://crates.io/crates/picky-krb)
[![docs.rs](https://docs.rs/picky-krb/badge.svg)](https://docs.rs/picky-krb)
![Crates.io](https://img.shields.io/crates/l/picky-krb)

Compatible with rustc 1.56.
Minimal rustc version bumps happen [only with minor number bumps in this project](https://github.com/Devolutions/picky-rs/issues/89#issuecomment-868303478).

# picky-krb

Provides implementation for types defined in [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120.txt).

## Serializing and Deserializing raw Kerberos

picky-krb serializes raw Kerberos bytes using `picky_asn1_der::from_bytes`, for example:

```rust
use picky_krb::messages::AsRep;
let as_rep: AsRep = picky_asn1_der::from_bytes(&raw).unwrap();
```

Kerberos structures can be deserialized to raw bytes using `picky_asn1_der::to_vec`, for example:

```rust
use picky_krb::messages::TgsReq;
let tgs_req: TgsReq = picky_asn1_der::from_bytes(&raw).unwrap();
let tgs_req_raw = picky_asn1_der::to_vec(&tgs_req).unwrap();
```
