//! RC4 keystream known answers and key lengths.

use picky_crypto::*;

use crate::harness::{CheckedResult, Checks, Expect, Options};
use crate::vectors as v;

pub fn run(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let a = StreamCipherAlgorithm::Rc4;
    match helpers::stream_cipher(p, a) {
        Err(error) => c.absent::<()>(p, Algorithm::StreamCipher(a), Err(error)),
        Ok(e) => {
            for (key, offset, expected) in v::rc4() {
                let id = format!("{a:?}/rfc/rfc6229.txt/keyBits={}/offset={offset}", key.len() * 8);
                if let Some(out) = c.call(&id, Expect::Success, || {
                    let mut ctx = e.start(&key)?;
                    ctx.apply(&vec![0; offset]).checked()?;
                    ctx.apply(&vec![0; expected.len()])
                }) {
                    c.bytes(&id, &out, &expected);
                }
            }
            for length in [0, 257] {
                c.call(
                    &format!("{a:?}/key length={length}"),
                    Expect::Error(Error::InvalidKey),
                    || e.start(&vec![0; length]),
                );
            }
        }
    }
    c.finish();
}
