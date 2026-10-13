//! RC4 keystream known answers, key lengths and the longest must-support key.

use picky_crypto::*;

use crate::harness::{Checks, Expect, Options};
use crate::{select, vectors as v};

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
                    ctx.apply(&vec![0; offset])?;
                    ctx.apply(&vec![0; expected.len()])
                }) {
                    c.bytes(&id, &out, &expected);
                }
            }
            // No published RC4 vector has a 256-byte key, so this one expects only the contract's properties: success, length, state carry-over and XOR.
            let (source, key) = select::rc4_longest_key();
            let message = &key;
            let id = format!("{a:?}/key length=256/{source}");
            let split = message.len() / 2;
            if let Some((whole, parts, restored)) = c.call(&id, Expect::Success, || {
                let whole = e.start(&key)?.apply(message)?;
                let mut ctx = e.start(&key)?;
                let parts = [
                    ctx.apply(&message[..split])?.to_vec(),
                    ctx.apply(&message[split..])?.to_vec(),
                ]
                .concat();
                let restored = e.start(&key)?.apply(&whole)?;
                Ok((whole, parts, restored))
            }) {
                c.check(&id, whole.len() == message.len(), "output length");
                c.check(&id, parts == whole.as_ref(), "two calls must continue one keystream");
                c.bytes(&format!("{id}/applied twice"), &restored, message);
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
