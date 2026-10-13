//! Provider-wide metadata: FIPS reports, entry identity, directional support and `missing`.

use picky_crypto::*;

use crate::algorithms;
use crate::harness::{Checks, Expect, Options};

pub fn run(provider: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    c.call(
        "helpers::key_agreement/Ffdh",
        Expect::Error(Error::InvalidInput),
        || helpers::key_agreement(provider, KeyAgreementAlgorithm::Ffdh).map(|_| ()),
    );
    if let Some((nonempty, entries_fips, reported)) = c.metadata("provider/FIPS", || {
        (
            provider.entries().next().is_some(),
            provider.entries().all(helpers::entry_fips),
            provider.fips(),
        )
    }) {
        c.check(
            "provider/FIPS",
            !reported || (nonempty && entries_fips),
            "FIPS report requires nonempty, FIPS entries",
        );
    }
    for entry in provider.entries() {
        let Some(id) = c.metadata("provider/entry identity", || helpers::entry_algorithm(entry)) else {
            continue;
        };
        c.check(
            &format!("{id:?}"),
            provider.get(id).is_some(),
            "entry not found under own algorithm",
        );
        let protections = c
            .metadata(&format!("{id:?}/protections"), || match entry {
                Entry::Mac(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                Entry::Cipher(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                Entry::Aead(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                Entry::KeyWrap(e) => Some((e.supports(Protection::Apply), e.supports(Protection::Process))),
                _ => None,
            })
            .flatten();
        if let Some((a, b)) = protections {
            c.check(&format!("{id:?}"), a || b, "entry supports neither protection");
        }
    }
    for a in algorithms::all() {
        if provider.get(a).is_none() {
            c.check(
                &format!("{a:?}"),
                helpers::missing(provider, &[a.into()]) == [a.into()],
                "missing omitted absent entry",
            );
        }
    }
    c.finish();
}
