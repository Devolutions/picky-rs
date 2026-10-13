//! Self-tests of the conformance suite: they check the suite's own code, not a backend.
//!
//! They cover the vector parsers and their counts, the selection of published vectors, the re-encoding of published keys, derived inputs, the harness and the area lists.
//! Where a check needs a provider, it uses an empty provider or a small mock built here, never a real backend.
//! Backends run the suite through the `picky-crypto-conformance` runner.

mod area_lists;
mod asymmetric;
mod der;
mod differential;
mod freshness;
mod harness;
mod selection;
mod stream_cipher;
mod vectors;
