picky fuzzing
=============

- [install cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html)
- fuzz x509, pem and keys: `cargo fuzz run x509`
- fuzz jose: `cargo fuzz run jose -- -only_ascii=1`
- fuzz http signatures: `cargo fuzz run --release http -- -only_ascii=1` (release is recommended because of heavy crypto operations)
