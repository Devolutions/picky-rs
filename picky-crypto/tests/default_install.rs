use picky_crypto::{CryptoProvider, get_default, get_or_install_default, helpers, install_default};

fn unexpected_factory() -> CryptoProvider {
    panic!("factory must not be called after installation")
}

#[test]
fn explicit_installation_and_conflict() {
    assert!(get_default().is_none());
    let panic = std::panic::catch_unwind(helpers::default_provider).unwrap_err();
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(message.contains("picky_crypto::install_default"));
    assert!(message.contains("picky-crypto-rustcrypto-bundle"));
    install_default(CryptoProvider::builder().build().unwrap()).unwrap();
    let installed = get_default().unwrap();
    assert!(std::ptr::eq(installed, helpers::default_provider()));
    assert!(std::ptr::eq(installed, get_or_install_default(unexpected_factory)));
    let rejected = install_default(CryptoProvider::builder().build().unwrap()).unwrap_err();
    assert_eq!(rejected.entries().count(), 0);
    assert!(std::ptr::eq(installed, get_default().unwrap()));
}
