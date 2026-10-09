use picky_crypto::{CryptoProvider, get_default, get_or_install_default};
use std::{
    panic::catch_unwind,
    sync::atomic::{AtomicUsize, Ordering},
};

static PANICKING_CALLS: AtomicUsize = AtomicUsize::new(0);
static SUCCEEDING_CALLS: AtomicUsize = AtomicUsize::new(0);

fn panicking_maker() -> CryptoProvider {
    PANICKING_CALLS.fetch_add(1, Ordering::SeqCst);
    panic!("maker failure");
}

fn succeeding_maker() -> CryptoProvider {
    SUCCEEDING_CALLS.fetch_add(1, Ordering::SeqCst);
    CryptoProvider::builder().build().unwrap()
}

#[test]
fn panicking_initialization_leaves_the_default_unset_and_allows_retry() {
    assert!(get_default().is_none());
    assert!(catch_unwind(|| get_or_install_default(panicking_maker)).is_err());
    assert_eq!(PANICKING_CALLS.load(Ordering::SeqCst), 1);
    assert!(get_default().is_none());

    let installed = get_or_install_default(succeeding_maker);
    assert_eq!(SUCCEEDING_CALLS.load(Ordering::SeqCst), 1);
    assert!(std::ptr::eq(installed, get_default().unwrap()));
    assert!(std::ptr::eq(installed, get_or_install_default(succeeding_maker)));
    assert_eq!(SUCCEEDING_CALLS.load(Ordering::SeqCst), 1);
}
