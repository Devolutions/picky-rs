use picky_crypto::{CryptoProvider, get_default, get_or_install_default, install_default};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

static CALLS: AtomicUsize = AtomicUsize::new(0);
fn factory() -> CryptoProvider {
    CALLS.fetch_add(1, Ordering::SeqCst);
    CryptoProvider::builder().build().unwrap()
}

#[test]
fn concurrent_lazy_initialization() {
    assert!(get_default().is_none());
    let barrier = Arc::new(Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                get_or_install_default(factory)
            })
        })
        .collect();
    let installed = threads.into_iter().map(|t| t.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    for provider in installed {
        assert!(std::ptr::eq(provider, get_default().unwrap()));
    }
    assert!(install_default(factory()).is_err());
}
