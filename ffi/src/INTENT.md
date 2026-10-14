Rule:
1. Never implement drop for opaque that borrows, and never let a Drop touch borrowed data
  This is a known limitation from upstream, the Dotnet destructor call order is NOT determinstic 
Example:
```rust
#[diplomat::opaque]
pub struct Parent(RefCell<Vec<u8>>);

#[diplomat::opaque]
pub struct Reader<'a>(Ref<'a, Vec<u8>>); // dropping a `Ref` writes to the parent's RefCell

impl Parent {
    pub fn reader<'a>(&'a self) -> Box<Reader<'a>> {
        Box::new(Reader(self.0.borrow()))
    }
}

// Same problem with a hand-written Drop:
impl Drop for ffi::ExtensionView<'_> {
    fn drop(&mut self) {
        tracing::trace!(oid = %self.0.extn_id(), "dropped"); // reads `'a` data
    }
}
```

The follwoing is allowed 
```rust
#[diplomat::opaque]
#[diplomat::attr(dotnet, manually_disposable)]
pub struct SshPrivateKey(pub ssh::SshPrivateKey); // no lifetime, owns everything

impl Drop for ffi::SshPrivateKey {
    fn drop(&mut self) {
        if let Some(passphrase) = self.0.passphrase.as_mut() {
            zeroize::Zeroize::zeroize(passphrase); // touches only its own data
        }
    }
}
```


2. Only mark `manually_disposable` for 1.memory-heavy types and 2.the sensitive data
