## Opaque types and `Drop`

`INTENT.md` here forbids an opaque type with a lifetime from touching borrowed data when it is dropped.

- Don't implement `Drop` for an opaque type that borrows.
- Don't give such a type a field whose own drop touches the borrow, such as a `Ref` into the parent's `RefCell`.
- A `Drop` on an opaque type without a lifetime may touch its own data, for example to zeroize a secret.

Not allowed:

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

Allowed:

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

## `manually_disposable`

Mark an opaque type `#[diplomat::attr(dotnet, manually_disposable)]` only when it holds a lot of memory or sensitive data.
