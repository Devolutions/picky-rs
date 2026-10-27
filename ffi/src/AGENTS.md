# FFI maintenance

Do not implement `Drop` for an opaque type that borrows; `INTENT.md` explains the finalizer lifetime hazard.
A `Ref` into a parent's `RefCell` writes to the parent when dropped, even without an explicit `Drop` on the opaque type.
An owning type may access its own data on drop, for example to zeroize secrets.

Mark an opaque type `#[diplomat::attr(dotnet, manually_disposable)]` only when it holds a lot of memory or sensitive data.
