## Deterministic disposal in .NET bindings

When adding or changing a Diplomat opaque type exposed to .NET, decide whether to apply `#[diplomat::attr(dotnet, manually_disposable)]`.

Apply the attribute when at least one of these conditions is true:

- The type owns a large allocated resource.
  E.g.: framebuffer, byte buffer.
- The type owns a scarce or externally observable resource, regardless of size.
  E.g.: operating-system handles, sockets, named pipes, file locks.
- The type is a borrowing view, directly or transitively, of a disposable type.

Default to no `IDisposable`; do not add it defensively.
