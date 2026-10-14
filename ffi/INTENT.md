## Deterministic disposal in .NET bindings

The generated .NET API SHOULD expose an opaque type as `IDisposable` when at least one of these conditions is true:

- The type owns a large allocated resource that is invisible to the garbage collector's cost model.
- The type owns a scarce or externally observable resource, regardless of its size, such as an operating-system handle, socket, named pipe, or file lock.
- The type is a borrowing view, directly or transitively, of a disposable type.
  A view must not prevent deterministic release of the value it retains.
  (NOTE: this should be enforced by the diplomat-tool’s .NET backend eventually.)

The API SHOULD NOT expose a small, value-like opaque type as `IDisposable` unless it is a borrowing view of a disposable type.
The default is no `IDisposable`; it is not added defensively.
