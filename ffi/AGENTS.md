## .NET target framework

Target the oldest .NET version that is still supported by Microsoft.
When that version reaches end of support, move the target to the next oldest supported version.

## Deterministic disposal in .NET bindings

When adding or changing a Diplomat opaque type exposed to .NET, decide whether to apply `#[diplomat::attr(dotnet, manually_disposable)]`.

Apply the attribute when at least one of these conditions is true:

- The type owns a large allocated resource.
  E.g.: byte buffer.
- The type owns a scarce or externally observable resource, regardless of size.
  E.g.: operating-system handles, sockets, named pipes, file locks.
- The type is a borrowing view, directly or transitively, of a disposable type.

Default to no `IDisposable`; do not add it defensively.

## Error handling

- Prefer to return `Option` if the error details are not important to the caller.

## Validation

Run `just diplomat-install` and `just bindings` from `ffi/` to verify that the bindings can be generated.
