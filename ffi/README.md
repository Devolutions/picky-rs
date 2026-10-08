# Picky FFI

This crate exposes a C-compatible API. Bindings are auto-generated.

## Native library build

Build is as simple as:

```
$ cargo build -p picky-ffi
```

or

```
$ cargo build -p picky-ffi --release
```

Binary will be generated inside `target` folder located at workspace root.

## C# .NET bindings

C# .NET bindings are located in the `./dotnet/` folder.
[`Diplomat`](https://github.com/rust-diplomat/diplomat) is used to generate most of the code.
Both the macros and the tool are pinned to a tag on the [Devolutions fork](https://github.com/Devolutions/diplomat); see the `justfile`.

## Justfile

A [justfile](https://github.com/casey/just) is provided to run common commands useful at developement time.

The appropriate version of `Diplomat`'s tool can be installed with (requires a stable Rust toolchain, 1.95 or newer):

```
$ just diplomat-install
```

Commands for generating the bindings are issued with:

```
$ just bindings
```

Sanity tests, including the .NET Framework 4.8 marshalling tests, are run with:

```
$ just test
```

On Windows, run `just` with `--shell powershell.exe --shell-arg -c`.
For instance:
```
$ just --shell powershell.exe --shell-arg -c test
```
