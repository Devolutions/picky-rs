# Picky WASM

JavaScript bindings to [`picky`](https://github.com/Devolutions/picky-rs/tree/master/picky) using wasm-bindgen.

## Build & publish

This should be run in the CI.

1. Install [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/).

2. Build the package: 

    ```
    $ npm run build
    ```

3. Publish to npm:

    ```
    $ npm publish
    ```

## Testing

Some tests can be in Firefox in headless mode:

```
$ wasm-pack test --headless --firefox
```

Other tests are run using `nodejs` and the `ava` testing framework.
For these, you need to build the npm package targeting `nodejs`:

```
$ wasm-pack build --target nodejs --scope @devolutions --out-name picky
```

Rename `@devolutions/picky-wasm` to `@devolutions/picky` in `pkg/package.json`.

Run the `ava` tests

```
cd ava_tests
npm install
npm test
```
