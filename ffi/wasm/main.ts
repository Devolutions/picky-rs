// Re-export all exports.
export * from "./pkg/picky";

// Re-export the default export as default as well.
import { default as _wasm_init } from "./pkg/picky";
export default _wasm_init;
