import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"

const PickyError_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.PickyError_destroy(underlying);
});

export class PickyError {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      PickyError_box_destroy_registry.register(this, underlying);
    }
  }

  to_display() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return wasm.PickyError_to_display(this.underlying, writeable);
    });
  }

  print() {
    wasm.PickyError_print(this.underlying);
  }
}
