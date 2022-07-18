import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { Pem } from "./Pem.js"
import { PickyError } from "./PickyError.js"

const PublicKey_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.PublicKey_destroy(underlying);
});

export class PublicKey {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      PublicKey_box_destroy_registry.register(this, underlying);
    }
  }

  static from_pem(arg_pem) {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PublicKey_from_pem(diplomat_receive_buffer, arg_pem.underlying);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new PublicKey(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }

  static from_der(arg_der) {
    const buf_arg_der = diplomatRuntime.DiplomatBuf.slice(wasm, arg_der, 1);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PublicKey_from_der(diplomat_receive_buffer, buf_arg_der.ptr, buf_arg_der.size);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new PublicKey(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
    buf_arg_der.free();
    return diplomat_out;
  }

  to_pem() {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PublicKey_to_pem(diplomat_receive_buffer, this.underlying);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new Pem(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }
}
