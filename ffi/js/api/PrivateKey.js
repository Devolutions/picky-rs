import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { Pem } from "./Pem.js"
import { PickyError } from "./PickyError.js"
import { PublicKey } from "./PublicKey.js"

const PrivateKey_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.PrivateKey_destroy(underlying);
});

export class PrivateKey {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      PrivateKey_box_destroy_registry.register(this, underlying);
    }
  }

  static from_pem(arg_pem) {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PrivateKey_from_pem(diplomat_receive_buffer, arg_pem.underlying);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new PrivateKey(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }

  static from_pkcs8(arg_pkcs8) {
    const buf_arg_pkcs8 = diplomatRuntime.DiplomatBuf.slice(wasm, arg_pkcs8, 1);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PrivateKey_from_pkcs8(diplomat_receive_buffer, buf_arg_pkcs8.ptr, buf_arg_pkcs8.size);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new PrivateKey(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
    buf_arg_pkcs8.free();
    return diplomat_out;
  }

  static generate_rsa(arg_bits) {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PrivateKey_generate_rsa(diplomat_receive_buffer, arg_bits);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new PrivateKey(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }

  to_pem() {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.PrivateKey_to_pem(diplomat_receive_buffer, this.underlying);
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

  to_public_key() {
    return new PublicKey(wasm.PrivateKey_to_public_key(this.underlying), true, []);
  }
}
