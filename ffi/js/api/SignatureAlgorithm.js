import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { HashAlgorithm_js_to_rust, HashAlgorithm_rust_to_js } from "./HashAlgorithm.js"
import { PickyError } from "./PickyError.js"

const SignatureAlgorithm_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.SignatureAlgorithm_destroy(underlying);
});

export class SignatureAlgorithm {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      SignatureAlgorithm_box_destroy_registry.register(this, underlying);
    }
  }

  static new_rsa_pkcs_1v15(arg_hash_algorithm) {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.SignatureAlgorithm_new_rsa_pkcs_1v15(diplomat_receive_buffer, HashAlgorithm_js_to_rust[arg_hash_algorithm]);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new SignatureAlgorithm(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }

  verify(arg_public_key, arg_msg, arg_signature) {
    const buf_arg_msg = diplomatRuntime.DiplomatBuf.slice(wasm, arg_msg, 1);
    const buf_arg_signature = diplomatRuntime.DiplomatBuf.slice(wasm, arg_signature, 1);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.SignatureAlgorithm_verify(diplomat_receive_buffer, this.underlying, arg_public_key.underlying, buf_arg_msg.ptr, buf_arg_msg.size, buf_arg_signature.ptr, buf_arg_signature.size);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = {};
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
    buf_arg_msg.free();
    buf_arg_signature.free();
    return diplomat_out;
  }
}
