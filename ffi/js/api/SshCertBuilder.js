import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { PickyError } from "./PickyError.js"
import { SshCert } from "./SshCert.js"
import { SshCertKeyType_js_to_rust, SshCertKeyType_rust_to_js } from "./SshCertKeyType.js"
import { SshCertType_js_to_rust, SshCertType_rust_to_js } from "./SshCertType.js"

const SshCertBuilder_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.SshCertBuilder_destroy(underlying);
});

export class SshCertBuilder {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      SshCertBuilder_box_destroy_registry.register(this, underlying);
    }
  }

  static init() {
    return new SshCertBuilder(wasm.SshCertBuilder_init(), true, []);
  }

  set_cert_key_type(arg_key_type) {
    wasm.SshCertBuilder_set_cert_key_type(this.underlying, SshCertKeyType_js_to_rust[arg_key_type]);
  }

  set_key(arg_key) {
    wasm.SshCertBuilder_set_key(this.underlying, arg_key.underlying);
  }

  set_serial(arg_serial) {
    wasm.SshCertBuilder_set_serial(this.underlying, arg_serial);
  }

  set_cert_type(arg_cert_type) {
    wasm.SshCertBuilder_set_cert_type(this.underlying, SshCertType_js_to_rust[arg_cert_type]);
  }

  set_key_id(arg_key_id) {
    const buf_arg_key_id = diplomatRuntime.DiplomatBuf.str(wasm, arg_key_id);
    wasm.SshCertBuilder_set_key_id(this.underlying, buf_arg_key_id.ptr, buf_arg_key_id.size);
    buf_arg_key_id.free();
  }

  set_valid_before(arg_valid_before) {
    wasm.SshCertBuilder_set_valid_before(this.underlying, arg_valid_before);
  }

  set_valid_after(arg_valid_after) {
    wasm.SshCertBuilder_set_valid_after(this.underlying, arg_valid_after);
  }

  set_signature_key(arg_signature_key) {
    wasm.SshCertBuilder_set_signature_key(this.underlying, arg_signature_key.underlying);
  }

  set_signature_algo(arg_signature_algo) {
    wasm.SshCertBuilder_set_signature_algo(this.underlying, arg_signature_algo.underlying);
  }

  set_comment(arg_comment) {
    const buf_arg_comment = diplomatRuntime.DiplomatBuf.str(wasm, arg_comment);
    wasm.SshCertBuilder_set_comment(this.underlying, buf_arg_comment.ptr, buf_arg_comment.size);
    buf_arg_comment.free();
  }

  build() {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.SshCertBuilder_build(diplomat_receive_buffer, this.underlying);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new SshCert(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
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
