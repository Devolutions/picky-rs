import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { PickyError } from "./PickyError.js"
import { SshCertBuilder } from "./SshCertBuilder.js"
import { SshCertKeyType_js_to_rust, SshCertKeyType_rust_to_js } from "./SshCertKeyType.js"
import { SshCertType_js_to_rust, SshCertType_rust_to_js } from "./SshCertType.js"
import { SshPublicKey } from "./SshPublicKey.js"

const SshCert_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.SshCert_destroy(underlying);
});

export class SshCert {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      SshCert_box_destroy_registry.register(this, underlying);
    }
  }

  static builder() {
    return new SshCertBuilder(wasm.SshCert_builder(), true, []);
  }

  static parse(arg_repr) {
    const buf_arg_repr = diplomatRuntime.DiplomatBuf.str(wasm, arg_repr);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.SshCert_parse(diplomat_receive_buffer, buf_arg_repr.ptr, buf_arg_repr.size);
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
    buf_arg_repr.free();
    return diplomat_out;
  }

  to_repr() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.SshCert_to_repr(diplomat_receive_buffer, this.underlying, writeable);
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
    });
  }

  get_public_key() {
    return new SshPublicKey(wasm.SshCert_get_public_key(this.underlying), true, []);
  }

  get_ssh_key_type() {
    return SshCertKeyType_rust_to_js[wasm.SshCert_get_ssh_key_type(this.underlying)];
  }

  get_cert_type() {
    return SshCertType_rust_to_js[wasm.SshCert_get_cert_type(this.underlying)];
  }

  get_valid_after() {
    return wasm.SshCert_get_valid_after(this.underlying);
  }

  get_valid_before() {
    return wasm.SshCert_get_valid_before(this.underlying);
  }

  get_signature_key() {
    return new SshPublicKey(wasm.SshCert_get_signature_key(this.underlying), true, []);
  }

  get_key_id() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.SshCert_get_key_id(diplomat_receive_buffer, this.underlying, writeable);
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
    });
  }

  get_comment() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.SshCert_get_comment(diplomat_receive_buffer, this.underlying, writeable);
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
    });
  }
}
