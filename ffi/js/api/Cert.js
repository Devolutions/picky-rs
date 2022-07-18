import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { CertType_js_to_rust, CertType_rust_to_js } from "./CertType.js"
import { Pem } from "./Pem.js"
import { PickyError } from "./PickyError.js"
import { PublicKey } from "./PublicKey.js"
import { UtcDate } from "./UtcDate.js"

const Cert_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.Cert_destroy(underlying);
});

export class Cert {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      Cert_box_destroy_registry.register(this, underlying);
    }
  }

  static from_der(arg_der) {
    const buf_arg_der = diplomatRuntime.DiplomatBuf.slice(wasm, arg_der, 1);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.Cert_from_der(diplomat_receive_buffer, buf_arg_der.ptr, buf_arg_der.size);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new Cert(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
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

  static from_pem(arg_pem) {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.Cert_from_pem(diplomat_receive_buffer, arg_pem.underlying);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new Cert(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
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
      wasm.Cert_to_pem(diplomat_receive_buffer, this.underlying);
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

  get_ty() {
    return CertType_rust_to_js[wasm.Cert_get_ty(this.underlying)];
  }

  get_public_key() {
    return new PublicKey(wasm.Cert_get_public_key(this.underlying), true, []);
  }

  get_cert_type() {
    return CertType_rust_to_js[wasm.Cert_get_cert_type(this.underlying)];
  }

  get_valid_not_before() {
    return new UtcDate(wasm.Cert_get_valid_not_before(this.underlying), true, []);
  }

  get_valid_not_after() {
    return new UtcDate(wasm.Cert_get_valid_not_after(this.underlying), true, []);
  }

  get_subject_key_id_hex() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.Cert_get_subject_key_id_hex(diplomat_receive_buffer, this.underlying, writeable);
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

  get_subject_name() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.Cert_get_subject_name(diplomat_receive_buffer, this.underlying, writeable);
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

  get_issuer_name() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.Cert_get_issuer_name(diplomat_receive_buffer, this.underlying, writeable);
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
