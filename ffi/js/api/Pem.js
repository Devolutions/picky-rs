import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { PickyError } from "./PickyError.js"

const Pem_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.Pem_destroy(underlying);
});

export class Pem {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      Pem_box_destroy_registry.register(this, underlying);
    }
  }

  static new(arg_label, arg_data) {
    const buf_arg_label = diplomatRuntime.DiplomatBuf.str(wasm, arg_label);
    const buf_arg_data = diplomatRuntime.DiplomatBuf.slice(wasm, arg_data, 1);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.Pem_new(diplomat_receive_buffer, buf_arg_label.ptr, buf_arg_label.size, buf_arg_data.ptr, buf_arg_data.size);
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
    buf_arg_label.free();
    buf_arg_data.free();
    return diplomat_out;
  }

  static load_from_file(arg_path) {
    const buf_arg_path = diplomatRuntime.DiplomatBuf.str(wasm, arg_path);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.Pem_load_from_file(diplomat_receive_buffer, buf_arg_path.ptr, buf_arg_path.size);
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
    buf_arg_path.free();
    return diplomat_out;
  }

  save_to_file(arg_path) {
    const buf_arg_path = diplomatRuntime.DiplomatBuf.str(wasm, arg_path);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.Pem_save_to_file(diplomat_receive_buffer, this.underlying, buf_arg_path.ptr, buf_arg_path.size);
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
    buf_arg_path.free();
    return diplomat_out;
  }

  static parse(arg_input) {
    const buf_arg_input = diplomatRuntime.DiplomatBuf.str(wasm, arg_input);
    const diplomat_out = (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.Pem_parse(diplomat_receive_buffer, buf_arg_input.ptr, buf_arg_input.size);
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
    buf_arg_input.free();
    return diplomat_out;
  }

  get_data_length() {
    return wasm.Pem_get_data_length(this.underlying);
  }

  get_label() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.Pem_get_label(diplomat_receive_buffer, this.underlying, writeable);
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

  to_repr() {
    return diplomatRuntime.withWriteable(wasm, (writeable) => {
      return (() => {
        const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
        wasm.Pem_to_repr(diplomat_receive_buffer, this.underlying, writeable);
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
