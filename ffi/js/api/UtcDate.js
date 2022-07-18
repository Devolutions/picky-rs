import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"
import { PickyError } from "./PickyError.js"

const UtcDate_box_destroy_registry = new FinalizationRegistry(underlying => {
  wasm.UtcDate_destroy(underlying);
});

export class UtcDate {
  #lifetimeEdges = [];
  constructor(underlying, owned, edges) {
    this.underlying = underlying;
    this.#lifetimeEdges.push(...edges);
    if (owned) {
      UtcDate_box_destroy_registry.register(this, underlying);
    }
  }

  static new(arg_year, arg_month, arg_day, arg_hour, arg_minute, arg_second) {
    return (() => {
      const option_ptr = wasm.UtcDate_new(arg_year, arg_month, arg_day, arg_hour, arg_minute, arg_second);
      return (option_ptr == 0) ? null : new UtcDate(option_ptr, true, []);
    })();
  }

  static ymd(arg_year, arg_month, arg_day) {
    return (() => {
      const option_ptr = wasm.UtcDate_ymd(arg_year, arg_month, arg_day);
      return (option_ptr == 0) ? null : new UtcDate(option_ptr, true, []);
    })();
  }

  static now() {
    return new UtcDate(wasm.UtcDate_now(), true, []);
  }

  static from_timestamp(arg_timestamp) {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(5, 4);
      wasm.UtcDate_from_timestamp(diplomat_receive_buffer, arg_timestamp);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 4);
      if (is_ok) {
        const ok_value = new UtcDate(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 5, 4);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }

  get_timestamp() {
    return (() => {
      const diplomat_receive_buffer = wasm.diplomat_alloc(9, 8);
      wasm.UtcDate_get_timestamp(diplomat_receive_buffer, this.underlying);
      const is_ok = diplomatRuntime.resultFlag(wasm, diplomat_receive_buffer, 8);
      if (is_ok) {
        const ok_value = (new BigInt64Array(wasm.memory.buffer, diplomat_receive_buffer, 1))[0];
        wasm.diplomat_free(diplomat_receive_buffer, 9, 8);
        return ok_value;
      } else {
        const throw_value = new PickyError(diplomatRuntime.ptrRead(wasm, diplomat_receive_buffer), true, []);
        wasm.diplomat_free(diplomat_receive_buffer, 9, 8);
        throw new diplomatRuntime.FFIError(throw_value);
      }
    })();
  }

  get_month() {
    return wasm.UtcDate_get_month(this.underlying);
  }

  get_day() {
    return wasm.UtcDate_get_day(this.underlying);
  }

  get_hour() {
    return wasm.UtcDate_get_hour(this.underlying);
  }

  get_minute() {
    return wasm.UtcDate_get_minute(this.underlying);
  }

  get_second() {
    return wasm.UtcDate_get_second(this.underlying);
  }

  get_year() {
    return wasm.UtcDate_get_year(this.underlying);
  }
}
