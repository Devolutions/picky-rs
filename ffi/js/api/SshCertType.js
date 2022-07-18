import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"

export const SshCertType_js_to_rust = {
  "Client": 0,
  "Host": 1,
};

export const SshCertType_rust_to_js = {
  0: "Client",
  1: "Host",
};

export const SshCertType = {
  "Client": "Client",
  "Host": "Host",
};
