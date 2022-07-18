import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"

export const CertType_js_to_rust = {
  "Root": 0,
  "Intermediate": 1,
  "Leaf": 2,
  "Unknown": 3,
};

export const CertType_rust_to_js = {
  0: "Root",
  1: "Intermediate",
  2: "Leaf",
  3: "Unknown",
};

export const CertType = {
  "Root": "Root",
  "Intermediate": "Intermediate",
  "Leaf": "Leaf",
  "Unknown": "Unknown",
};
