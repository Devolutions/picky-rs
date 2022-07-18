import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"

export const HashAlgorithm_js_to_rust = {
  "MD5": 0,
  "SHA1": 1,
  "SHA2_224": 2,
  "SHA2_256": 3,
  "SHA2_384": 4,
  "SHA2_512": 5,
  "SHA3_384": 6,
  "SHA3_512": 7,
  "Unknown": 8,
};

export const HashAlgorithm_rust_to_js = {
  0: "MD5",
  1: "SHA1",
  2: "SHA2_224",
  3: "SHA2_256",
  4: "SHA2_384",
  5: "SHA2_512",
  6: "SHA3_384",
  7: "SHA3_512",
  8: "Unknown",
};

export const HashAlgorithm = {
  "MD5": "MD5",
  "SHA1": "SHA1",
  "SHA2_224": "SHA2_224",
  "SHA2_256": "SHA2_256",
  "SHA2_384": "SHA2_384",
  "SHA2_512": "SHA2_512",
  "SHA3_384": "SHA3_384",
  "SHA3_512": "SHA3_512",
  "Unknown": "Unknown",
};
