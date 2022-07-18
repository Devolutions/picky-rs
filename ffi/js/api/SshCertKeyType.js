import wasm from "../wasm.mjs"
import * as diplomatRuntime from "./diplomat-runtime.js"

export const SshCertKeyType_js_to_rust = {
  "SshRsaV01": 0,
  "SshDssV01": 1,
  "RsaSha2_256V01": 2,
  "RsaSha2_512v01": 3,
  "EcdsaSha2Nistp256V01": 4,
  "EcdsaSha2Nistp384V01": 5,
  "EcdsaSha2Nistp521V01": 6,
  "SshEd25519V01": 7,
};

export const SshCertKeyType_rust_to_js = {
  0: "SshRsaV01",
  1: "SshDssV01",
  2: "RsaSha2_256V01",
  3: "RsaSha2_512v01",
  4: "EcdsaSha2Nistp256V01",
  5: "EcdsaSha2Nistp384V01",
  6: "EcdsaSha2Nistp521V01",
  7: "SshEd25519V01",
};

export const SshCertKeyType = {
  "SshRsaV01": "SshRsaV01",
  "SshDssV01": "SshDssV01",
  "RsaSha2_256V01": "RsaSha2_256V01",
  "RsaSha2_512v01": "RsaSha2_512v01",
  "EcdsaSha2Nistp256V01": "EcdsaSha2Nistp256V01",
  "EcdsaSha2Nistp384V01": "EcdsaSha2Nistp384V01",
  "EcdsaSha2Nistp521V01": "EcdsaSha2Nistp521V01",
  "SshEd25519V01": "SshEd25519V01",
};
