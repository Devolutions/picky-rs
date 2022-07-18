import { FFIError } from "./diplomat-runtime"
import { HashAlgorithm } from "./HashAlgorithm";
import { PickyError } from "./PickyError";
import { PublicKey } from "./PublicKey";

/**
 */
export class SignatureAlgorithm {

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static new_rsa_pkcs_1v15(hash_algorithm: HashAlgorithm): SignatureAlgorithm | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  verify(public_key: PublicKey, msg: Uint8Array, signature: Uint8Array): void | never;
}
