import { FFIError } from "./diplomat-runtime"
import { Pem } from "./Pem";
import { PickyError } from "./PickyError";

/**
 */
export class PublicKey {

  /**

   * Extracts public key from PEM object.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_pem(pem: Pem): PublicKey | never;

  /**

   * Reads a public key from its DER encoding.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_der(der: Uint8Array): PublicKey | never;

  /**

   * Exports the public key into a PEM object
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_pem(): Pem | never;
}
