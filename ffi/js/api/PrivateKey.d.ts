import { u32 } from "./diplomat-runtime"
import { FFIError } from "./diplomat-runtime"
import { Pem } from "./Pem";
import { PickyError } from "./PickyError";
import { PublicKey } from "./PublicKey";

/**
 */
export class PrivateKey {

  /**

   * Extracts private key from PEM object.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_pem(pem: Pem): PrivateKey | never;

  /**

   * Reads a private key from its PKCS8 storage.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_pkcs8(pkcs8: Uint8Array): PrivateKey | never;

  /**

   * Generates a new RSA private key.

   * This is slow in debug builds.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static generate_rsa(bits: usize): PrivateKey | never;

  /**

   * Exports the private key into a PEM object
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_pem(): Pem | never;

  /**

   * Extracts the public part of this private key
   */
  to_public_key(): PublicKey;
}
