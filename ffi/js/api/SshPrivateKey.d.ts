import { u32 } from "./diplomat-runtime"
import { FFIError } from "./diplomat-runtime"
import { Pem } from "./Pem";
import { PickyError } from "./PickyError";
import { PrivateKey } from "./PrivateKey";
import { SshPublicKey } from "./SshPublicKey";

/**

 * SSH Private Key.
 */
export class SshPrivateKey {

  /**

   * Generates a new SSH RSA Private Key.

   * No passphrase is set if `passphrase` is empty.

   * No comment is set if `comment` is empty.

   * This is slow in debug builds.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static generate_rsa(bits: usize, passphrase: string, comment: string): SshPrivateKey | never;

  /**

   * Extracts SSH Private Key from PEM object.

   * No passphrase is set if `passphrase` is empty.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_pem(pem: Pem, passphrase: string): SshPrivateKey | never;

  /**
   */
  static from_private_key(key: PrivateKey): SshPrivateKey;

  /**

   * Exports the SSH Private Key into a PEM object
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_pem(): Pem | never;

  /**

   * Returns the SSH Private Key string representation.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_repr(): string | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_cipher_name(): string | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_comment(): string | never;

  /**

   * Extracts the public part of this private key
   */
  to_public_key(): SshPublicKey;
}
