import { FFIError } from "./diplomat-runtime"
import { PickyError } from "./PickyError";

/**

 * SSH Public Key.
 */
export class SshPublicKey {

  /**

   * Parses string representation of a SSH Public Key.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static parse(repr: string): SshPublicKey | never;

  /**

   * Returns the SSH Public Key string representation.

   * It is generally represented as: "(algorithm) (der for the key) (comment)" where (comment) is usually an email address.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_repr(): string | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_comment(): string | never;
}
