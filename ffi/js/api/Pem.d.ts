import { u64 } from "./diplomat-runtime"
import { FFIError } from "./diplomat-runtime"
import { PickyError } from "./PickyError";

/**

 * PEM object.
 */
export class Pem {

  /**

   * Creates a PEM object with the given label and data.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static new(label: string, data: Uint8Array): Pem | never;

  /**

   * Loads a PEM from the filesystem.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static load_from_file(path: string): Pem | never;

  /**

   * Saves this PEM object to the filesystem.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  save_to_file(path: string): void | never;

  /**

   * Parses a PEM-encoded string representation.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static parse(input: string): Pem | never;

  /**

   * Returns the length of the data contained by this PEM object.
   */
  get_data_length(): u64;

  /**

   * Returns the label of this PEM object.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_label(): string | never;

  /**

   * Returns the string representation of this PEM object.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_repr(): string | never;
}
