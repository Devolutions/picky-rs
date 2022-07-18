import { FFIError } from "./diplomat-runtime"
import { CertType } from "./CertType";
import { Pem } from "./Pem";
import { PickyError } from "./PickyError";
import { PublicKey } from "./PublicKey";
import { UtcDate } from "./UtcDate";

/**
 */
export class Cert {

  /**

   * Parses a X509 certificate from its DER representation.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_der(der: Uint8Array): Cert | never;

  /**

   * Extracts X509 certificate from PEM object.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static from_pem(pem: Pem): Cert | never;

  /**

   * Exports the X509 certificate into a PEM object
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_pem(): Pem | never;

  /**
   */
  get_ty(): CertType;

  /**
   */
  get_public_key(): PublicKey;

  /**
   */
  get_cert_type(): CertType;

  /**
   */
  get_valid_not_before(): UtcDate;

  /**
   */
  get_valid_not_after(): UtcDate;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_subject_key_id_hex(): string | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_subject_name(): string | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_issuer_name(): string | never;
}
