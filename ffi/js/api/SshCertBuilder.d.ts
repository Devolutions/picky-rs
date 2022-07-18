import { u64 } from "./diplomat-runtime"
import { FFIError } from "./diplomat-runtime"
import { PickyError } from "./PickyError";
import { SignatureAlgorithm } from "./SignatureAlgorithm";
import { SshCert } from "./SshCert";
import { SshCertKeyType } from "./SshCertKeyType";
import { SshCertType } from "./SshCertType";
import { SshPrivateKey } from "./SshPrivateKey";
import { SshPublicKey } from "./SshPublicKey";

/**

 * SSH Certificate Builder.
 */
export class SshCertBuilder {

  /**
   */
  static init(): SshCertBuilder;

  /**

   * Required
   */
  set_cert_key_type(key_type: SshCertKeyType): void;

  /**

   * Required
   */
  set_key(key: SshPublicKey): void;

  /**

   * Optional (set to 0 by default)
   */
  set_serial(serial: u64): void;

  /**

   * Required
   */
  set_cert_type(cert_type: SshCertType): void;

  /**

   * Optional
   */
  set_key_id(key_id: string): void;

  /**

   * Required
   */
  set_valid_before(valid_before: u64): void;

  /**

   * Required
   */
  set_valid_after(valid_after: u64): void;

  /**

   * Required
   */
  set_signature_key(signature_key: SshPrivateKey): void;

  /**

   * Optional. RsaPkcs1v15 with SHA256 is used by default.
   */
  set_signature_algo(signature_algo: SignatureAlgorithm): void;

  /**

   * Optional
   */
  set_comment(comment: string): void;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  build(): SshCert | never;
}
