import { u64 } from "./diplomat-runtime"
import { FFIError } from "./diplomat-runtime"
import { PickyError } from "./PickyError";
import { SshCertBuilder } from "./SshCertBuilder";
import { SshCertKeyType } from "./SshCertKeyType";
import { SshCertType } from "./SshCertType";
import { SshPublicKey } from "./SshPublicKey";

/**
 */
export class SshCert {

  /**
   */
  static builder(): SshCertBuilder;

  /**

   * Parses string representation of a SSH Certificate.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  static parse(repr: string): SshCert | never;

  /**

   * Returns the SSH Certificate string representation.
   * @throws {@link FFIError}<{@link PickyError}>
   */
  to_repr(): string | never;

  /**
   */
  get_public_key(): SshPublicKey;

  /**
   */
  get_ssh_key_type(): SshCertKeyType;

  /**
   */
  get_cert_type(): SshCertType;

  /**
   */
  get_valid_after(): u64;

  /**
   */
  get_valid_before(): u64;

  /**
   */
  get_signature_key(): SshPublicKey;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_key_id(): string | never;

  /**
   * @throws {@link FFIError}<{@link PickyError}>
   */
  get_comment(): string | never;
}
