
/**

 * SSH key type.
 */
export enum SshCertKeyType {
  /**
   */
  SshRsaV01 = 'SshRsaV01',
  /**
   */
  SshDssV01 = 'SshDssV01',
  /**
   */
  RsaSha2_256V01 = 'RsaSha2_256V01',
  /**
   */
  RsaSha2_512v01 = 'RsaSha2_512v01',
  /**
   */
  EcdsaSha2Nistp256V01 = 'EcdsaSha2Nistp256V01',
  /**
   */
  EcdsaSha2Nistp384V01 = 'EcdsaSha2Nistp384V01',
  /**
   */
  EcdsaSha2Nistp521V01 = 'EcdsaSha2Nistp521V01',
  /**
   */
  SshEd25519V01 = 'SshEd25519V01',
}