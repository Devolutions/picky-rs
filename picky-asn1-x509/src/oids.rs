/// Unsafely marks a branch as unreachable.
/// This won't panic if reached, however children will be sacrificed and dark magic performed.
///
/// # Unsafety
///
/// This is incredibly unsafe.
/// You can already see Hades waving his hand at you from here.
/// You shall not pass this bridge leading to insanity. Never.
/// No one can tell you what would happen if you did.
/// Only one thing is for sure: it leads to a land of desolation called UB.
/// I mean, I'm literally creating infinity out of emptiness.
/// If you don't care about your mental sanity, you can read the
/// [nomicon on unchecked uninitialized memory](https://doc.rust-lang.org/nomicon/unchecked-uninit.html).
#[allow(invalid_value)]
unsafe fn unreachable() -> ! {
    core::mem::MaybeUninit::uninit().assume_init()
}

macro_rules! define_oid {
    ($uppercase:ident => $lowercase:ident => $str_value:literal) => {
        pub const $uppercase: &'static str = $str_value;

        pub fn $lowercase() -> oid::ObjectIdentifier {
            use std::sync::Once;
            use std::convert::TryInto;

            static mut OID: Option<oid::ObjectIdentifier> = None;
            static INIT: Once = Once::new();
            unsafe {
                INIT.call_once(|| {
                    OID = Some($uppercase.try_into().unwrap())
                });
                if let Some(oid) = &OID { oid.clone() } else { unreachable() }
            }
        }
    };
    ( $( $uppercase:ident => $lowercase:ident => $str_value:literal, )+ ) => {
        $( define_oid! { $uppercase => $lowercase => $str_value } )+
    };
}

define_oid! {
    // ANSI-X962
    EC_PUBLIC_KEY => ec_public_key => "1.2.840.10045.2.1",
    ECDSA_WITH_SHA256 => ecdsa_with_sha256 => "1.2.840.10045.4.3.2",
    ECDSA_WITH_SHA384 => ecdsa_with_sha384 => "1.2.840.10045.4.3.3",

    // RSADSI
    RSA_ENCRYPTION => rsa_encryption => "1.2.840.113549.1.1.1",
    SHA1_WITH_RSA_ENCRYPTION => sha1_with_rsa_encryption => "1.2.840.113549.1.1.5",
    SHA256_WITH_RSA_ENCRYPTION => sha256_with_rsa_encryption => "1.2.840.113549.1.1.11",
    SHA384_WITH_RSA_ENCRYPTION => sha384_with_rsa_encryption => "1.2.840.113549.1.1.12",
    SHA512_WITH_RSA_ENCRYPTION => sha512_with_rsa_encryption => "1.2.840.113549.1.1.13",
    SHA224_WITH_RSA_ENCRYPTION => sha224_with_rsa_encryption => "1.2.840.113549.1.1.14",
    EMAIL_ADDRESS => email_address => "1.2.840.113549.1.9.1", // deprecated

    // NIST
    DSA_WITH_SHA224 => dsa_with_sha224 => "2.16.840.1.101.3.4.3.1",
    DSA_WITH_SHA256 => dsa_with_sha256 => "2.16.840.1.101.3.4.3.2",
    DSA_WITH_SHA384 => dsa_with_sha384 => "2.16.840.1.101.3.4.3.3",
    DSA_WITH_SHA512 => dsa_with_sha512 => "2.16.840.1.101.3.4.3.4",
    ID_ECDSA_WITH_SHA3_256 => id_ecdsa_with_sha3_256 => "2.16.840.1.101.3.4.3.10",
    ID_RSASSA_PKCS1_V1_5_WITH_SHA3_224 => id_rsassa_pkcs1_v1_5_with_sha3_224 => "2.16.840.1.101.3.4.3.13",
    ID_RSASSA_PKCS1_V1_5_WITH_SHA3_256 => id_rsassa_pkcs1_v1_5_with_sha3_256 => "2.16.840.1.101.3.4.3.14",
    ID_RSASSA_PKCS1_V1_5_WITH_SHA3_384 => id_rsassa_pkcs1_v1_5_with_sha3_384 => "2.16.840.1.101.3.4.3.15",
    ID_RSASSA_PKCS1_V1_5_WITH_SHA3_512 => id_rsassa_pkcs1_v1_5_with_sha3_512 => "2.16.840.1.101.3.4.3.16",

    // Certicom Object Identifiers
    SECP384R1 => secp384r1 => "1.3.132.0.34",

    // Extended key purpose OIDS
    KP_SERVER_AUTH => kp_server_auth => "1.3.6.1.5.5.7.3.1",
    KP_CLIENT_AUTH => kp_client_auth => "1.3.6.1.5.5.7.3.2",
    KP_CODE_SIGNING => kp_code_signing => "1.3.6.1.5.5.7.3.3",
    KP_EMAIL_PROTECTION => kp_email_protection => "1.3.6.1.5.5.7.3.4",
    KP_IPSEC_END_SYSTEM => kp_ipsec_end_system => "1.3.6.1.5.5.7.3.5",
    KP_IPSPEC_TUNNEL => kp_ipsec_tunnel => "1.3.6.1.5.5.7.3.6",
    KP_IPSEC_USER => kp_ipsec_user => "1.3.6.1.5.5.7.3.7",
    KP_TIME_STAMPING => kp_time_stamping => "1.3.6.1.5.5.7.3.8",
    KP_OCSP_SIGNING => kp_ocsp_signing => "1.3.6.1.5.5.7.3.9",
    KP_ANY_EXTENDED_KEY_USAGE => kp_any_extended_key_usage => "2.5.29.37.0",

    // attribute types
    AT_COMMON_NAME => at_common_name => "2.5.4.3",
    AT_SURNAME => at_surname => "2.5.4.4",
    AT_SERIAL_NUMBER => at_serial_number => "2.5.4.5",
    AT_COUNTRY_NAME => at_country_name => "2.5.4.6",
    AT_LOCALITY_NAME => at_locality_name => "2.5.4.7",
    AT_STATE_OR_PROVINCE_NAME => at_state_or_province_name => "2.5.4.8",
    AT_STREET_NAME => at_street_name => "2.5.4.9",
    AT_ORGANISATION_NAME => at_organisation_name => "2.5.4.10",
    AT_ORGANISATIONAL_UNIT_NAME => at_organisational_unit_name => "2.5.4.11",

    // certificate extensions
    SUBJECT_KEY_IDENTIFIER => subject_key_identifier => "2.5.29.14",
    KEY_USAGE => key_usage => "2.5.29.15",
    SUBJECT_ALTERNATIVE_NAME => subject_alternative_name => "2.5.29.17",
    ISSUER_ALTERNATIVE_NAME => issuer_alternative_name => "2.5.29.18",
    BASIC_CONSTRAINTS => basic_constraints => "2.5.29.19",
    AUTHORITY_KEY_IDENTIFIER => authority_key_identifier => "2.5.29.35",
    EXTENDED_KEY_USAGE => extended_key_usage => "2.5.29.37",

    // aes
    // aes-128
    AES128_ECB => aes128_ecb => "2.16.840.1.101.3.4.1.1",
    AES128_CBC => aes128_cbc => "2.16.840.1.101.3.4.1.2",
    AES128_OFB => aes128_ofb => "2.16.840.1.101.3.4.1.3",
    AES128_CFB => aes128_cfb => "2.16.840.1.101.3.4.1.4",
    AES128_WRAP => aes128_wrap => "2.16.840.1.101.3.4.1.5",
    AES128_GCM => aes128_gcm => "2.16.840.1.101.3.4.1.6",
    AES128_CCM => aes128_ccm => "2.16.840.1.101.3.4.1.7",
    AES128_WRAP_PAD => aes128_wrap_pad => "2.16.840.1.101.3.4.1.8",
    // aes-192
    AES192_ECB => aes192_ecb => "2.16.840.1.101.3.4.1.21",
    AES192_CBC => aes192_cbc => "2.16.840.1.101.3.4.1.22",
    AES192_OFB => aes192_ofb => "2.16.840.1.101.3.4.1.23",
    AES192_CFB => aes192_cfb => "2.16.840.1.101.3.4.1.24",
    AES192_WRAP => aes192_wrap => "2.16.840.1.101.3.4.1.25",
    AES192_GCM => aes192_gcm => "2.16.840.1.101.3.4.1.26",
    AES192_CCM => aes192_ccm => "2.16.840.1.101.3.4.1.27",
    AES192_WRAP_PAD => aes192_wrap_pad => "2.16.840.1.101.3.4.1.28",
    // aes-256
    AES256_ECB => aes256_ecb => "2.16.840.1.101.3.4.1.41",
    AES256_CBC => aes256_cbc => "2.16.840.1.101.3.4.1.42",
    AES256_OFB => aes256_ofb => "2.16.840.1.101.3.4.1.43",
    AES256_CFB => aes256_cfb => "2.16.840.1.101.3.4.1.44",
    AES256_WRAP => aes256_wrap => "2.16.840.1.101.3.4.1.45",
    AES256_GCM => aes256_gcm => "2.16.840.1.101.3.4.1.46",
    AES256_CCM => aes256_ccm => "2.16.840.1.101.3.4.1.47",
    AES256_WRAP_PAD => aes256_wrap_pad => "2.16.840.1.101.3.4.1.48",

    // hash algorithm
    SHA256 => sha256 => "2.16.840.1.101.3.4.2.1",
    SHA384 => sha384 => "2.16.840.1.101.3.4.2.2",
    SHA512 => sha512 => "2.16.840.1.101.3.4.2.3",
    SHA224 => sha224 => "2.16.840.1.101.3.4.2.4",
    SHA512_224 => sha512_224 => "2.16.840.1.101.3.4.2.5",
    SHA512_256 => sha512_256 => "2.16.840.1.101.3.4.2.6",
    SHA3_224 => sha3_224 => "2.16.840.1.101.3.4.2.7",
    SHA3_256 => sha3_256 => "2.16.840.1.101.3.4.2.8",
    SHA3_384 => sha3_384 => "2.16.840.1.101.3.4.2.9",
    SHA3_512 => sha3_512 => "2.16.840.1.101.3.4.2.10",
    SHAKE128 => shake128 => "2.16.840.1.101.3.4.2.11",
    SHAKE256 => shake256 => "2.16.840.1.101.3.4.2.12",
}
