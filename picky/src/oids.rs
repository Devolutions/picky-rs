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
}
