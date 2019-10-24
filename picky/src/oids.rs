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
#[inline(always)]
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
    EMAIL_ADDRESS => email_address => "1.2.840.113549.1.9.1", // deprecated

    // Certicom Object Identifiers
    SECP384R1 => secp384r1 => "1.3.132.0.34",

    // attribute types
    COMMON_NAME => common_name => "2.5.4.3",
    SERIAL_NUMBER => serial_number => "2.5.4.5",
    COUNTRY_NAME => country_name => "2.5.4.6",
    LOCALITY_NAME => locality_name => "2.5.4.7",
    STATE_OR_PROVINCE_NAME => state_or_province_name => "2.5.4.8",
    ORGANISATION_NAME => organisation_name => "2.5.4.10",
    ORGANISATIONAL_UNIT_NAME => organisational_unit_name => "2.5.4.11",

    // certificate extensions
    SUBJECT_KEY_IDENTIFIER => subject_key_identifier => "2.5.29.14",
    KEY_USAGE => key_usage => "2.5.29.15",
    BASIC_CONSTRAINTS => basic_constraints => "2.5.29.19",
    AUTHORITY_KEY_IDENTIFIER => authority_key_identifier => "2.5.29.35",
}
