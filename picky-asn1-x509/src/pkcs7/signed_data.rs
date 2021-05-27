use super::content_info::EncapsulatedContentInfo;
use super::crls::RevocationInfoChoices;
use super::signer_info::SignerInfo;
use crate::cmsversion::CmsVersion;
use crate::{AlgorithmIdentifier, Certificate};
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::Asn1SetOf;
use serde::{de, ser, Deserialize, Serialize};

/// [RFC 5652 #5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1)
/// ``` not_rust
/// SignedData ::= SEQUENCE {
///         version CMSVersion,
///         digestAlgorithms DigestAlgorithmIdentifiers,
///         encapContentInfo EncapsulatedContentInfo,
///         certificates [0] IMPLICIT CertificateSet OPTIONAL,
///         crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///         signerInfos SignerInfos }
/// ```
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub content_info: EncapsulatedContentInfo,
    pub certificates: CertificateSet,
    pub crls: RevocationInfoChoices,
    pub signers_infos: SignersInfos,
}

/// [RFC 5652 #5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1)
/// ``` not_rust
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DigestAlgorithmIdentifiers(pub Asn1SetOf<AlgorithmIdentifier>);

/// [RFC 5652 #5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1)
/// ``` not_rust
/// SignerInfos ::= SET OF SignerInfo
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SignersInfos(pub Asn1SetOf<SignerInfo>);

/// [RFC 5652 #10.2.3](https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.3)
/// ``` not_rust
/// CertificateSet ::= SET OF CertificateChoices
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct CertificateSet(pub Vec<Certificate>);

// FIXME: This is a workaround, related to https://github.com/Devolutions/picky-rs/pull/78#issuecomment-789904165
impl ser::Serialize for CertificateSet {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        let mut raw_der = picky_asn1_der::to_vec(&self.0).unwrap_or_else(|_| vec![0]);
        raw_der[0] = Tag::APP_0.number();
        picky_asn1_der::Asn1RawDer(raw_der).serialize(serializer)
    }
}

impl<'de> de::Deserialize<'de> for CertificateSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut raw_der = picky_asn1_der::Asn1RawDer::deserialize(deserializer)?.0;
        raw_der[0] = Tag::SEQUENCE.number();
        let vec = picky_asn1_der::from_bytes(&raw_der).unwrap_or_default();
        Ok(CertificateSet(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crls::*;
    use crate::{
        oids, EncapsulatedRsaPublicKey, Extension, Extensions, KeyIdentifier, Name, NameAttr, PublicKey, RsaPublicKey,
        SubjectPublicKeyInfo, TbsCertificate, Validity, Version,
    };
    use picky_asn1::bit_string::BitString;
    use picky_asn1::date::UTCTime;
    use picky_asn1::restricted_string::{IA5String, PrintableString};
    use picky_asn1::wrapper::{IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1Container, PrintableStringAsn1};

    #[test]
    fn decode_test() {
        let pkcs7 = base64::decode(
            "MIIGOgYJKoZIhvcNAQcCoIIGKzCCBicCAQExADALBgkqhkiG9w0BBwGgggYNMIIG\
                CTCCA/GgAwIBAgIUOnS/zC1zk2aJttmSVNtzX8rhMXwwDQYJKoZIhvcNAQELBQAw\
                gZMxCzAJBgNVBAYTAlVBMRIwEAYDVQQIDAlIdW1ibGVHdXkxETAPBgNVBAcMCFNv\
                bWVDaXR5MRkwFwYDVQQKDBBTb21lT3JnYW5pemF0aW9uMREwDwYDVQQLDAhTb21l\
                VW5pdDEMMAoGA1UEAwwDR3V5MSEwHwYJKoZIhvcNAQkBFhJzb21lZW1haWxAbWFp\
                bC5jb20wHhcNMjEwNDIzMTQzMzQzWhcNMjIwNDIzMTQzMzQzWjCBkzELMAkGA1UE\
                BhMCVUExEjAQBgNVBAgMCUh1bWJsZUd1eTERMA8GA1UEBwwIU29tZUNpdHkxGTAX\
                BgNVBAoMEFNvbWVPcmdhbml6YXRpb24xETAPBgNVBAsMCFNvbWVVbml0MQwwCgYD\
                VQQDDANHdXkxITAfBgkqhkiG9w0BCQEWEnNvbWVlbWFpbEBtYWlsLmNvbTCCAiIw\
                DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAM6JtTiGxVFdQr0r5hpBioObluoZ\
                UW/u4RMPLlb4xwuIVM+q7Xk968c8FKoxMsTGPfjfF6CBHhvcZTojYRLqFdHaYRzl\
                +m5gnR6ZJRYGOtH7dyFX+2UgTIuLxsBPoXoY/DICpUp2sch8eXmi+lwL1A8Kk9pM\
                CB0s0+nVwNLqpa6aZg5kFkverZzn8tdV8z2yg/BV1fx7FGIDYFuoqc10azEg9aa8\
                bq1psf4c4IrymFEBvuXlvi/vukY/hUPFLHDAjt6vQeDNT0GjsPIj7Fb5ISLEVbBb\
                qMKq0Atr6Af2avtIMudTVm+BT9QlX1gUr83GLiIhsPbS/WBPJcdeWLxvjWIUIJNo\
                hIJkL6YhYhkeniNN5Pq0zrhkSGNt5ai2ZeW/D4npEeCbR7gjsQm8LPJDrnDH3Iax\
                KvPgxen/rCMfssgw6UUWUEGn3n6QPtBp7HcWe+oBQOEuL6zIJKG8XzEypn6EZm+x\
                p7TjCcUgRm1X5OtDnc8E8yHsrs9dKLhzLARs6XDgcw1KhfhzryLY6VsjZD9mm5iu\
                PVgw0Hg+v4cxekWYcjJWCf6EjsCV9iax4UwGb1G7yD5XsYULajZOYqRYNak2Jruu\
                18daA66TQ8HNas25YFFQQQtQG/1RrL1u853DBlrxaNcZQfR6mkE1D7O5MUADqjoM\
                pgoL7k2XqkJMjs/PAgMBAAGjUzBRMB0GA1UdDgQWBBQAX8F1PgwVwxbjCDdpvYKI\
                0YW9DTAfBgNVHSMEGDAWgBQAX8F1PgwVwxbjCDdpvYKI0YW9DTAPBgNVHRMBAf8E\
                BTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQAH3Qweqt8+PnQoAKTPXTUMp+lE01a0\
                2vzoc7EPWiclyuQPatlUIyUEH5nbBiXu8v9X5wHIrfzkV7tO+clVy9w6a4Fhnejv\
                2zurSHf6vP/UEq2gPuBJ1jc1BDpE4TtlZdrO6GYBQwETRBbw44lFvyk6sjnCHPgz\
                nl5dryWIyNSALFpSzUJ9xSdtzWEKnWe9NaxBc6b0RxJSsRl33Fx25WkKMuhY4j26\
                wZvWMSj86eRdI7BP31UGEt8GdfQscz5JtMlY+eJbilAMTZt4iAEJFv9OI7/asVJv\
                u8oNZJewGstWqRyRrJcHeEINjxeKL0quKJQF38fCd6pqRI7PlPBaGfVCSHTggpKO\
                yD0ACcE13kcjnOwa8J/DFFZVpI3oofGUE+hajJT09vGJv4NJKUfdJIuieEFeJe8B\
                TPkVjCHp6j6Vj56EdGqvkYtVsuzHUNlIsEcpXGEiODbwbps7GxPCiurVIldun2Gu\
                1mq8Q6aU+yh5Fs5ZsSXozzXyWqwPkT5WbJEOAUMd2+JSRHN83MOSqq+igpDBKQZQ\
                t5vcoqFzuspOVIvdPLFY3pPZY9dxVNdDi4T6qJNZCq++Ukyc0LQOUkshF9HaHB3I\
                xUDGjR5n4X0lkjgM5IvL+OaZREqWkD/tiCu4V/5Z86mZi6VwCcgYrp/Q4bFjsWBw\
                p0mAUFZ9UjurAaEAMQA=",
        )
        .unwrap();

        assert_eq!(CmsVersion::V1, CmsVersion::from_u8(*pkcs7.get(25).unwrap()).unwrap());

        let digest_algorithm_identifiers = DigestAlgorithmIdentifiers(vec![].into());

        check_serde!(digest_algorithm_identifiers: DigestAlgorithmIdentifiers in pkcs7[26..28]);

        let content_info = EncapsulatedContentInfo {
            content_type: ObjectIdentifierAsn1::from(oids::pkcs7()),
            content: None,
        };

        check_serde!(content_info: EncapsulatedContentInfo in pkcs7[28..41]);

        let mut issuer = Name::new();
        issuer.add_attr(
            NameAttr::CountryName,
            PrintableStringAsn1::from(PrintableString::new("UA".as_bytes()).unwrap()),
        );
        issuer.add_attr(NameAttr::StateOrProvinceName, "HumbleGuy");
        issuer.add_attr(NameAttr::LocalityName, "SomeCity");
        issuer.add_attr(NameAttr::OrganizationName, "SomeOrganization");
        issuer.add_attr(NameAttr::OrganizationalUnitName, "SomeUnit");
        issuer.add_attr(NameAttr::CommonName, "Guy");
        issuer.add_email(IA5String::new("someemail@mail.com".as_bytes()).unwrap());

        check_serde!(issuer: Name in pkcs7[95..245]);

        let validity = Validity {
            not_before: UTCTime::new(2021, 4, 23, 14, 33, 43).unwrap().into(),
            not_after: UTCTime::new(2022, 4, 23, 14, 33, 43).unwrap().into(),
        };

        check_serde!(validity: Validity in pkcs7[245..277]);

        let subject = issuer.clone();

        check_serde!(subject: Name in pkcs7[277..427]);

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::new_rsa_encryption(),
            subject_public_key: PublicKey::Rsa(EncapsulatedRsaPublicKey::from(RsaPublicKey {
                modulus: IntegerAsn1::from(pkcs7[459..972].to_vec()),
                public_exponent: IntegerAsn1::from(pkcs7[974..977].to_vec()),
            })),
        };

        check_serde!(subject_public_key_info: SubjectPublicKeyInfo in pkcs7[427..977]);

        let extensions = Extensions(vec![
            Extension::new_subject_key_identifier(pkcs7[992..1012].to_vec()),
            Extension::new_authority_key_identifier(KeyIdentifier::from(pkcs7[1025..1045].to_vec()), None, None),
            Extension::new_basic_constraints(*pkcs7.get(1054).unwrap() != 0, None),
        ]);

        check_serde!(extensions: Extensions in  pkcs7[979..1062]);

        let full_certificate = Certificate {
            tbs_certificate: TbsCertificate {
                version: Version::V3.into(),
                serial_number: IntegerAsn1(pkcs7[60..80].to_vec()),
                signature: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
                issuer,
                validity,
                subject,
                subject_public_key_info,
                extensions: extensions.into(),
            },
            signature_algorithm: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
            signature_value: BitString::with_bytes(&pkcs7[1082..1594]).into(),
        };
        check_serde!(full_certificate: Certificate in pkcs7[45..1594]);

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: DigestAlgorithmIdentifiers(Vec::new().into()),
            content_info,
            certificates: CertificateSet(vec![full_certificate]),
            crls: RevocationInfoChoices(Vec::new()),
            signers_infos: SignersInfos(Vec::new().into()),
        };

        check_serde!(signed_data: SignedData in pkcs7[19..1598]);
    }

    #[test]
    fn decode_with_crl() {
        let decoded = base64::decode(
            "MIIIxwYJKoZIhvcNAQcCoIIIuDCCCLQCAQExADALBgkqhkiG9w0BBwGgggXJMIIF\
                xTCCA62gAwIBAgIUFYedpm34R9SrNONqEn43NrNlDHMwDQYJKoZIhvcNAQELBQAw\
                cjELMAkGA1UEBhMCZmYxCzAJBgNVBAgMAmZmMQswCQYDVQQHDAJmZjELMAkGA1UE\
                CgwCZmYxCzAJBgNVBAsMAmZmMQ8wDQYDVQQDDAZDQU5hbWUxHjAcBgkqhkiG9w0B\
                CQEWD2NhbWFpbEBtYWlsLmNvbTAeFw0yMTA0MTkxNTQxNDlaFw0yNjA0MTkxNTQx\
                NDlaMHIxCzAJBgNVBAYTAmZmMQswCQYDVQQIDAJmZjELMAkGA1UEBwwCZmYxCzAJ\
                BgNVBAoMAmZmMQswCQYDVQQLDAJmZjEPMA0GA1UEAwwGQ0FOYW1lMR4wHAYJKoZI\
                hvcNAQkBFg9jYW1haWxAbWFpbC5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw\
                ggIKAoICAQCwVfg08dBZyObLkyZufYCZ396B17ICMAjYUWjk2pfK3Q/3C0vCjppd\
                F5VW0g49D/ULV7tzRc3AZecw9RxHuwkeXioIZ6NQ92qdg8CnkOPLrSyDlMyDZgYU\
                NSFdpz81Bu0v17sUHfREz41Wi5CvdK9qSS/IiuZhEpKYx1trGAc22YwXLBGs6Dcb\
                jf3C8zRnG1FCsOYukaG6wUdzUtwkrgOIIMERTqZ1U5s0rXehg4Kb3chAsA31xvKT\
                UhMNfovjI+5FDB/ZjZOOPMobnN6E7DLFjBzpa11eFywPFvimNxWjN26HkEceIh7y\
                Hm/9GrlSvpXnZQRFNNKIIQBkHt6jbpByxIhU9Yq0uWSZNWk+c34H6sksWZtJpVvM\
                YWIGziatkr2Rjskn9xjSNFNHacj5u3j2KKGxCtkxrCXiLY9Chf1CfbhmLpdECTPW\
                fgOOzXu/GIFXaxsh0+NqodEChaA5GDztweqt7Ep3/V9c/ITWONzj8SOj97R5OYy8\
                rtu24YY+ft2PkRYRSwsJzHs4KfDaf1yN0WCBZSl1itVW7qsEKQ60pp4qOna8XbyN\
                6VY3ce/qhKYPZKs9pFWX5vBTtAFcA4HjmT/EkHJ2ISJU0ueU0E6iH9Q01ENk1dso\
                dDMKP354kqmuHW4I0Wc39tJsXdUsGaisVyfOZdJQpqc2sle6LR8WpQIDAQABo1Mw\
                UTAdBgNVHQ4EFgQUxy69gEp87JxLsLZKmjYUObTIei4wHwYDVR0jBBgwFoAUxy69\
                gEp87JxLsLZKmjYUObTIei4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF\
                AAOCAgEAZzl2JCK3+5lm5vkcidD4swafCkE+kKuS27Ta7RVjfvEmZQmE69meMxuS\
                PZ/xcB2EVF+zTMw5qmtOiCFrN90sR5lGHhdkqFDMAhQtu7aGz9rJ8s9R4Hx8NWXk\
                d9H6USqWd6O3OIVl4cB7HZEdn4Y+oVgtSd48EAK4C/a2a9NLsrpPgGAB2m3wGRBY\
                l9ynvaR9hMXc0qQ/s/BseA/UvEaVVd1mxKcTeL4dGQpBJ9bKYbesJGHJssRnSlDb\
                AMI5tgoIYPadumNEqmDZL+eH798lfnyXCLokSZk/I7a4TLgtTnlubbFnapu8M645\
                qOS2VWzKnqRYC31DDWy5PcI/eDfLNCzrben9I6nSAx5AFOfi8z7znAwXw1fGcUEw\
                BPSzK91KHZkqsOaK/kExja32xeSSy7SW1dBHmwaDbA0kv7COPYCHIWmFsrxFkB9E\
                O5P1hSnFMZmdAO2jm/k0cZQxlaYZuio0XCQEJZMvfsGL8qWV5uRdUx8D5zZQem/R\
                OHEe1tMTIqJ3BoGgX15atokFY++iVLjk/2eKv1k5Sw5m/4cxxDgcK89UH4Y1UR3u\
                ah3emGU6zySj/Y3HpFfKslewb59FZXS/RKgRHhIw1TfauuTNtT5D2LpXPYfLuTrs\
                aCpH/QGsSBGiMTmrdXukRCIsz663TKiLVYOdvY4Y+cBcJlk/YMChggLPMIICyzCB\
                tAIBATANBgkqhkiG9w0BAQUFADByMQswCQYDVQQGEwJmZjELMAkGA1UECAwCZmYx\
                CzAJBgNVBAcMAmZmMQswCQYDVQQKDAJmZjELMAkGA1UECwwCZmYxDzANBgNVBAMM\
                BkNBTmFtZTEeMBwGCSqGSIb3DQEJARYPY2FtYWlsQG1haWwuY29tFw0yMTA0MjAw\
                NjUyMjRaFw0yMzA0MjAwNjUyMjRaoA4wDDAKBgNVHRQEAwIBAzANBgkqhkiG9w0B\
                AQUFAAOCAgEAW/+H6pzGp6cRUssck1a5pAJo2V98gpLX5gnPoorEIE2nkcLChiWc\
                RCdJuc5PtOisM/FRl9IxQWpePISB3I15jaL1u1ol5ISNn69f3eWwvVEw3kJSEeb/\
                TYvqW0+k1CgMr84oP38K4/434FwfotULX36FdU04MSzMirAszjZ0kLMsb3mNSSaH\
                VC0kZs7AnvzwKBXsB143ouNAH5mmLom1EyRAWU1ZP/pFZXDGE1ct2jB+oOdZebQj\
                /4VjfGDyvzUd9cNu9i6ZqNf49E9vhemrCdkZHc94QkwO92FhBROZhQ9fKelV8CRs\
                jf2oyToe+2NN2eXj+DY/s13Knoeqb7FcD3BFObtrILvE/rrCxZa0JeHfdg79nIiG\
                BCfQloA+cZdQsCQ1H1Qd3kwqo6ZLQpeTyW0UeIJNLQiSMATvpMAtunwT/OgxSP/Q\
                eTXV+221Eu2tDhXYMVkFtjgFdp0O5XqPU5fNPF/5XL3DlgAaWe9ULl4ZwBNPSkOm\
                LiFMcN1hzGQQo00ycuU6eF+Iz+H/olJyrpdJxf0jh2Sok71LX6YlALvfvZjW5eYc\
                8AvDttigOLiDwm8eYAxsC8Ku4cMiMSkgs71vvmz0U/LHypZiNJsEEaR76NH9OLiz\
                XCIYfP7WudYgfGBRRiw4WeB7jZNtVzFzkyiwliZLqocBuM8f1O2pv/QxAA==",
        )
        .unwrap();

        let mut issuer = Name::new();
        issuer.add_attr(NameAttr::CountryName, PrintableString::new("ff").unwrap());
        issuer.add_attr(NameAttr::StateOrProvinceName, "ff");
        issuer.add_attr(NameAttr::LocalityName, "ff");
        issuer.add_attr(NameAttr::OrganizationName, "ff");
        issuer.add_attr(NameAttr::OrganizationalUnitName, "ff");
        issuer.add_attr(NameAttr::CommonName, "CAName");
        issuer.add_email(IA5String::new("camail@mail.com").unwrap());

        let tbs_cert_list = TbsCertList {
            version: Some(Version::V2),
            signature: AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
            issuer,
            this_update: UTCTime::new(2021, 4, 20, 6, 52, 24).unwrap().into(),
            next_update: Some(UTCTime::new(2023, 4, 20, 6, 52, 24).unwrap().into()),
            revoked_certificates: None,
            crl_extension: Some(Extensions(vec![Extension::new_crl_number(OctetStringAsn1Container(
                IntegerAsn1::from(decoded[1716..1717].to_vec()),
            ))]))
            .into(),
        };

        check_serde!(tbs_cert_list: TbsCertList in decoded[1534..1717]);

        let crl = RevocationInfoChoices(vec![RevocationInfoChoice::Crl(CertificateList {
            tbs_cert_list,
            signature_algorithm: AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
            signature_value: BitString::with_bytes(&decoded[1737..2249]).into(),
        })]);

        check_serde!(crl: RevocationInfoChoices in decoded[1526..2249]);
    }
}
