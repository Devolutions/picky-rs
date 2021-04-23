use picky_asn1::{tag::Tag, wrapper::Asn1SetOf};
use serde::{de, ser, Deserialize, Serialize};

use super::{content_info::ContentInfo, crls::RevocationInfoChoices, singer_info::SingersInfos};
use crate::{AlgorithmIdentifier, Certificate, Version};

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct SignedData {
    pub version: Version,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub content_info: ContentInfo,
    pub certificates: ExtendedCertificatesAndCertificates,
    pub crls: RevocationInfoChoices,
    pub singers_infos: SingersInfos,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct DigestAlgorithmIdentifiers(pub Asn1SetOf<AlgorithmIdentifier>);

#[derive(Debug, PartialEq, Clone)]
pub struct ExtendedCertificatesAndCertificates(pub Vec<Certificate>);

// FIXME: This is a workaround, related to https://github.com/Devolutions/picky-rs/pull/78#issuecomment-789904165

impl ser::Serialize for ExtendedCertificatesAndCertificates {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        let mut raw_der = picky_asn1_der::to_vec(&self.0).unwrap_or_else(|_| vec![0]);
        raw_der[0] = Tag::APP_0.number();
        picky_asn1_der::Asn1RawDer(raw_der).serialize(serializer)
    }
}

impl<'de> de::Deserialize<'de> for ExtendedCertificatesAndCertificates {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut raw_der = picky_asn1_der::Asn1RawDer::deserialize(deserializer)?.0;
        raw_der[0] = Tag::SEQUENCE.number();
        let vec = picky_asn1_der::from_bytes(&raw_der).unwrap_or_default();
        Ok(ExtendedCertificatesAndCertificates(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crls::*, oids, EncapsulatedRSAPublicKey, Extension, Extensions, KeyIdentifier, Name, NameAttr, PublicKey,
        RSAPublicKey, SubjectPublicKeyInfo, TBSCertificate, Validity,
    };
    use picky_asn1::{
        bit_string::BitString,
        date::UTCTime,
        restricted_string::{IA5String, PrintableString},
        wrapper::{
            ApplicationTag0, ApplicationTag3, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1Container,
            PrintableStringAsn1,
        },
    };

    #[test]
    fn decode_test() {
        let pkcs7 = base64::decode(
            "MIIGQgYJKoZIhvcNAQcCoIIGMzCCBi8CAQExADALBgkqhkiG9w0BBwGgggYVMIIG\
                ETCCA/mgAwIBAgIUGWNpoUt5l2nRwfsGDY8Ta+nccpIwDQYJKoZIhvcNAQELBQAw\
                gZcxCzAJBgNVBAYTAlVBMQ8wDQYDVQQIDAZEbmlwcm8xDzANBgNVBAcMBkRuaXBy\
                bzERMA8GA1UECgwIQXByaW9yaXQxFzAVBgNVBAsMDklubm92YXRpb25UZWFtMQ0w\
                CwYDVQQDDARBbGV4MSswKQYJKoZIhvcNAQkBFhxhbGVrc2FuZHIueXVzdWtAYXBy\
                aW9yaXQuY29tMB4XDTIxMDQxMzA5MDM0M1oXDTIyMDQxMzA5MDM0M1owgZcxCzAJ\
                BgNVBAYTAlVBMQ8wDQYDVQQIDAZEbmlwcm8xDzANBgNVBAcMBkRuaXBybzERMA8G\
                A1UECgwIQXByaW9yaXQxFzAVBgNVBAsMDklubm92YXRpb25UZWFtMQ0wCwYDVQQD\
                DARBbGV4MSswKQYJKoZIhvcNAQkBFhxhbGVrc2FuZHIueXVzdWtAYXByaW9yaXQu\
                Y29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4jYGtPkGlMXGGZGI\
                2zE65KrqVxWlRGdOU7281RFnkzh/sGMeWb5EIbLBqfrzAorCFjLy7xDkuU9L5A59\
                hN2AkuQeEYMeNoCTkgXy3CzyvtgYPvBnJi+Gnutu2R5gyeHGVssgJFNHhPKxPz+d\
                sXV04WnMArGdemYMU58GtvK98Xk6xrlJPatGuULv1UTsEFmU0oBSPjc20+BYKXhd\
                VvrY+Po6J5G6WttS+YPyqkkP8py3ckEW2GmpjcoRvkkhS5tWQfYD2pIHX6S4ZM4M\
                w4sIsDTHB+yfplqVESpLqSAtZycbcc3KW8k9sooh2YpOi1U+EsbC1kK1/CH8v9cp\
                k1h49Yc5DyrxWsmKWSkOTvNy60FKHEc8GR3MqmUdlB0uZt3WnQwfbq6lxj7eOOkV\
                qax6cUSoO5idSDldCZAn15l5kqUvfGMaqWH/JsPTXaTXFoADxh4uwIynAsUYSxWG\
                /uvR5GsZOy4DFOqKxd1vkfS6EtMq52VOO8Pwisax7m+9HtjybttbQSIBJE37jckx\
                e2aN5+gPrGNLYvL3NAHUzizrkMI6c9kWUw7AynAVuDSU/bea5znDV+RzZEagcGAU\
                ZysgD3x8Cn8UkDrpbDnhJM2OIzC5xvvVexvlrJ0fSZCyV6Ecj2mgopnV5uFpVIih\
                oCDWLDuAtpBfNinPxiMsX7VOxPcCAwEAAaNTMFEwHQYDVR0OBBYEFFNl9vm07mLu\
                MrLbz++XncV9NU2hMB8GA1UdIwQYMBaAFFNl9vm07mLuMrLbz++XncV9NU2hMA8G\
                A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAC07+hvXzVLbD6wxr40j\
                A2p1flTNDmccNmrkX0gxW8K0ZywNFM3z93w0ZZvTTGj6DwbhPFSDSG+6pqI+gtPw\
                uvBG/Wc32QhSBtWuFyTLNAgTM+uRwhGNowgoS4Rr/LdUOCzNE9/6ZqRNuLPy7uNE\
                maTZFcgJsGHGrGrvLY/An0SlGVjbDanJn4v5pCeAZvru3QMsqKveKpPqe0tdSTHm\
                O7aADBnOfeA2y9Q4nTaIs1ozwZjUUAbnAwMWic1U84DohgNAcf4WEgX+AAemvwmS\
                kpjZUu1gAEFd6AtIGjXvFQ1wCec+sdoCcQDIFHZHaipRC6oJRLxF6XSSL+mISntS\
                LoIWnwixCZLqRB1JOlwa9ppUihA2d5y2uUFAIpd2DUeC4Fhce3hvOUR5crHiV/We\
                ffNprfZWEPBj3YwFXdGrfgLSqDySSfcjPZW+EqrREauL8ZZPNvZN+Al4cyE9J7YW\
                qmSKgOfA4Vpda2+aQnT3B2TNmZiZZJ9c1LzTCxCOMS7fG6VUPqhd8eiqRV8eev0i\
                4tB3coLBJtQlAew9wQnd9Nw9h/b7ODF76JEyrPs4tQvQ25lVNxKOkxfYUMG/QPdk\
                6NmQ1uDSLknZfV9Gz9YV55v+Lz1jfe3+/Y4riuitT854fQnuj7xbRmqGJ5uWTOp9\
                ZjHKF8y7QKjT1anRDivi9gkvoQAxAA==",
        )
        .unwrap();

        assert_eq!(Version::V2, Version::from_u8(*pkcs7.get(25).unwrap()).unwrap());

        let digest_algorithm_identifiers = DigestAlgorithmIdentifiers(vec![].into());

        check_serde!(digest_algorithm_identifiers: DigestAlgorithmIdentifiers in pkcs7[26..28]);

        let content_info = ContentInfo {
            content_type: ObjectIdentifierAsn1::from(oids::pkcs7()),
            content: None,
        };

        check_serde!(content_info: ContentInfo in pkcs7[28..41]);

        let mut issuer = Name::new();
        issuer.add_attr(
            NameAttr::CountryName,
            PrintableStringAsn1::from(PrintableString::new("UA".as_bytes()).unwrap()),
        );
        issuer.add_attr(NameAttr::StateOrProvinceName, "Dnipro");
        issuer.add_attr(NameAttr::LocalityName, "Dnipro");
        issuer.add_attr(NameAttr::OrganizationName, "Apriorit");
        issuer.add_attr(NameAttr::OrganizationalUnitName, "InnovationTeam");
        issuer.add_attr(NameAttr::CommonName, "Alex");
        issuer.add_email(IA5String::new("aleksandr.yusuk@apriorit.com".as_bytes()).unwrap());

        check_serde!(issuer: Name in pkcs7[95..249]);

        let validity = Validity {
            not_before: UTCTime::new(2021, 4, 13, 9, 3, 43).unwrap().into(),
            not_after: UTCTime::new(2022, 4, 13, 9, 3, 43).unwrap().into(),
        };

        check_serde!(validity: Validity in pkcs7[249..281]);

        let subject = issuer.clone();

        check_serde!(subject: Name in pkcs7[281..435]);

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::new_rsa_encryption(),
            subject_public_key: PublicKey::RSA(EncapsulatedRSAPublicKey::from(RSAPublicKey {
                modulus: IntegerAsn1::from(pkcs7[467..980].to_vec()),
                public_exponent: IntegerAsn1::from(pkcs7[982..985].to_vec()),
            })),
        };

        check_serde!(subject_public_key_info: SubjectPublicKeyInfo in pkcs7[435..985]);

        let extensions = Extensions(vec![
            Extension::new_subject_key_identifier(pkcs7[1000..1020].to_vec()),
            Extension::new_authority_key_identifier(KeyIdentifier::from(pkcs7[1033..1053].to_vec()), None, None),
            Extension::new_basic_constraints(*pkcs7.get(1060).unwrap() != 0, None),
        ]);

        check_serde!(extensions: Extensions in  pkcs7[987..1070]);

        let full_certificate = Certificate {
            tbs_certificate: TBSCertificate {
                version: ApplicationTag0(Version::V3),
                serial_number: IntegerAsn1(pkcs7[60..80].to_vec()),
                signature: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
                issuer,
                validity,
                subject,
                subject_public_key_info,
                extensions: ApplicationTag3(extensions),
            },
            signature_algorithm: AlgorithmIdentifier::new_sha256_with_rsa_encryption(),
            signature_value: BitString::with_bytes(&pkcs7[1090..1602]).into(),
        };
        check_serde!(full_certificate: Certificate in pkcs7[45..1602]);

        let signed_data = SignedData {
            version: Version::V2,
            digest_algorithms: DigestAlgorithmIdentifiers(Vec::new().into()),
            content_info,
            certificates: ExtendedCertificatesAndCertificates(vec![full_certificate]),
            crls: RevocationInfoChoices(Vec::new()),
            singers_infos: SingersInfos(Vec::new().into()),
        };

        check_serde!(signed_data: SignedData in pkcs7[19..1606]);
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

        let tbs_cert_list = TBSCertList {
            version: Some(Version::V2),
            signature: AlgorithmIdentifier::new_sha1_with_rsa_encryption().into(),
            issuer,
            this_update: UTCTime::new(2021, 4, 20, 6, 52, 24).unwrap().into(),
            next_update: Some(UTCTime::new(2023, 4, 20, 6, 52, 24).unwrap().into()),
            revoked_certificates: None,
            crl_extension: ApplicationTag0(Some(Extensions(vec![Extension::new_crl_number(
                OctetStringAsn1Container(IntegerAsn1::from(decoded[1716..1717].to_vec())),
            )]))),
        };

        check_serde!(tbs_cert_list: TBSCertList in decoded[1534..1717]);

        let crl = RevocationInfoChoices(vec![RevocationInfoChoice::Crl(CertificateList {
            tbs_cert_list,
            signature_algorithm: AlgorithmIdentifier::new_sha1_with_rsa_encryption(),
            signature_value: BitString::with_bytes(&decoded[1737..2249]).into(),
        })]);

        check_serde!(crl: RevocationInfoChoices in decoded[1526..2249]);
    }
}
