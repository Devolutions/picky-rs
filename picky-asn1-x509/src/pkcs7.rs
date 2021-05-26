pub mod cmsversion;
pub mod content_info;
pub mod crls;
pub mod signed_data;
pub mod signer_info;

use crate::oids;
use signed_data::SignedData;

use picky_asn1::wrapper::{ApplicationTag0, ObjectIdentifierAsn1};
use serde::{de, Serialize};

#[derive(Serialize, Debug, PartialEq, Clone)]
pub struct Pkcs7Certificate {
    pub oid: ObjectIdentifierAsn1,
    pub signed_data: ApplicationTag0<SignedData>,
}

impl<'de> de::Deserialize<'de> for Pkcs7Certificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        use std::fmt;

        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Pkcs7Certificate;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid DER-encoded pcks7 certificate")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let oid: ObjectIdentifierAsn1 =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let signed_data: ApplicationTag0<SignedData> = match Into::<String>::into(&oid.0).as_str() {
                    oids::SIGNED_DATA => seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    _ => {
                        return Err(serde_invalid_value!(
                            Pkcs7Certificate,
                            "unknown oid type",
                            "SignedData oid"
                        ))
                    }
                };

                Ok(Pkcs7Certificate { oid, signed_data })
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::Pkcs7Certificate;
    use picky_asn1_der::Asn1DerError;

    #[test]
    fn full_pkcs7_decode() {
        let decoded = base64::decode(
            "MIIF1AYJKoZIhvcNAQcCoIIFxTCCBcECAQExADALBgkqhkiG9w0BBwGgggWnMIIF\
                ozCCA4ugAwIBAgIUXp0J4CZ0ZSsXBh952AQo0XUudpwwDQYJKoZIhvcNAQELBQAw\
                YTELMAkGA1UEBhMCQVIxCzAJBgNVBAgMAkFSMQswCQYDVQQHDAJBUjELMAkGA1UE\
                CgwCQVIxCzAJBgNVBAsMAkFSMQswCQYDVQQDDAJBUjERMA8GCSqGSIb3DQEJARYC\
                QVIwHhcNMjEwNDE5MTEzMzEzWhcNMjIwNDE5MTEzMzEzWjBhMQswCQYDVQQGEwJB\
                UjELMAkGA1UECAwCQVIxCzAJBgNVBAcMAkFSMQswCQYDVQQKDAJBUjELMAkGA1UE\
                CwwCQVIxCzAJBgNVBAMMAkFSMREwDwYJKoZIhvcNAQkBFgJBUjCCAiIwDQYJKoZI\
                hvcNAQEBBQADggIPADCCAgoCggIBAK96+zZ3Ik9K9yqHCz5uTMLAAEKCGo7IjBzc\
                KDY4DlhfSJ1N6MC2US/QBCpLQprLVw0JToMgBt0ErHhLzuACXnpZk6lPqaXruv5+\
                h6bRU3nVcEgkinShGTtybEDHCjbRBODg5aMbsb4vFSzVdk7PijqlUXVn1/1ke3KZ\
                GGYQ/EKweqElpOkjnrawP98gQqVS2wJO++B5DmaEYbe3ketnfv/pPNyQzehyjrsf\
                3jO/5hsRRxHwc6IgsWajRxU12bx3fBqs5CWqe4sZCfJIfpNLkDeE5cvz36P9BLr3\
                s4nKGdDAhMUOYZh6pqX9uZoq3Hm5a76HglY0SpmqOYums97dVcVMxbkMCPPawd+q\
                jz4izc4kEWhDMal3rKr8QqaoFS6ez2hUsUoJW9fPfgiLAArfXLvpWRZCuEGWjWAq\
                US/Kzfc3SvOI4095++IvLxTuvTw+iaEi0J4BLzFBnZs8lUBENJI+zYnhwEhwU8/V\
                vSpjWmvly0RtbCiImFtYpd0y2/TlaJ4jupdR9//8gb21W/nKNzRrlYzVhYfdM+BP\
                itNzeHKQHNzfy18LHBRpvqlp/nV3KhxTuEe/CvIsFS5xRtTmUICBwBC4ycq8cV/6\
                Ek4FQTCYo08VQ9F68qX9iVAk+ajaRr3cE6+oX+aXIRx6GZ2KkC/NWcLnjOPy2flR\
                y1lBxUmfAgMBAAGjUzBRMB0GA1UdDgQWBBRxxrWG5tXUbtOytggfIuTu/sP/4TAf\
                BgNVHSMEGDAWgBRxxrWG5tXUbtOytggfIuTu/sP/4TAPBgNVHRMBAf8EBTADAQH/\
                MA0GCSqGSIb3DQEBCwUAA4ICAQBZ5AyGS/U5Fqo5MpMvTlIuEXKDL4tTFyFXvBg6\
                iowN9NylLeH2xyD5Deb2EOjoAJTnrhtCNmyOh3JmPpyFMN2S0LdzGeQS5idHlCsT\
                PZpj0qJp+iexDS0syrYX/9/+L+5cR1LBVXEoK3kF0ZpSHUOxZkIx11zHjKohs+FF\
                Hanhmx7cyVdDhBwtBcQfR41al6idt155xyhuYVTyXi0XSKr3YgBWXzjKnfrxsEe0\
                7Zo18ZtMe0p42yYwEhQaPL0UQkuSC7hAilOO3YWQ51Vnk3QJ7kw+EEqed6LNuAsS\
                Qt8h4F7fiVuO4UG5CToDwK9bEw4zfQ8Xrm+6rwy/3CWC8L/YZ8Paj89+2JB3woIv\
                F+6QvKTPpQ0arM4dI82nsyHSdt2bxXkLJ7iZ/D1vJZkWzBrpvuTmeHAKiFIj2hfJ\
                5FruZrC/60BKrbx4FAniXinNSzk43l4Q42JD6zGkex7mxXURkxqbbz6TAqSmbwgp\
                ygxNWPIKIvldXq1yeNt9lPfHANqd+dCrpnkNCXVwaFbDqTaltYdaB4zg9HlzvlBK\
                Eh49eilHGchkyMBawo80ctWy9UNH/Yt3uiwuga0Q2sCLlrbPxE5Ro3Ou/SZF9YtZ\
                Ee/Xdsl0pUmdAylBzp08AJWCuPheE7XjrnfDlPz4BRuiB+qOMDO/ngLNZ0rFbiIV\
                3ojRzKEAMQA=",
        )
        .unwrap();

        let pkcs7: Result<Pkcs7Certificate, Asn1DerError> = picky_asn1_der::from_bytes(decoded.as_slice());
        assert!(pkcs7.is_ok());
    }

    #[test]
    fn full_pkcs7_decode_with_ca_root() {
        let decoded = base64::decode(
            "MIIIwgYJKoZIhvcNAQcCoIIIszCCCK8CAQExADALBgkqhkiG9w0BBwGgggiVMIIE\
                nDCCAoQCFGe148Dqygm4BCpH70eVHP64Kf3zMA0GCSqGSIb3DQEBCwUAMIGHMQsw\
                CQYDVQQGEwJUWTELMAkGA1UECAwCVFkxETAPBgNVBAcMCFNvbWVDaXR5MRQwEgYD\
                VQQKDAtTb21lQ29tcGFueTERMA8GA1UECwwIU29tZVVuaXQxDzANBgNVBAMMBk15\
                TmFtZTEeMBwGCSqGSIb3DQEJARYPbXltYWlsQG1haWwuY29tMB4XDTIxMDQxOTEy\
                NDgwMloXDTI0MDExNDEyNDgwMlowgYwxCzAJBgNVBAYTAlRZMQswCQYDVQQIDAJU\
                WTERMA8GA1UEBwwIU29tZUNpdHkxGTAXBgNVBAoMEFNvbWVPcmdhbml6YXRpb24x\
                ETAPBgNVBAsMCFNvbWVVbml0MQ8wDQYDVQQDDAZNeU5hbWUxHjAcBgkqhkiG9w0B\
                CQEWD215bWFpbEBtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\
                ggEBAJ3PyrdEwqN4SBK/1RIkH9s0MSJ+qWLvgPWozvWgOmK1peYWEpcaR/Kph8rq\
                rPrePLXX6ZM7Oyy/rtf1A521hNdPAvNbJ/Dhxou/ivavqoLoc6cMhM/0LFKrN0en\
                BCwfC1XKOF3F+LgkitKtbF9iWGbt4Pp5GtrEjjCdwHzF/5tmsq+yzcnQGTiX24BA\
                pvhlHuXpcLvBEDwNXJ2Tj812hJO1gZ8iOyIKY8BMBygRLp2pE3z/9w1E0gF03Y3C\
                N4ts4VDi/pFstxHRfSX7V7TdLxcm8CsZhmbxYzKOG95TORwY9q2nGQcRKAzyHd5w\
                a25ri/LbuHaz2LnUQrLYMXOHag0CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAGaKl\
                8Bq5M6BIU8gYXIx1kRE/WOMonUAwn6agoqeRVROiHz0XSkSArUM76WZ98Ndvbbvj\
                4p+yCMeiX12zro0qj1hxxBF6cYxRxutukJjU/OjTCR7jR57QHVVHzjBDW2PQoHIE\
                fX399yr2IILzAeI8xvLx8v2y+o7vfCWW5Sd8x7puww1FGNA/QqKBu/kw4NobybwS\
                j+SC38qfBQQsKghbuJbxpwLuY3yixqwPV8Swlzc1PrAwtA+RWabQDHjShnTBppqu\
                XNTFhGbPDdTHzECnRxg9cQbqSpiOkdnxEpagy8c7ccCwvHjD2SQGr44ydHg5FYPB\
                k2wXKc8EFtmR4kyWg1zYjuboY0/0iaUkyWOZYy6NZE/ktwZKR02gXoN1I3YSsbw/\
                fytr4ldkqq6bkpgMK/60CKiQvI8tdxcnQejeSlJfYqzptIlnsPH8X1x/kfQ8dWFj\
                YIyxvRDe+26/1wOXodgTNwrn02FzNEcxqyOLL9YzYvbq1UiNi2n6CBaAJKdU7NhE\
                dnzb81P4uOfs0QbsWGkVE3T9NzRlJlEPjei+srUZDvFYDjTTo2rTITOPDLPzSJlE\
                UfxVV3uaRHc8Z07oTiaW2H/eizOwwBLbgVRKMy74dk4wC/3P1CSwyd4Z+c/l2LZ5\
                8Z2LMjIFw/eVYCfAiOmS/xyGqYZoXNXVZlp2/UswggPxMIIC2aADAgECAhQY0ZCe\
                SXAknAwNvZQgZvONNLI/xjANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMCVFkx\
                CzAJBgNVBAgMAlJGMREwDwYDVQQHDAhTb21lQ2l0eTEUMBIGA1UECgwLU29tZUNv\
                bXBhbnkxETAPBgNVBAsMCFNvbWVVbml0MQ8wDQYDVQQDDAZNeU5hbWUxHjAcBgkq\
                hkiG9w0BCQEWD215bWFpbEBtYWlsLmNvbTAeFw0yMTA0MTkxMjI4MzNaFw0yNDA0\
                MDkxMjI4MzNaMIGHMQswCQYDVQQGEwJUWTELMAkGA1UECAwCUkYxETAPBgNVBAcM\
                CFNvbWVDaXR5MRQwEgYDVQQKDAtTb21lQ29tcGFueTERMA8GA1UECwwIU29tZVVu\
                aXQxDzANBgNVBAMMBk15TmFtZTEeMBwGCSqGSIb3DQEJARYPbXltYWlsQG1haWwu\
                Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1a+nyoNA6hkFplgN\
                ajApR5lITmhxGJGYvrm3w4fYTqQ+eGr9PxQsEfhQQqy8+nOyCSRL9FJ2YwGdwrPZ\
                KjJc1RIVWpCk+vxbm04C8PMlDiygpeD9l7tfZDTdJD4npRvHlltUSbK69/j0djC+\
                aJr+DMT3h2fU/9mDDfVaKB30Q0mwOdmtLGcOAXddN9AJBVP9b6GekAE7jKC037jK\
                UUrA3h5bw0rvic+jvtKnf1rsh5VYfHelJnxRnZ/XBijy99fZRf260i8gzp0+/OSg\
                39ggjOPlrGcPpLPcHShMlTK553GmO64T7IgBtmH8LdG/XInkcRw0oZ6BK5lUCSPp\
                UQ4TfQIDAQABo1MwUTAdBgNVHQ4EFgQUznGR6rk3Nzi+3z80yteN8IPI3TYwHwYD\
                VR0jBBgwFoAUznGR6rk3Nzi+3z80yteN8IPI3TYwDwYDVR0TAQH/BAUwAwEB/zAN\
                BgkqhkiG9w0BAQsFAAOCAQEAjcK4L3VqsdUHmAyL9VBxBK4msWOzKMStUJ0d9+j6\
                LLMMo39/0RLqvwiREP1JELCzWdKCrMKRtKbQh/e7dQoFR4zWezJ5ChtKRqAlUdVt\
                m7yr61Ua0ftpkJtcb5+b8vP+cruAvnrjpW8VQNOkbce+VjOjl287FdfliZgpTCee\
                5UPxb2USETPoTohJOPpE27w6/1Ztb8AUgDzjZwd50Ty1ci6SBeFsD7YBgnSZO9ze\
                S8zhKeY18ivsny0RKPO28/fO7rhExogn4sg12H6kaM3NokmDUf8FVy/Np0LCFreU\
                cjZ0Bdoi73yZiQcNp8lb1Hm5jJbq2Oa1aY88KZ1Hdyx+jqEAMQA=",
        )
        .unwrap();

        let pkcs7: Result<Pkcs7Certificate, Asn1DerError> = picky_asn1_der::from_bytes(decoded.as_slice());
        assert!(pkcs7.is_ok());
    }
}
