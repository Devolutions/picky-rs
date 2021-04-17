use picky_asn1::{
    tag::Tag,
    wrapper::{ApplicationTag0, Asn1SequenceOf},
};
use serde::{de, ser, Deserialize, Serialize};

use super::singer_info::CertificateSerialNumber;
use crate::{AlgorithmIdentifier, Extensions, Name, Time, Version};

// TODO: Code in this file is sub optional and need to be finished, it may serialize and deserialize properly, but some checks are missing

#[derive(Debug, PartialEq, Clone, Default)]
pub struct RevocationInfoChoices(pub Vec<RevocationInfoChoice>);

// FIXME: This is a workaround, related to https://github.com/Devolutions/picky-rs/pull/78#issuecomment-789904165

impl ser::Serialize for RevocationInfoChoices {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
    where
        S: ser::Serializer,
    {
        let mut raw_der = picky_asn1_der::to_vec(&self.0).unwrap_or_default();
        raw_der[0] = Tag::APP_1.number();
        picky_asn1_der::Asn1RawDer(raw_der).serialize(serializer)
    }
}

impl<'de> de::Deserialize<'de> for RevocationInfoChoices {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as de::Deserializer<'de>>::Error>
    where
        D: de::Deserializer<'de>,
    {
        let mut raw_der = picky_asn1_der::Asn1RawDer::deserialize(deserializer)?.0;
        raw_der[0] = Tag::SEQUENCE.number();
        let vec = picky_asn1_der::from_bytes(&raw_der).unwrap_or_default();
        Ok(RevocationInfoChoices(vec))
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum RevocationInfoChoice {
    Crl(CertificateList),
    // Other(Implicit<ApplicationTag1<OtherRevocationInfoFormat>>),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CertificateList {
    version: Option<Version>,
    signature: AlgorithmIdentifier,
    issuer: Name,
    this_update: Time,
    next_update: Time,
    revoked_certificates: RevokedCertificates,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RevokedCertificates(pub Asn1SequenceOf<RevokedCertificate>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RevokedCertificate {
    user_certificate: CertificateSerialNumber,
    revocation_data: Time,
    crl_entry_extensions: Option<Extensions>,
    crl_extensions: Option<ApplicationTag0<Extensions>>,
}

/*
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct OtherRevocationInfoFormat {
    other_rev_info_format: ObjectIdentifierAsn1,
    other_rev_info: (),
}
*/
