use crate::serde::attribute_type_and_value::{
    AttributeTypeAndValue, AttributeTypeAndValueParameters, DirectoryString,
};
use serde_asn1_der::asn1_wrapper::{Asn1SequenceOf, Asn1SetOf};
use std::fmt;

pub type RelativeDistinguishedName = Asn1SetOf<AttributeTypeAndValue>;
pub type GeneralNames = Asn1SequenceOf<RelativeDistinguishedName>;
pub type Name = GeneralNames;

pub fn new_common_name<S: Into<DirectoryString>>(name: S) -> Name {
    Asn1SequenceOf(vec![Asn1SetOf(vec![
        AttributeTypeAndValue::new_common_name(name),
    ])])
}

pub struct NamePrettyFormatter<'a>(pub &'a Name);
impl fmt::Display for NamePrettyFormatter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for name in &(self.0).0 {
            if first {
                first = false;
            } else {
                write!(f, ",")?;
            }

            match &name.0[0].value {
                AttributeTypeAndValueParameters::CommonName(name) => {
                    write!(f, "CN={}", name)?;
                }
                AttributeTypeAndValueParameters::SerialNumber(name) => {
                    write!(f, "SN={}", name)?;
                }
                AttributeTypeAndValueParameters::CountryName(name) => {
                    write!(f, "C={}", name)?;
                }
                AttributeTypeAndValueParameters::LocalityName(name) => {
                    write!(f, "L={}", name)?;
                }
                AttributeTypeAndValueParameters::StateOrProvinceName(name) => {
                    write!(f, "ST={}", name)?;
                }
                AttributeTypeAndValueParameters::OrganisationName(name) => {
                    write!(f, "O={}", name)?;
                }
                AttributeTypeAndValueParameters::OrganisationalUnitName(name) => {
                    write!(f, "OU={}", name)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_name() {
        #[rustfmt::skip]
        let encoded = [
            0x30, 0x1D, // sequence
                0x31, 0x1B, // set
                    0x30, 0x19, // sequence
                        0x06, 0x03, 0x55, 0x04, 0x03, // oid
                        0x0c, 0x12, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x63, 0x6F, 0x6E, 0x74, 0x6F,
                            0x73, 0x6F, 0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C, // utf8 string
        ];
        let expected = new_common_name("test.contoso.local");
        check_serde!(expected: Name in encoded);
    }
}
