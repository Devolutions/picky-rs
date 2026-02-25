#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::utils::ffi::VecU8;
    use crate::x509::attribute::ffi::{
        AttributeTypeAndValue, AttributeTypeAndValueIterator, AttributeTypeAndValueNestedIterator,
    };
    use crate::x509::string::ffi::DirectoryString;
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;
    use std::str::FromStr;

    #[diplomat::opaque]
    pub struct GeneralNameIterator(pub Vec<GeneralName>);

    impl GeneralNameIterator {
        pub fn next(&mut self) -> Option<Box<GeneralName>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct GeneralName(pub picky_asn1_x509::name::GeneralName);

    pub enum GeneralNameType {
        OtherName,
        Rfc822Name,
        DnsName,
        DirectoryName,
        EdiPartyName,
        Uri,
        IpAddress,
        RegisteredId,
    }

    impl GeneralName {
        pub fn get_type(&self) -> GeneralNameType {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::OtherName(_) => GeneralNameType::OtherName,
                picky_asn1_x509::name::GeneralName::Rfc822Name(_) => GeneralNameType::Rfc822Name,
                picky_asn1_x509::name::GeneralName::DnsName(_) => GeneralNameType::DnsName,
                picky_asn1_x509::name::GeneralName::DirectoryName(_) => GeneralNameType::DirectoryName,
                picky_asn1_x509::name::GeneralName::EdiPartyName(_) => GeneralNameType::EdiPartyName,
                picky_asn1_x509::name::GeneralName::Uri(_) => GeneralNameType::Uri,
                picky_asn1_x509::name::GeneralName::IpAddress(_) => GeneralNameType::IpAddress,
                picky_asn1_x509::name::GeneralName::RegisteredId(_) => GeneralNameType::RegisteredId,
            }
        }

        pub fn to_other_name(&self) -> Option<Box<OtherName>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::OtherName(other_name) => {
                    Some(Box::new(OtherName(other_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_rfc822_name(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::Rfc822Name(rfc822_name) => {
                    write!(writable, "{}", rfc822_name.0)?;
                    Ok(())
                }
                _ => Err("not an RFC822 name".into()),
            }
        }

        pub fn to_dns_name(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::DnsName(dns_name) => {
                    write!(writable, "{}", dns_name.0)?;
                    Ok(())
                }
                _ => Err("not a DNS name".into()),
            }
        }

        pub fn to_directory_name(&self) -> Option<Box<AttributeTypeAndValueNestedIterator>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::DirectoryName(directory_name) => {
                    let mut vec = vec![];
                    let clone = directory_name.0.clone();
                    for names in clone.0 {
                        vec.push(AttributeTypeAndValueIterator(
                            names.0.clone().into_iter().map(AttributeTypeAndValue).collect(),
                        ));
                    }
                    Some(Box::new(AttributeTypeAndValueNestedIterator(vec)))
                }
                _ => None,
            }
        }

        pub fn to_edi_party_name(&self) -> Option<Box<EdiPartyName>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::EdiPartyName(edi_party_name) => {
                    Some(Box::new(EdiPartyName(edi_party_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_uri(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::Uri(uri) => {
                    write!(writable, "{}", uri.0)?;
                    Ok(())
                }
                _ => Err("not a URI".into()),
            }
        }

        pub fn to_ip_address(&self) -> Option<Box<VecU8>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::IpAddress(ip_address) => {
                    Some(VecU8::from_bytes(&ip_address.0).boxed())
                }
                _ => None,
            }
        }

        pub fn to_registered_id(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::RegisteredId(registered_id) => {
                    let oid: String = registered_id.0.clone().into();
                    write!(writable, "{oid}")?;
                    Ok(())
                }
                _ => Err("not a registered ID".into()),
            }
        }
    }

    #[diplomat::opaque]
    pub struct EdiPartyName(pub picky_asn1_x509::name::EdiPartyName);

    impl EdiPartyName {
        pub fn get_name_assigner(&self) -> Option<Box<DirectoryString>> {
            self.0
                .name_assigner
                .as_ref()
                .map(|name_assigner| Box::new(DirectoryString(name_assigner.0.clone())))
        }

        pub fn get_party_name(&self) -> Box<DirectoryString> {
            Box::new(DirectoryString(self.0.party_name.0.clone()))
        }
    }

    #[diplomat::opaque]
    pub struct OtherName(pub picky_asn1_x509::name::OtherName);

    impl OtherName {
        pub fn get_type_id(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.type_id.0.clone().into();
            write!(writable, "{oid}")?;
            Ok(())
        }

        pub fn get_value(&self) -> Box<crate::utils::ffi::VecU8> {
            VecU8::from_bytes(&self.0.value.0.0).boxed()
        }
    }

    #[diplomat::enum_convert(picky_asn1_x509::name::NameAttr)]
    pub enum NameAttr {
        CommonName,
        Surname,
        SerialNumber,
        CountryName,
        LocalityName,
        StateOrProvinceName,
        StreetName,
        OrganizationName,
        OrganizationalUnitName,
        GivenName,
        Phone,
    }

    #[diplomat::opaque]
    pub struct DirectoryName(pub picky::x509::name::DirectoryName);

    #[diplomat::opaque]
    pub struct DirectoryNameIterator(pub Vec<DirectoryName>);

    impl DirectoryName {
        pub fn new() -> Box<DirectoryName> {
            Box::new(DirectoryName(picky::x509::name::DirectoryName::new()))
        }

        pub fn new_common_name(name: &str) -> Box<DirectoryName> {
            Box::new(DirectoryName(picky::x509::name::DirectoryName::new_common_name(name)))
        }

        pub fn find_common_name(&self) -> Option<Box<DirectoryString>> {
            self.0
                .find_common_name()
                .map(|name| Box::new(DirectoryString(name.clone())))
        }

        pub fn add_attr(&mut self, attr: NameAttr, value: &str) {
            self.0.add_attr(attr.into(), value);
        }

        pub fn add_email(&mut self, email: &str) -> Result<(), Box<PickyError>> {
            let ia5_string = picky_asn1::restricted_string::IA5String::from_str(email)?;
            self.0.add_email(ia5_string);
            Ok(())
        }
    }
}
