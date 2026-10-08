#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use diplomat_runtime::DiplomatWrite;
    use std::fmt::Write;

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AlgorithmIdentifier(pub picky::AlgorithmIdentifier);

    impl AlgorithmIdentifier {
        pub fn is_a(&self, other: &str) -> Result<bool, Box<PickyError>> {
            Ok(self
                .0
                .is_a(picky::oid::ObjectIdentifier::try_from(other).map_err(|_| "invalid OID")?))
        }

        #[diplomat::attr(auto, getter = "oid")]
        pub fn get_oid(&self, writable: &mut DiplomatWrite) -> Result<(), Box<PickyError>> {
            let string: String = self.0.oid().into();
            write!(writable, "{string}")?;
            Ok(())
        }

        #[diplomat::attr(auto, getter = "parameters")]
        pub fn get_parameters(&self) -> Box<AlgorithmIdentifierParameters> {
            Box::new(AlgorithmIdentifierParameters(self.0.parameters().clone()))
        }
    }

    // Owns a copy so it doesn't borrow from `AlgorithmIdentifier`, which keeps that type disposable.
    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AlgorithmIdentifierParameters(pub picky_asn1_x509::AlgorithmIdentifierParameters);

    pub enum AlgorithmIdentifierParametersType {
        None,
        Null,
        Aes,
        Ec,
        RsassaPss,
    }

    impl AlgorithmIdentifierParameters {
        #[diplomat::attr(auto, getter = "type")]
        pub fn get_type(&self) -> AlgorithmIdentifierParametersType {
            match &self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::None => AlgorithmIdentifierParametersType::None,
                picky_asn1_x509::AlgorithmIdentifierParameters::Null => AlgorithmIdentifierParametersType::Null,
                picky_asn1_x509::AlgorithmIdentifierParameters::Aes(_) => AlgorithmIdentifierParametersType::Aes,
                picky_asn1_x509::AlgorithmIdentifierParameters::Ec(_) => AlgorithmIdentifierParametersType::Ec,
                picky_asn1_x509::AlgorithmIdentifierParameters::RsassaPss(_) => {
                    AlgorithmIdentifierParametersType::RsassaPss
                }
            }
        }

        pub fn to_aes(&self) -> Option<Box<AesParameters>> {
            match &self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::Aes(params) => {
                    Some(Box::new(AesParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_ec(&self) -> Option<Box<EcParameters>> {
            match &self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::Ec(params) => {
                    Some(Box::new(EcParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_rsassa_pss(&self) -> Option<Box<RsassaPssParameters>> {
            match &self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::RsassaPss(params) => {
                    Some(Box::new(RsassaPssParameters(params.clone())))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AesParameters(pub picky_asn1_x509::AesParameters);

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct EcParameters(pub picky_asn1_x509::EcParameters);

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct RsassaPssParameters(pub picky_asn1_x509::RsassaPssParams);

    pub enum AesParametersType {
        Null,
        InitializationVector,
        AuthenticatedEncryptionParameters,
    }

    impl AesParameters {
        #[diplomat::attr(auto, getter = "type")]
        pub fn get_type(&self) -> AesParametersType {
            match self.0 {
                picky_asn1_x509::AesParameters::Null => AesParametersType::Null,
                picky_asn1_x509::AesParameters::InitializationVector(_) => AesParametersType::InitializationVector,
                picky_asn1_x509::AesParameters::AuthenticatedEncryptionParameters(_) => {
                    AesParametersType::AuthenticatedEncryptionParameters
                }
            }
        }

        pub fn to_initialization_vector(&self) -> Option<Box<crate::utils::ffi::VecU8>> {
            match &self.0 {
                picky_asn1_x509::AesParameters::InitializationVector(iv) => Some(Box::new(iv.into())),
                _ => None,
            }
        }

        pub fn to_authenticated_encryption_parameters(&self) -> Option<Box<AesAuthEncParams>> {
            match &self.0 {
                picky_asn1_x509::AesParameters::AuthenticatedEncryptionParameters(params) => {
                    Some(Box::new(AesAuthEncParams(params.clone())))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AesAuthEncParams(pub picky_asn1_x509::AesAuthEncParams);

    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AlgorithmIdentifierIterator(pub Vec<picky::AlgorithmIdentifier>);

    impl AlgorithmIdentifierIterator {
        pub fn next(&mut self) -> Option<Box<AlgorithmIdentifier>> {
            self.0.pop().map(|algo| Box::new(AlgorithmIdentifier(algo)))
        }
    }
}
