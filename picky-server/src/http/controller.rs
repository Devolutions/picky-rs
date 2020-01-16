use crate::{
    configuration::ServerConfig,
    db::{get_storage, BoxedPickyStorage, CertificateEntry, PickyStorage},
    http::{
        authorization::{check_authorization, Authorized, CsrClaims},
        utils::SyncRequestUtil,
    },
    multihash::*,
    picky_controller::Picky,
};
use picky::{
    pem::{parse_pem, to_pem, Pem},
    x509::{Cert, Csr},
};
use saphir::{Controller, ControllerDispatch, Method, StatusCode, SyncRequest, SyncResponse};
use serde_json::{self, Value};
use std::fmt;

struct ControllerData {
    pub storage: BoxedPickyStorage,
    pub config: ServerConfig,
}

pub struct ServerController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl ServerController {
    pub fn from_config(config: ServerConfig) -> Result<Self, String> {
        let storage = get_storage(&config);

        if !config.root_cert.is_empty() && !config.root_key.is_empty() {
            info!("Inject Root CA provided by settings");
            if let Err(e) = inject_config_provided_cert(
                &format!("{} Root CA", config.realm),
                &config.root_cert,
                &config.root_key,
                storage.as_ref(),
            ) {
                return Err(format!("couldn't inject Root CA: {}", e));
            }
        } else {
            info!("Root CA...");
            let created =
                generate_root_ca(&config, storage.as_ref()).map_err(|e| format!("couldn't generate root CA: {}", e))?;
            if created {
                info!("Created");
            } else {
                info!("Already exists");
            }
        }

        if !config.intermediate_cert.is_empty() && !config.intermediate_key.is_empty() {
            info!("Inject Intermediate CA provided by settings");
            if let Err(e) = inject_config_provided_cert(
                &format!("{} Authority", config.realm),
                &config.intermediate_cert,
                &config.intermediate_key,
                storage.as_ref(),
            ) {
                return Err(format!("couldn't inject Intermediate CA: {}", e));
            }
        } else {
            info!("Intermediate CA...");
            let created = generate_intermediate_ca(&config, storage.as_ref())
                .map_err(|e| format!("couldn't generate intermediate CA: {}", e))?;
            if created {
                info!("Created");
            } else {
                info!("Already exists");
            }
        }

        let controller_data = ControllerData { storage, config };

        let dispatch = ControllerDispatch::new(controller_data);

        dispatch.add(Method::GET, "/chain", get_default_chain);
        dispatch.add(Method::POST, "/sign", cert_signature_request);
        dispatch.add(Method::GET, "/health", health);
        dispatch.add(Method::GET, "/cert/<multihash>", get_cert);
        dispatch.add(Method::POST, "/cert", post_cert);

        Ok(ServerController { dispatch })
    }
}

impl Controller for ServerController {
    fn handle(&self, req: &mut SyncRequest, res: &mut SyncResponse) {
        self.dispatch.dispatch(req, res);
    }

    fn base_path(&self) -> &str {
        "/"
    }
}

// === helper macros === //

macro_rules! saphir_try {
    ( $result:expr ) => {
        saphir_try!($result, "Error")
    };
    ( $result:expr , $context:literal $(,)? ) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                error!(concat!($context, ": {}"), e);
                return;
            }
        }
    };
}

macro_rules! unwrap_opt {
    ( $opt:expr , $error:literal $(,)? ) => {
        match $opt {
            Some(value) => value,
            None => {
                error!($error);
                return;
            }
        }
    };
}

// === header format === //

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Format {
    PemFile,
    Json,
    PkixCertBinary,
    PkixCertBase64,
    Pkcs10Binary,
    Pkcs10Base64,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Format::PemFile => write!(f, "pem file"),
            Format::Json => write!(f, "json"),
            Format::PkixCertBinary => write!(f, "binary-encoded pkix-cert"),
            Format::PkixCertBase64 => write!(f, "base64-encoded pkix-cert"),
            Format::Pkcs10Binary => write!(f, "binary-encoded pkcs10"),
            Format::Pkcs10Base64 => write!(f, "base64-encoded pkcs10"),
        }
    }
}

impl Format {
    fn request_format(req: &SyncRequest) -> Result<Self, String> {
        let content_type_opt = req.get_header_string_value("Content-Type");
        let content_transfert_encoding_opt = req.get_header_string_value("Content-Transfer-Encoding");

        if let Some(content_type) = content_type_opt {
            Self::new(
                content_type.as_str(),
                content_transfert_encoding_opt.as_ref().map(|s| s.as_str()),
            )
        } else {
            Err("Content-Type header is missing".to_string())
        }
    }

    fn response_format(req: &SyncRequest) -> Result<Self, String> {
        let accept_opt = req.get_header_string_value("Accept").map(|s| {
            // cannot panic
            s.split(',').next().unwrap().split(';').next().unwrap().to_owned()
        });
        let accept_encoding_opt = req.get_header_string_value("Accept-Encoding").map(|s| {
            // cannot panic
            s.split(',').next().unwrap().split(';').next().unwrap().to_owned()
        });

        if let Some(accept) = accept_opt {
            Self::new(accept.as_str(), accept_encoding_opt.as_ref().map(|s| s.as_str()))
        } else {
            Err("Accept header is missing".to_string())
        }
    }

    fn new(format: &str, encoding: Option<&str>) -> Result<Self, String> {
        match (format, encoding) {
            ("application/x-pem-file", _) => Ok(Self::PemFile),
            ("application/json", _) => Ok(Self::Json),
            ("application/pkix-cert", Some("binary")) => Ok(Self::PkixCertBinary),
            ("application/pkix-cert", Some("base64")) => Ok(Self::PkixCertBase64),
            ("application/pkix-cert", Some(unsupported)) => {
                Err(format!("unsupported encoding format for pkix-cert: {}", unsupported))
            }
            ("application/pkix-cert", None) => Err("format encoding for pkix-cert is missing".to_owned()),
            ("application/pkcs10", Some("binary")) => Ok(Self::Pkcs10Binary),
            ("application/pkcs10", Some("base64")) => Ok(Self::Pkcs10Base64),
            ("application/pkcs10", Some(unsupported)) => {
                Err(format!("unsupported encoding format for pkcs10: {}", unsupported))
            }
            ("application/pkcs10", None) => Err("format encoding for pkcs10 is missing".to_owned()),
            (unsupported, _) => Err(format!("unsupported format: {}", unsupported)),
        }
    }
}

// === health === //

fn health(controller_data: &ControllerData, _req: &SyncRequest, res: &mut SyncResponse) {
    if controller_data.storage.health().is_ok() {
        res.status(StatusCode::OK).body("Everything should be alright!");
    } else {
        res.status(StatusCode::SERVICE_UNAVAILABLE);
    }
}

// === post_cert === //

fn post_cert(controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse) {
    res.status(StatusCode::BAD_REQUEST);

    let request_format = saphir_try!(Format::request_format(req));
    let cert = match request_format {
        Format::PemFile => {
            let pem = saphir_try!(parse_pem(req.body()), "couldn't parse pem");
            saphir_try!(Cert::from_der(pem.data()), "(pem) couldn't deserialize certificate")
        }
        Format::Json => {
            let json = saphir_try!(
                serde_json::from_slice::<Value>(req.body()),
                "(json) couldn't parse json"
            );
            let pem = saphir_try!(
                json["certificate"]
                    .to_string()
                    .trim_matches('"')
                    .replace("\\n", "\n")
                    .parse::<Pem>(),
                "(json) couldn't parse pem",
            );
            saphir_try!(Cert::from_der(pem.data()), "(json) couldn't deserialize certificate")
        }
        Format::PkixCertBinary => saphir_try!(Cert::from_der(req.body()), "(binary) couldn't deserialize certificate"),
        Format::PkixCertBase64 => {
            let der = saphir_try!(base64::decode(&req.body()), "couldn't decode base64 body");
            saphir_try!(Cert::from_der(&der), "(base64) couldn't deserialize certificate")
        }
        unexpected => {
            error!("unexpected request format: {}", unexpected);
            return;
        }
    };

    let ski = hex::encode(saphir_try!(cert.subject_key_identifier(), "couldn't fetch SKI"));

    let issuer_name = unwrap_opt!(
        cert.issuer_name().find_common_name(),
        "couldn't find issuer common name"
    )
    .to_string();

    if issuer_name != format!("{} Authority", &controller_data.config.realm) {
        error!("this certificate was not signed by the CA of this server.");
        return;
    }

    let der = saphir_try!(cert.to_der(), "couldn't serialize certificate into der");
    let subject_name = unwrap_opt!(
        cert.subject_name().find_common_name(),
        "couldn't find subject issuer common name"
    )
    .to_string();

    if let Err(e) = controller_data.storage.store(CertificateEntry {
        name: subject_name.clone(),
        cert: der,
        key_identifier: ski,
        key: None,
    }) {
        error!("Insertion error for leaf {}: {}", subject_name, e);
    } else {
        res.status(StatusCode::OK);
    }
}

// === cert_signature_request ===

fn cert_signature_request(controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse) {
    res.status(StatusCode::BAD_REQUEST);

    let locked_subject_name: Option<String> = match check_authorization(&controller_data.config, req) {
        Ok(Authorized::ApiKey) => None,
        Ok(Authorized::Token(token)) => {
            let csr_claims: CsrClaims = saphir_try!(serde_json::from_value(token.into_claims()));
            Some(csr_claims.sub)
        }
        Err(e) => {
            error!("Authorization failed: {}", e);
            res.status(StatusCode::UNAUTHORIZED);
            return;
        }
    };

    let request_format = saphir_try!(Format::request_format(req));
    let mut ca_name = format!("{} Authority", &controller_data.config.realm);
    let csr = match request_format {
        Format::PemFile => {
            let pem = saphir_try!(parse_pem(req.body()), "couldn't parse pem");
            saphir_try!(Csr::from_der(pem.data()), "(pem) couldn't deserialize csr")
        }
        Format::Json => {
            let json = saphir_try!(
                serde_json::from_slice::<Value>(req.body()),
                "(json) couldn't parse json"
            );

            if let Some(ca) = json["ca"].as_str() {
                ca_name = ca.trim_matches('"').to_owned();
            }

            let pem = saphir_try!(
                json["csr"]
                    .to_string()
                    .trim_matches('"')
                    .replace("\\n", "\n")
                    .parse::<Pem>(),
                "(json) couldn't parse pem",
            );
            saphir_try!(Csr::from_der(pem.data()), "(json) couldn't deserialize csr")
        }
        Format::Pkcs10Binary => saphir_try!(Csr::from_der(req.body()), "(binary) couldn't deserialize csr"),
        Format::Pkcs10Base64 => {
            let der = saphir_try!(base64::decode(&req.body()), "couldn't decode base64 body");
            saphir_try!(Csr::from_der(&der), "(base64) couldn't deserialize csr")
        }
        unexpected => {
            error!("unexpected request format: {}", unexpected);
            return;
        }
    };

    if let Some(locked_subject_name) = locked_subject_name {
        let subject_name = unwrap_opt!(
            csr.subject_name().find_common_name(),
            "couldn't find signed CSR subject common name"
        )
        .to_string();

        if locked_subject_name != subject_name {
            error!(
                "Requested a certificate with an unauthorized subject name: {}, expected: {}",
                subject_name, locked_subject_name
            );
            res.status(StatusCode::UNAUTHORIZED);
            return;
        }
    }

    // Sign CSR
    let signed_cert = saphir_try!(sign_certificate(
        &ca_name,
        csr,
        &controller_data.config,
        controller_data.storage.as_ref()
    ));

    let response_format = Format::response_format(req).unwrap_or(Format::PemFile);
    match response_format {
        Format::PemFile => {
            let pem = saphir_try!(signed_cert.to_pem(), "couldn't get certificate pem");
            res.body(pem.to_string());
        }
        Format::PkixCertBinary => {
            let der = saphir_try!(signed_cert.to_der(), "couldn't get certificate der");
            res.body(der);
        }
        Format::PkixCertBase64 => {
            let der = saphir_try!(signed_cert.to_der(), "couldn't get certificate der");
            res.body(base64::encode(&der));
        }
        unexpected => {
            error!("unexpected response format: {}", unexpected);
            return;
        }
    }

    res.status(StatusCode::OK);
}

fn sign_certificate(
    ca_name: &str,
    csr: Csr,
    config: &ServerConfig,
    storage: &dyn PickyStorage,
) -> Result<Cert, String> {
    let ca_hash = storage
        .get_hash_by_name(ca_name)
        .map_err(|e| format!("couldn't fetch CA: {}", e))?;

    let ca_cert_der = storage
        .get_cert_by_hash(&ca_hash)
        .map_err(|e| format!("couldn't get CA cert der: {}", e))?;
    let ca_cert = Cert::from_der(&ca_cert_der).map_err(|e| format!("couldn't deserialize CA cert: {}", e))?;

    let ca_pk_der = storage
        .get_key_by_hash(&ca_hash)
        .map_err(|e| format!("couldn't fetch CA private key: {}", e))?;
    let ca_pk = Picky::parse_pk_from_magic_der(&ca_pk_der).map_err(|e| e.to_string())?;

    let dns_name = csr
        .subject_name()
        .find_common_name()
        .ok_or_else(|| "couldn't find signed cert subject common name")?
        .to_string();

    let signed_cert = Picky::generate_leaf_from_csr(csr, &ca_cert, &ca_pk, config.key_config, &dns_name)
        .map_err(|e| format!("couldn't generate leaf certificate: {}", e))?;

    if config.save_certificate {
        let cert_der = signed_cert
            .to_der()
            .map_err(|e| format!("couldn't serialize certificate to der: {}", e))?;
        let ski = hex::encode(
            signed_cert
                .subject_key_identifier()
                .map_err(|e| format!("couldn't get SKI: {}", e))?,
        );

        storage
            .store(CertificateEntry {
                name: dns_name.clone(),
                cert: cert_der,
                key_identifier: ski,
                key: None,
            })
            .map_err(|e| format!("insertion error for leaf {}: {}", dns_name, e))?;
    }

    Ok(signed_cert)
}

// === get_cert === //

fn get_cert(controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse) {
    res.status(StatusCode::BAD_REQUEST);

    let hash = unwrap_opt!(req.captures().get("multihash"), "multihash is missing");

    let cert_der = match controller_data.storage.get_cert_by_hash(hash) {
        Ok(cert_der) => cert_der,
        Err(e) => {
            info!(
                "couldn't fetch certificate using hash {}: {}. Trying again assuming sha256.",
                hash, e
            );
            let multihash = saphir_try!(sha256_to_multihash(hash));
            saphir_try!(controller_data.storage.get_cert_by_hash(&multihash))
        }
    };

    let response_format = Format::response_format(req).unwrap_or(Format::PemFile);
    match response_format {
        Format::PemFile => {
            res.body(to_pem("CERTIFICATE", &cert_der));
        }
        Format::PkixCertBinary => {
            res.body(cert_der);
        }
        Format::PkixCertBase64 => {
            res.body(base64::encode(&cert_der));
        }
        unexpected => {
            error!("unexpected response format: {}", unexpected);
            return;
        }
    }

    res.status(StatusCode::OK);
}

// === chain ===

fn get_default_chain(controller_data: &ControllerData, _: &SyncRequest, res: &mut SyncResponse) {
    res.status(StatusCode::BAD_REQUEST);
    let ca = format!("{} Authority", &controller_data.config.realm);
    let chain = saphir_try!(find_ca_chain(controller_data.storage.as_ref(), &ca));
    res.body(chain.join("\n"));
    res.status(StatusCode::OK);
}

fn find_ca_chain(storage: &dyn PickyStorage, ca_name: &str) -> Result<Vec<String>, String> {
    let ca_hash = storage
        .get_hash_by_name(ca_name)
        .map_err(|e| format!("couldn't fetch CA hash id for {}: {}", ca_name, e))?;

    let mut cert_der = storage
        .get_cert_by_hash(&ca_hash)
        .map_err(|e| format!("couldn't fetch CA certificate der: {}", e))?;
    let mut chain = vec![to_pem("CERTIFICATE", &cert_der)];
    let mut current_key_id = String::default();
    loop {
        let cert = Cert::from_der(&cert_der).map_err(|e| format!("couldn't deserialize certificate: {}", e))?;

        let parent_key_id = hex::encode(
            cert.authority_key_identifier()
                .map_err(|e| format!("couldn't fetch authority key identifier: {}", e))?
                .key_identifier()
                .ok_or_else(|| "parent key identifier not found".to_owned())?,
        );

        if current_key_id == parent_key_id {
            // The authority is itself. It is a root.
            break;
        }

        let hash = storage
            .get_hash_by_key_identifier(&parent_key_id)
            .map_err(|e| format!("couldn't fetch hash: {}", e))?;

        cert_der = storage
            .get_cert_by_hash(&hash)
            .map_err(|e| format!("couldn't fetch certificate der: {}", e))?;

        chain.push(to_pem("CERTIFICATE", &cert_der));

        current_key_id = parent_key_id;
    }

    Ok(chain)
}

// === generate root CA === //

fn generate_root_ca(config: &ServerConfig, storage: &dyn PickyStorage) -> Result<bool, String> {
    let name = format!("{} Root CA", config.realm);

    if let Ok(certs) = storage.get_hash_by_name(&name) {
        if !certs.is_empty() {
            // already exists
            return Ok(false);
        }
    }

    let pk = Picky::generate_private_key(4096).map_err(|e| format!("couldn't generate private key: {}", e))?;
    let root = Picky::generate_root(&name, &pk, config.key_config)
        .map_err(|e| format!("couldn't generate root certificate: {}", e))?;
    let ski = root
        .subject_key_identifier()
        .map_err(|e| format!("couldn't fetch subject key identifier: {}", e))?;

    let cert_der = root
        .to_der()
        .map_err(|e| format!("couldn't serialize root certificate into der: {}", e))?;

    let pk_pkcs8 = pk
        .to_pkcs8()
        .map_err(|e| format!("couldn't get private key pkcs8: {}", e))?;

    storage
        .store(CertificateEntry {
            name,
            cert: cert_der,
            key_identifier: hex::encode(ski),
            key: Some(pk_pkcs8),
        })
        .map_err(|e| format!("couldn't store generated root certificate: {}", e))?;

    Ok(true)
}

// === generate intermediate CA === //

fn generate_intermediate_ca(config: &ServerConfig, storage: &dyn PickyStorage) -> Result<bool, String> {
    let root_name = format!("{} Root CA", config.realm);
    let intermediate_name = format!("{} Authority", config.realm);

    if let Ok(certs) = storage.get_hash_by_name(&intermediate_name) {
        if !certs.is_empty() {
            // already exists
            return Ok(false);
        }
    }

    let (root_cert_der, root_key_der) = match storage.get_hash_by_name(&root_name) {
        Ok(root_hash) => (
            storage
                .get_cert_by_hash(&root_hash)
                .map_err(|e| format!("couldn't fetch root CA: {}", e))?,
            storage
                .get_key_by_hash(&root_hash)
                .map_err(|e| format!("couldn't fetch root CA private key: {}", e))?,
        ),
        Err(e) => {
            return Err(format!("error while fetching root: {}", e));
        }
    };

    let pk = Picky::generate_private_key(2048).map_err(|e| e.to_string())?;
    let root_cert = Cert::from_der(&root_cert_der).map_err(|e| format!("couldn't parse root cert from der: {}", e))?;
    let root_key = Picky::parse_pk_from_magic_der(&root_key_der).map_err(|e| e.to_string())?;

    let intermediate_cert = Picky::generate_intermediate(
        &intermediate_name,
        pk.to_public_key(),
        &root_cert,
        &root_key,
        config.key_config,
    )
    .map_err(|e| format!("couldn't generate intermediate certificate: {}", e))?;

    let ski = intermediate_cert
        .subject_key_identifier()
        .map_err(|e| format!("couldn't fetch key id: {}", e))?;

    let cert_der = intermediate_cert
        .to_der()
        .map_err(|e| format!("couldn't serialize intermediate certificate into der: {}", e))?;

    let pk_pkcs8 = pk
        .to_pkcs8()
        .map_err(|e| format!("couldn't get private key pkcs8: {}", e))?;

    storage
        .store(CertificateEntry {
            name: intermediate_name,
            cert: cert_der,
            key_identifier: hex::encode(ski),
            key: Some(pk_pkcs8),
        })
        .map_err(|e| format!("couldn't store generated intermediate certificate: {}", e))?;

    Ok(true)
}

// === inject config provided certificates in picky storage === //

fn inject_config_provided_cert(
    expected_subject_name: &str,
    cert_pem: &str,
    key_pem: &str,
    storage: &dyn PickyStorage,
) -> Result<(), String> {
    let cert_pem = cert_pem
        .parse::<Pem>()
        .map_err(|e| format!("couldn't parse cert pem: {}", e))?;
    let cert = Cert::from_der(cert_pem.data()).map_err(|e| format!("couldn't parse cert from der: {}", e))?;
    let ski = hex::encode(
        cert.subject_key_identifier()
            .map_err(|e| format!("couldn't parse fetch subject key identifier: {}", e))?,
    );
    let subject_name = cert
        .subject_name()
        .find_common_name()
        .ok_or_else(|| "couldn't find subject common name".to_owned())?
        .to_string();

    if subject_name != expected_subject_name {
        return Err(format!(
            "unexpected subject name: {} ; expected: {}",
            subject_name, expected_subject_name
        ));
    }

    let key_pem = key_pem
        .parse::<Pem>()
        .map_err(|e| format!("couldn't parse key pem: {}", e))?;

    storage
        .store(CertificateEntry {
            name: subject_name,
            cert: cert_pem.into_data().into_owned(),
            key_identifier: ski,
            key: Some(key_pem.into_data().into_owned()),
        })
        .map_err(|e| format!("couldn't store certificate: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::BackendType;
    use picky::{
        signature::SignatureHashType,
        x509::{date::UTCDate, name::DirectoryName},
    };

    fn config() -> ServerConfig {
        let mut config = ServerConfig::default();
        config.backend = BackendType::Memory;
        config
    }

    #[test]
    fn generate_chain_and_verify() {
        let config = config();
        let storage = get_storage(&config);

        let ca_name = format!("{} Authority", config.realm);

        generate_root_ca(&config, storage.as_ref()).expect("couldn't generate root ca");
        generate_intermediate_ca(&config, storage.as_ref()).expect("couldn't generate intermediate ca");

        let pk = Picky::generate_private_key(2048).expect("couldn't generate private key");
        let csr = Csr::generate(
            DirectoryName::new_common_name("Mister Bushido"),
            &pk,
            SignatureHashType::RsaSha384,
        )
        .expect("couldn't generate csr");

        let signed_cert =
            sign_certificate(&ca_name, csr, &config, storage.as_ref()).expect("couldn't sign certificate");

        let issuer_name = signed_cert.issuer_name().find_common_name().unwrap().to_string();
        let chain_pem = find_ca_chain(storage.as_ref(), &issuer_name).expect("couldn't fetch CA chain");

        assert_eq!(chain_pem.len(), 2);

        let chain = chain_pem
            .iter()
            .map(|cert_pem| {
                let pem = cert_pem.parse::<Pem>().expect("couldn't parse cert pem");
                Cert::from_der(pem.data()).expect("couldn't parse cert from der")
            })
            .collect::<Vec<Cert>>();

        assert_eq!(chain[0].subject_name().to_string(), "CN=Picky Authority");
        assert_eq!(chain[1].subject_name().to_string(), "CN=Picky Root CA");

        signed_cert
            .verify_chain(chain.iter(), &UTCDate::now())
            .expect("couldn't validate ca chain");
    }

    fn new_saphir_request(headers: Vec<(&str, &str)>) -> SyncRequest {
        use saphir::Request;

        let mut request = Request::builder();
        for (header, value) in headers.into_iter() {
            request.header(header, value);
        }
        let (parts, _) = request.body(()).unwrap().into_parts();

        SyncRequest::new(parts, vec![])
    }

    #[test]
    fn request_format() {
        let format =
            Format::request_format(&new_saphir_request(vec![("Content-Type", "application/x-pem-file")])).unwrap();
        assert_eq!(format, Format::PemFile);

        let format = Format::request_format(&new_saphir_request(vec![("Content-Type", "application/json")])).unwrap();
        assert_eq!(format, Format::Json);

        let format = Format::request_format(&new_saphir_request(vec![
            ("Content-Type", "application/pkix-cert"),
            ("Content-Transfer-Encoding", "binary"),
        ]))
        .unwrap();
        assert_eq!(format, Format::PkixCertBinary);

        let format = Format::request_format(&new_saphir_request(vec![
            ("Content-Type", "application/pkcs10"),
            ("Content-Transfer-Encoding", "base64"),
        ]))
        .unwrap();
        assert_eq!(format, Format::Pkcs10Base64);
    }

    #[test]
    fn request_format_err() {
        let err = Format::request_format(&new_saphir_request(vec![])).err().unwrap();
        assert_eq!(err, "Content-Type header is missing");

        let err = Format::request_format(&new_saphir_request(vec![("Content-Type", "application/pkcs10")]))
            .err()
            .unwrap();
        assert_eq!(err, "format encoding for pkcs10 is missing");

        let err = Format::request_format(&new_saphir_request(vec![
            ("Content-Type", "application/unknown"),
            ("Content-Transfer-Encoding", "unknown"),
        ]))
        .err()
        .unwrap();
        assert_eq!(err, "unsupported format: application/unknown");

        let err = Format::request_format(&new_saphir_request(vec![
            ("Content-Type", "application/pkcs10"),
            ("Content-Transfer-Encoding", "unknown"),
        ]))
        .err()
        .unwrap();
        assert_eq!(err, "unsupported encoding format for pkcs10: unknown");
    }

    #[test]
    fn response_format() {
        let format = Format::response_format(&new_saphir_request(vec![("Accept", "application/x-pem-file")])).unwrap();
        assert_eq!(format, Format::PemFile);

        let format = Format::response_format(&new_saphir_request(vec![(
            "Accept",
            "application/json;q=0.5, application/x-pem-file",
        )]))
        .unwrap();
        assert_eq!(format, Format::Json);

        let format = Format::response_format(&new_saphir_request(vec![
            (
                "Accept",
                "application/pkix-cert, application/x-pem-file, snateinsrturiest",
            ),
            ("Accept-Encoding", "binary, base64"),
        ]))
        .unwrap();
        assert_eq!(format, Format::PkixCertBinary);

        let format = Format::response_format(&new_saphir_request(vec![
            ("Accept", "application/pkcs10;q=1"),
            ("Accept-Encoding", "base64;q=1"),
        ]))
        .unwrap();
        assert_eq!(format, Format::Pkcs10Base64);
    }

    #[test]
    fn response_format_err() {
        let err = Format::response_format(&new_saphir_request(vec![])).err().unwrap();
        assert_eq!(err, "Accept header is missing");
    }
}
