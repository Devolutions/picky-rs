use crate::{
    addressing::{convert_to_canonical_base, CANONICAL_HASH},
    config::{CertKeyPair, Config},
    db::{get_storage, BoxedPickyStorage, CertificateEntry, PickyStorage},
    http::{
        authorization::{check_authorization, Authorized, ProviderClaims},
        utils::{Format, StatusCodeResult},
    },
    logging::build_logger_config,
    picky_controller::Picky,
    utils::{GreedyError, PathOr},
};
use log4rs::Handle;
use picky::{
    pem::{parse_pem, to_pem, Pem},
    x509::{Cert, Csr},
};
use saphir::{prelude::*, response::Builder as ResponseBuilder};
use serde_json::{self, Value};
use std::{borrow::Cow, convert::TryFrom};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub struct ServerController {
    storage: BoxedPickyStorage,
    config: RwLock<Config>,
    log_handle: Handle,
}

impl ServerController {
    pub async fn new(config: Config, log_handle: Handle) -> Result<Self, String> {
        let storage = get_storage(&config).await;
        init_storage_from_config(storage.as_ref(), &config).await?;
        Ok(Self {
            storage,
            config: RwLock::new(config),
            log_handle,
        })
    }

    async fn read_conf(&self) -> RwLockReadGuard<'_, Config> {
        self.config.read().await
    }

    async fn write_conf(&self) -> RwLockWriteGuard<'_, Config> {
        self.config.write().await
    }
}

#[controller(name = "")]
impl ServerController {
    #[get("/health")]
    async fn health(&self) -> Result<&'static str, StatusCode> {
        self.storage.health().await.service_unavailable()?;
        Ok("I'm alive!")
    }

    #[post("/cert")]
    async fn post_cert(&self, req: Request) -> Result<StatusCode, StatusCode> {
        let req = req.load_body().await.bad_request()?;

        let (cert, der) = extract_cert_from_request(&req).await.bad_request()?;
        let ski = hex::encode(cert.subject_key_identifier().bad_request_desc("couldn't fetch SKI")?);
        let issuer_name = cert
            .issuer_name()
            .find_common_name()
            .bad_request_desc("couldn't find issuer common name")?
            .to_string();

        if issuer_name != format!("{} Authority", &self.read_conf().await.realm) {
            log::error!("this certificate was not signed by the CA of this server.");
            return Err(StatusCode::UNAUTHORIZED);
        }

        let subject_name = cert
            .subject_name()
            .find_common_name()
            .bad_request_desc("couldn't find subject issuer common name")?
            .to_string();

        if let Err(e) = self
            .storage
            .store(CertificateEntry {
                name: subject_name.clone(),
                cert: der,
                key_identifier: ski,
                key: None,
            })
            .await
        {
            log::error!("insertion failed for leaf {}: {}", subject_name, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }

        Ok(StatusCode::OK)
    }

    #[options("/sign")]
    async fn cert_signature_request_cors(&self, req: Request) -> ResponseBuilder {
        let builder = ResponseBuilder::new()
            .header("Access-Control-Allow-Methods", "POST")
            .header("Access-Control-Allow-Headers", "Authorization, Content-Type");

        if let Some(origin_header) = req.headers().get("Origin") {
            builder.header("Access-Control-Allow-Origin", origin_header)
        } else {
            builder
        }
    }

    #[post("/sign")]
    async fn cert_signature_request(&self, req: Request) -> Result<ResponseBuilder, StatusCode> {
        let (locked_subject_name, x509_duration_secs) = match check_authorization(&*self.read_conf().await, &req) {
            Ok(Authorized::ApiKey) => (None, None),
            Ok(Authorized::Token(token)) => {
                let provider_claims: ProviderClaims = serde_json::from_value(token.into_claims()).bad_request()?;
                (Some(provider_claims.sub), provider_claims.x509_duration_secs)
            }
            Err(e) => {
                log::error!("authorization failed: {}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        };

        let req = req.load_body().await.bad_request()?;

        let csr = extract_csr_from_request(&req).await.bad_request()?;

        if let Some(locked_subject_name) = locked_subject_name {
            let subject_name = csr
                .subject_name()
                .find_common_name()
                .bad_request_desc("couldn't find signed CSR subject common name")?
                .to_string();

            if locked_subject_name != subject_name {
                log::error!(
                    "Requested a certificate with an unauthorized subject name: {}, expected: {}",
                    subject_name,
                    locked_subject_name
                );
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        // Sign CSR
        let conf = self.read_conf().await;
        let ca_name = format!("{} Authority", &conf.realm);
        let signed_cert = sign_certificate(&ca_name, csr, &conf, self.storage.as_ref(), x509_duration_secs)
            .await
            .internal_error()?;
        drop(conf); // release lock early

        let builder = match Format::response_format(&req).unwrap_or(Format::PemFile) {
            Format::PemFile => {
                let pem = signed_cert
                    .to_pem()
                    .internal_error_desc("couldn't get certificate pem")?;
                ResponseBuilder::new().body(pem.to_string())
            }
            Format::PkixCertBinary => {
                let der = signed_cert
                    .to_der()
                    .internal_error_desc("couldn't get certificate der")?;
                ResponseBuilder::new().body(der)
            }
            Format::PkixCertBase64 => {
                let der = signed_cert
                    .to_der()
                    .internal_error_desc("couldn't get certificate der")?;
                ResponseBuilder::new().body(base64::encode(&der))
            }
            unexpected => {
                log::error!("unexpected response format: {}", unexpected);
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        builder
            .headers_mut()
            .internal_error()?
            .insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));

        Ok(builder)
    }

    #[get("/cert/<multihash>")]
    async fn get_cert(&self, multihash: String, req: Request) -> Result<ResponseBuilder, StatusCode> {
        let addressing_hash_any_base = multihash;
        let (addressing_hash, hash) = convert_to_canonical_base(&addressing_hash_any_base).internal_error()?;
        let canonical_address = if hash == CANONICAL_HASH {
            addressing_hash
        } else {
            let converted = self
                .storage
                .lookup_addressing_hash(&addressing_hash)
                .await
                .internal_error_desc("address lookup failed")?;
            log::info!("converted cert address {} -> {}", addressing_hash_any_base, converted);
            converted
        };

        let cert_der = match self.storage.get_cert_by_addressing_hash(&canonical_address).await {
            Ok(cert_der) => cert_der,
            Err(e) => {
                log::error!("couldn't fetch certificate using hash {}: {}", canonical_address, e);
                return Err(StatusCode::NOT_FOUND);
            }
        };

        match Format::response_format(&req).unwrap_or(Format::PemFile) {
            Format::PemFile => Ok(ResponseBuilder::new().body(to_pem("CERTIFICATE", &cert_der))),
            Format::PkixCertBinary => Ok(ResponseBuilder::new().body(cert_der)),
            Format::PkixCertBase64 => Ok(ResponseBuilder::new().body(base64::encode(&cert_der))),
            unexpected => {
                log::error!("unexpected response format: {}", unexpected);
                Err(StatusCode::BAD_REQUEST)
            }
        }
    }

    #[get("/chain")]
    async fn get_default_chain(&self) -> Result<String, StatusCode> {
        let ca = format!("{} Authority", &self.read_conf().await.realm);
        let chain = find_ca_chain(self.storage.as_ref(), &ca).await.not_found()?;
        Ok(chain.join("\n"))
    }

    #[get("/reload")]
    async fn reload_yaml_conf(&self) -> (&'static str, StatusCode) {
        match self.reload_yaml_conf_impl().await {
            Ok(()) => ("Config reloaded successfully!", StatusCode::OK),
            Err(e) => {
                log::error!("couldn't reload config: {}", e);
                ("Couldn't reload config... See logs", StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

impl ServerController {
    async fn reload_yaml_conf_impl(&self) -> Result<(), String> {
        match Config::init_yaml() {
            Ok(new_conf) => {
                log::info!("new config: {:#?}", new_conf);

                init_storage_from_config(self.storage.as_ref(), &new_conf).await?;

                match build_logger_config(&new_conf) {
                    Ok(logger_config) => self.log_handle.set_config(logger_config),
                    Err(e) => {
                        log::warn!("couldn't reload logger configuration: {}", e);
                    }
                }

                let mut old_conf = self.write_conf().await;
                if old_conf.database_url != new_conf.database_url {
                    log::warn!("'database_url' modification require service restart");
                }
                if old_conf.file_backend_path != new_conf.file_backend_path {
                    log::warn!("'file_backend_path' modification require service restart");
                }
                if old_conf.backend != new_conf.backend {
                    log::warn!("'backend' modification require service restart");
                }
                *old_conf = new_conf;

                log::info!("reloaded successfully");
                Ok(())
            }
            Err(e) => Err(format!("couldn't reload config: {}", e)),
        }
    }
}

async fn extract_cert_from_request(req: &Request<Bytes>) -> Result<(Cert, Vec<u8>), GreedyError> {
    match Format::request_format(&req)? {
        Format::PemFile => {
            let pem = parse_pem(req.body())?;
            Ok((Cert::from_der(pem.data())?, pem.into_data().into_owned()))
        }
        Format::Json => {
            let json = serde_json::from_slice::<Value>(req.body())?;
            let pem = json["certificate"]
                .to_string()
                .trim_matches('"')
                .replace("\\n", "\n")
                .parse::<Pem>()?;
            Ok((Cert::from_der(pem.data())?, pem.into_data().into_owned()))
        }
        Format::PkixCertBinary => Ok((Cert::from_der(req.body())?, req.body().to_vec())),
        Format::PkixCertBase64 => {
            let der = base64::decode(req.body())?;
            Ok((Cert::from_der(&der)?, der))
        }
        unexpected => Err(GreedyError(format!("unexpected request format: {}", unexpected))),
    }
}

async fn extract_csr_from_request(req: &Request<Bytes>) -> Result<Csr, GreedyError> {
    match Format::request_format(req)? {
        Format::PemFile => {
            let pem = parse_pem(req.body())?;
            Ok(Csr::from_der(pem.data())?)
        }
        Format::Json => {
            let json = serde_json::from_slice::<Value>(req.body())?;
            let pem = json["csr"]
                .to_string()
                .trim_matches('"')
                .replace("\\n", "\n")
                .parse::<Pem>()?;
            Ok(Csr::from_der(pem.data())?)
        }
        Format::Pkcs10Binary => Ok(Csr::from_der(req.body())?),
        Format::Pkcs10Base64 => {
            let der = base64::decode(req.body())?;
            Ok(Csr::from_der(&der)?)
        }
        unexpected => Err(GreedyError(format!("unexpected request format: {}", unexpected))),
    }
}

async fn sign_certificate(
    ca_name: &str,
    csr: Csr,
    config: &Config,
    storage: &dyn PickyStorage,
    x509_duration_secs: Option<u64>,
) -> Result<Cert, String> {
    let ca_hash = storage
        .get_addressing_hash_by_name(ca_name)
        .await
        .map_err(|e| format!("couldn't fetch CA: {}", e))?;

    let ca_cert_der = storage
        .get_cert_by_addressing_hash(&ca_hash)
        .await
        .map_err(|e| format!("couldn't get CA cert der: {}", e))?;
    let ca_cert = Cert::from_der(&ca_cert_der).map_err(|e| format!("couldn't deserialize CA cert: {}", e))?;

    let ca_pk_der = storage
        .get_key_by_addressing_hash(&ca_hash)
        .await
        .map_err(|e| format!("couldn't fetch CA private key: {}", e))?;
    let ca_pk = Picky::parse_pk_from_magic_der(&ca_pk_der).map_err(|e| e.to_string())?;

    let dns_name = csr
        .subject_name()
        .find_common_name()
        .ok_or_else(|| "couldn't find signed cert subject common name")?
        .to_string();

    let signed_cert = if let Some(duration_secs) = x509_duration_secs {
        Picky::generate_leaf_from_csr_with_duration(
            csr,
            &ca_cert,
            &ca_pk,
            config.signing_algorithm,
            &dns_name,
            chrono::Duration::seconds(
                i64::try_from(duration_secs).map_err(|e| format!("invalid x509 duration (too big?): {}", e))?,
            ),
        )
    } else {
        Picky::generate_leaf_from_csr(csr, &ca_cert, &ca_pk, config.signing_algorithm, &dns_name)
    }
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
            .await
            .map_err(|e| format!("insertion error for leaf {}: {}", dns_name, e))?;
    }

    Ok(signed_cert)
}

async fn find_ca_chain(storage: &dyn PickyStorage, ca_name: &str) -> Result<Vec<String>, String> {
    let ca_hash = storage
        .get_addressing_hash_by_name(ca_name)
        .await
        .map_err(|e| format!("couldn't fetch CA hash id for {}: {}", ca_name, e))?;

    let mut cert_der = storage
        .get_cert_by_addressing_hash(&ca_hash)
        .await
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

        let hash_address = storage
            .get_addressing_hash_by_key_identifier(&parent_key_id)
            .await
            .map_err(|e| format!("couldn't fetch hash: {}", e))?;

        cert_der = storage
            .get_cert_by_addressing_hash(&hash_address)
            .await
            .map_err(|e| format!("couldn't fetch certificate der: {}", e))?;

        chain.push(to_pem("CERTIFICATE", &cert_der));

        current_key_id = parent_key_id;
    }

    Ok(chain)
}

async fn generate_root_ca(config: &Config, storage: &dyn PickyStorage) -> Result<bool, String> {
    let name = format!("{} Root CA", config.realm);

    if let Ok(certs) = storage.get_addressing_hash_by_name(&name).await {
        if !certs.is_empty() {
            // already exists
            return Ok(false);
        }
    }

    let pk = Picky::generate_private_key(4096).map_err(|e| format!("couldn't generate private key: {}", e))?;
    let root = Picky::generate_root(&name, &pk, config.signing_algorithm)
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
        .await
        .map_err(|e| format!("couldn't store generated root certificate: {}", e))?;

    Ok(true)
}

async fn generate_intermediate_ca(config: &Config, storage: &dyn PickyStorage) -> Result<bool, String> {
    let root_name = format!("{} Root CA", config.realm);
    let intermediate_name = format!("{} Authority", config.realm);

    if let Ok(certs) = storage.get_addressing_hash_by_name(&intermediate_name).await {
        if !certs.is_empty() {
            // already exists
            return Ok(false);
        }
    }

    let (root_cert_der, root_key_der) = match storage.get_addressing_hash_by_name(&root_name).await {
        Ok(root_hash) => (
            storage
                .get_cert_by_addressing_hash(&root_hash)
                .await
                .map_err(|e| format!("couldn't fetch root CA: {}", e))?,
            storage
                .get_key_by_addressing_hash(&root_hash)
                .await
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
        config.signing_algorithm,
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
        .await
        .map_err(|e| format!("couldn't store generated intermediate certificate: {}", e))?;

    Ok(true)
}

async fn inject_config_provided_cert(
    expected_subject_name: &str,
    cert_key_pair: &CertKeyPair,
    storage: &dyn PickyStorage,
) -> Result<(), String> {
    let (cert, cert_der) = match &cert_key_pair.cert {
        PathOr::Path(path) => {
            let pem_str = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| format!("couldn't read cert: {}", e))?;
            let pem = pem_str
                .parse::<Pem>()
                .map_err(|e| format!("couldn't parse cert pem: {}", e))?;
            let cert = Cert::from_pem(&pem).map_err(|e| format!("couldn't parse cert: {}", e))?;
            (Cow::Owned(cert), pem.into_data().into_owned())
        }
        PathOr::Some(cert) => {
            let cert_der = cert
                .to_der()
                .map_err(|e| format!("couldn't encode cert to der: {}", e))?;
            (Cow::Borrowed(cert), cert_der)
        }
    };

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

    let key_der = match &cert_key_pair.key {
        PathOr::Path(path) => {
            let pem_str = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| format!("couldn't read key: {}", e))?;
            let pem = pem_str
                .parse::<Pem>()
                .map_err(|e| format!("couldn't parse key pem: {}", e))?;
            pem.into_data().into_owned()
        }
        PathOr::Some(key) => key
            .to_pkcs8()
            .map_err(|e| format!("couldn't convert key to pkcs8: {}", e))?,
    };

    storage
        .store(CertificateEntry {
            name: subject_name,
            cert: cert_der,
            key_identifier: ski,
            key: Some(key_der),
        })
        .await
        .map_err(|e| format!("couldn't store certificate: {}", e))?;

    Ok(())
}

async fn init_storage_from_config(storage: &dyn PickyStorage, config: &Config) -> Result<(), String> {
    log::info!("init storage from config");

    if let Some(root_cert_key_pair) = &config.root {
        log::info!("inject root CA provided by settings");
        let expected = format!("{} Root CA", config.realm);
        if let Err(e) = inject_config_provided_cert(&expected, root_cert_key_pair, storage).await {
            return Err(format!("couldn't inject root CA: {}", e));
        }
    } else {
        log::info!("root CA...");
        let created = generate_root_ca(&config, storage)
            .await
            .map_err(|e| format!("couldn't generate root CA: {}", e))?;
        if created {
            log::info!("created");
        } else {
            log::info!("already exists");
        }
    }

    if let Some(intermediate_cert_key_pair) = &config.intermediate {
        log::info!("inject intermediate CA provided by settings");
        let expected = format!("{} Authority", config.realm);
        if let Err(e) = inject_config_provided_cert(&expected, intermediate_cert_key_pair, storage).await {
            return Err(format!("couldn't inject intermediate CA: {}", e));
        }
    } else {
        log::info!("intermediate CA...");
        let created = generate_intermediate_ca(&config, storage)
            .await
            .map_err(|e| format!("couldn't generate intermediate CA: {}", e))?;
        if created {
            log::info!("created");
        } else {
            log::info!("already exists");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendType;
    use picky::{
        signature::SignatureHashType,
        x509::{date::UTCDate, name::DirectoryName},
    };
    use tokio_test::block_on;

    fn config() -> Config {
        let mut config = Config::default();
        config.backend = BackendType::Memory;
        config
    }

    #[test]
    fn generate_chain_and_verify() {
        let config = config();
        let storage = block_on(get_storage(&config));

        let ca_name = format!("{} Authority", config.realm);

        block_on(generate_root_ca(&config, storage.as_ref())).expect("couldn't generate root ca");
        block_on(generate_intermediate_ca(&config, storage.as_ref())).expect("couldn't generate intermediate ca");

        let pk = Picky::generate_private_key(2048).expect("couldn't generate private key");
        let csr = Csr::generate(
            DirectoryName::new_common_name("Mister Bushido"),
            &pk,
            SignatureHashType::RsaSha384,
        )
        .expect("couldn't generate csr");

        let signed_cert = block_on(sign_certificate(&ca_name, csr, &config, storage.as_ref(), None))
            .expect("couldn't sign certificate");

        let issuer_name = signed_cert.issuer_name().find_common_name().unwrap().to_string();
        let chain_pem = block_on(find_ca_chain(storage.as_ref(), &issuer_name)).expect("couldn't fetch CA chain");

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
}
