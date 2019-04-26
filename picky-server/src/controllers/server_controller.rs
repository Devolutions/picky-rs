use saphir::*;
use serde_json;
use serde_json::Value;
use base64::URL_SAFE_NO_PAD;

use crate::configuration::ServerConfig;
use picky_core::controllers::core_controller::CoreController;
use crate::db::mongodb::mongo_repos::MongoRepos;
use crate::controllers::db_controller::DbStorage;
use crate::utils::*;

const CERT_PREFIX: &str = "-----BEGIN CERTIFICATE-----\n";
const CERT_SUFFIX: &str = "\n-----END CERTIFICATE-----\n";

pub struct ControllerData{
    pub repos: MongoRepos,
    pub config: ServerConfig
}

pub struct ServerController{
    dispatch: ControllerDispatch<ControllerData>
}

impl ServerController {
    pub fn new(repos: MongoRepos, config: ServerConfig) -> Self{
        let controller_data = ControllerData{
            repos,
            config
        };

        let dispatch = ControllerDispatch::new(controller_data);
        dispatch.add(Method::GET, "/chain/<api-key>", chains);
        dispatch.add(Method::POST, "/signcert/", sign_cert);
        dispatch.add(Method::POST, "/name/", request_name);

        ServerController {
            dispatch
        }
    }
}

impl Controller for ServerController{
    fn handle(&self, req: &mut SyncRequest, res: &mut SyncResponse){
        self.dispatch.dispatch(req, res);
    }

    fn base_path(&self) -> &str{
        "/"
    }
}

pub fn sign_cert(controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse){
    res.status(StatusCode::BAD_REQUEST);
    let repo = &controller_data.repos;

    if let Ok(body) = String::from_utf8(req.body().clone()) {
        if let Ok(json) = serde_json::from_str::<Value>(body.as_ref()) {
            let mut ca = json["ca"].to_string();
            ca = ca.trim_matches('"').to_string();
            let mut csr = json["csr"].to_string().trim_matches('"').replace("\\n", "\n").to_string();
            csr = csr.trim_matches('"').to_string();

            if let Ok(ca) = repo.find(ca.trim_matches('"')) {
                if let Ok(ca) = repo.get(&ca[0].key){
                    if let Some(ca) = ca{
                        if let Some(cert) = CoreController::generate_certificate_from_csr(&ca.0, &ca.1, controller_data.config.key_config.hash_type, &csr){
                            res.body(cert);
                            res.status(StatusCode::OK);
                        }
                    }
                }
            }
        }
    }
}

pub fn cert(controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse){
    res.status(StatusCode::BAD_REQUEST);
    let repos = &controller_data.repos;

    if let Some(multihash) = req.captures().get("api-key").and_then(|c| base64::decode_config(c, URL_SAFE_NO_PAD).ok()){
        let decoded = String::from_utf8_lossy(&multihash);

        if let Ok(certs) = repos.find(decoded.clone().trim_matches('"')){
            for cert in certs{
                if let Ok(Some(c)) = repos.get(&cert.value){
                    res.body(c.0);
                    res.status(StatusCode::OK);
                }
            }
        }
    }
}

pub fn chains(controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse){
    res.status(StatusCode::BAD_REQUEST);
    let repos = &controller_data.repos;

    if let Some(common_name) = req.captures().get("api-key").and_then(|c| base64::decode_config(c, URL_SAFE_NO_PAD).ok()){
        let decoded = String::from_utf8_lossy(&common_name);
        if let Ok(intermediate) = repos.find(decoded.clone().trim_matches('"').trim_matches('\0')) {
            if let Ok(cert) = repos.get(&intermediate[0].value){
                let mut chain = String::default();
                let cert = cert.unwrap();
                chain.push_str(&format!("{}{}{}", CERT_PREFIX, cert.0, CERT_SUFFIX));

                let mut child = intermediate[0].value.clone();

                loop {
                    if let Ok(parent) = repos.get_parent(&child){
                        chain.push_str(&format!("{}{}{}", CERT_PREFIX, &parent.1.clone(), CERT_SUFFIX));
                        child = parent.0.clone();
                    } else {
                        break;
                    }
                }

                res.body(chain.to_string());
                res.status(StatusCode::OK);
            }
        }
    }
}

pub fn request_name(_controller_data: &ControllerData, req: &SyncRequest, res: &mut SyncResponse){
    res.status(StatusCode::BAD_REQUEST);

    if let Ok(body) = String::from_utf8(req.body().clone()) {
        if let Ok(json) = serde_json::from_str::<Value>(body.as_ref()){
            let csr = json["csr"].to_string().trim_matches('"').replace("\\n", "\n");
            if let Ok(common_name) = CoreController::request_name(&csr){
                res.body(common_name);
                res.status(StatusCode::OK);
            }
        }
    }
}

pub fn generate_root_ca(config: &ServerConfig, repos: &MongoRepos) -> Result<bool, String>{
    if let Ok(certs) = repos.find(&format!("{} Root CA", config.realm)) {
        if certs.len() > 0 {
            return Ok(false);
        }
    }

    if let Some(root) = CoreController::generate_root_ca(&config.realm, config.key_config.hash_type, config.key_config.key_type){
        if let Err(e) = repos.store(&root.common_name.clone(), &root.certificate_pem.clone(), &root.keys.key_pem.clone()){
            return Err(format!("Insertion error: {:?}", e));
        }
    }

    Ok(true)
}

pub fn generate_intermediate(config: &ServerConfig, repos: &MongoRepos) -> Result<bool, String>{
    if let Ok(certs) = repos.find(&format!("{} Authority", config.realm)) {
        if certs.len() > 0 {
            return Ok(false);
        }
    }

    let root = match repos.find(&format!("{} Root CA", config.realm)){
        Ok(r) => r,
        Err(e) => {
            return Err(format!("Could not find root: {:?}", e));
        }
    };

    if let Ok(root) = repos.get(&root[0].value){
        if let Some(root) = root{
            if let Some(intermediate) = CoreController::generate_intermediate_ca(&root.0, &root.1, &config.realm, config.key_config.hash_type, config.key_config.key_type){
                if let Err(e) = repos.store(&intermediate.common_name.clone(), &intermediate.certificate_pem.clone(), &intermediate.keys.key_pem.clone()){
                    return Err(format!("Insertion error: {:?}", e));
                }

                return repos.link_cert(&intermediate.certificate_pem.clone(), &root.0);
            }
        }
    }

    Ok(true)
}