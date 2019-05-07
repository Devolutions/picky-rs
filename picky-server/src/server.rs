use crate::configuration::ServerConfig;
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::mongodb::mongo_repos::MongoRepos;

use saphir::{Middleware, SyncRequest, SyncResponse, RequestContinuation, StatusCode, header};
use saphir::Server as SaphirServer;
use crate::controllers::server_controller::{ServerController, generate_root_ca, generate_intermediate, check_certs_in_env};
use crate::db::backend::Backend;
use std::sync::Arc;

pub struct Server{
}

impl Server{
    pub fn run(config: ServerConfig) {
        let mut repos = Backend::from(&config).db;
        repos.init().expect("Picky cannot start without fully initializing its repos");
        if let Err(e) = check_certs_in_env(&config, &mut repos){
            info!("Error loading certificates in environment: {}", e);
        }

        info!("Creating root...");
        generate_root_ca(&config, &mut repos).and_then(|created|{
            if created {
                info!("Root CA Created");
            } else {
                info!("Root CA already exists");
            }
            info!("Creating intermediate...");
            generate_intermediate(&config, &mut repos)
        }).map(|created|{
            if created {
                info!("Intermediate Created");
            } else {
                info!("Intermediate already exists");
            }
        }).expect("Unable to configure picky");

        let _server = SaphirServer::builder()
            .configure_middlewares(|middle_stack|{
                middle_stack.apply(AuthMiddleware::new(config.clone()), ["/"].to_vec(), Some(vec![r"^/chain", r"^/json-chain", r"^/health", r"^/authority"]))
            }).configure_router(|router|{
            let controller = ServerController::new(repos.clone(), config.clone());
            router.add(controller)
        }).configure_listener(|listener_config|{
            listener_config.set_uri("http://0.0.0.0:12345")
        }).build()
            .run();
    }
}

pub struct AuthMiddleware{
    config: ServerConfig
}

impl AuthMiddleware{
    pub fn new(config: ServerConfig) -> Self{
        AuthMiddleware{
            config
        }
    }
}

impl Middleware for AuthMiddleware{
    fn resolve(&self, req: &mut SyncRequest, res: &mut SyncResponse) -> RequestContinuation{
        res.status(StatusCode::UNAUTHORIZED);

        let header = match req.headers_map().get(header::AUTHORIZATION){
            Some(h) => h.clone(),
            None => {
                res.status(StatusCode::UNAUTHORIZED);
                return RequestContinuation::Stop;
            }
        };

        let auth_str = match header.to_str() {
            Ok(s) => s,
            Err(_e) => {
                res.status(StatusCode::UNAUTHORIZED);
                return RequestContinuation::Stop;
            }
        };

        validate_api_key(&self.config, auth_str, res)
    }
}

fn validate_api_key(config: &ServerConfig, auth_str: &str, res: &mut SyncResponse) -> RequestContinuation{
    let auth_vec = auth_str.split(' ').collect::<Vec<&str>>();

    if auth_vec.len() != 2{
        res.status(StatusCode::UNAUTHORIZED);
        return RequestContinuation::Stop;
    }

    let method = auth_vec[0].to_lowercase();
    let api_key = auth_vec[1];
    if let "bearer" = method.as_str() {
        if api_key.eq(config.api_key.as_str()) {
            return RequestContinuation::Continue;
        }
    }

    res.status(StatusCode::UNAUTHORIZED);
    RequestContinuation::Stop
}

#[cfg(test)]
mod tests{
    use super::*;
    use std::env::set_var;
    use curl;
    use curl::easy::{Easy, List, Auth};
    use std::thread;
    use std::sync::mpsc::Receiver;
    use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
    use std::sync::{Arc, Mutex};
    use std::thread::{JoinHandle, Thread, sleep};
    use log::LevelFilter;
    use mongodb::error::ErrorCode::OK;
    use std::time::Duration;
    use serde_json;
    use crate::utils;

    const TEST_CSR: &'static [u8] = include_bytes!("../../assets/test_csr.csr");
    const TEST_ROOT: &'static [u8] = include_bytes!("../../assets/test_root.crt");
    const TEST_ROOT_KEY: &'static [u8] = include_bytes!("../../assets/test_root_key.pem");
    const TEST_INTERMEDIATE: &'static [u8] = include_bytes!("../../assets/test_intermediate.crt");
    const TEST_INTERMEDIATE_KEY: &'static [u8] = include_bytes!("../../assets/test_intermediate_key.pem");
    const TEST_HASH: &'static str = "122002bb29239b25eca26b77b4212c0bc7baa52b7f4be46cff2249f204c2ee6a555d";

    const PICKY_REALM_ENV: &'static str = "PICKY_REALM";
    const PICKY_DATABASE_URL_ENV: &'static str = "PICKY_DATABASE_URL";
    const PICKY_API_KEY_ENV: &'static str = "PICKY_API_KEY";
    const PICKY_BACKEND_ENV: &'static str = "PICKY_BACKEND";
    const PICKY_ROOT_CERT_ENV: &'static str = "PICKY_ROOT_CERT";
    const PICKY_ROOT_KEY_ENV: &'static str = "PICKY_ROOT_KEY";
    const PICKY_INTERMEDIATE_CERT_ENV: &'static str = "PICKY_INTERMEDIATE_CERT";
    const PICKY_INTERMEDIATE_KEY_ENV: &'static str = "PICKY_INTERMEDIATE_KEY";

    const LISTENING_URL: &'static str = "http://0.0.0.0:12345/";
    const URL_REALM: &'static str = "bXlfZGVuLmxvbCBBdXRob3JpdHk";
    const PICKY_API_KEY: &'static str = "11d9f888-3334-4b25-a812-7d0d64d5f235";

    fn init_logs(config: &ServerConfig) {
        use log4rs::append::console::ConsoleAppender;
        use log4rs::config::{Appender, Config as ConfigLog4rs, Logger, Root};
        let console_appender = ConsoleAppender::builder().build();

        let config = ConfigLog4rs::builder()
            .appender(Appender::builder().build("stdout", Box::new(console_appender)))
            .logger(Logger::builder().build("poston", LevelFilter::Off))
            .logger(Logger::builder().build("mio", LevelFilter::Off))
            .logger(Logger::builder().build("mio_extras", LevelFilter::Off))
            .logger(Logger::builder().build("hyper", LevelFilter::Off))
            .logger(Logger::builder().build("r2d2", LevelFilter::Warn))
            .logger(Logger::builder().build("tokio_io", LevelFilter::Off))
            .logger(Logger::builder().build("tokio_reactor", LevelFilter::Off))
            .logger(Logger::builder().build("tokio_threadpool", LevelFilter::Off))
            .logger(Logger::builder().build("tokio_core", LevelFilter::Off))
            .build(Root::builder().appender("stdout").build(config.level_filter()))
            .expect("Unable to configure logger");

        if let Err(e) = log4rs::init_config(config) {
            println!("Can't init log4rs: {}", e);
        }
    }

    fn set_env(backend: &str){
        set_var(PICKY_BACKEND_ENV, backend);
        set_var(PICKY_REALM_ENV, "my_den.lol");
        set_var(PICKY_API_KEY_ENV, "11d9f888-3334-4b25-a812-7d0d64d5f235");
        set_var(PICKY_ROOT_CERT_ENV, String::from_utf8_lossy(TEST_ROOT).to_string());
        set_var(PICKY_ROOT_KEY_ENV, String::from_utf8_lossy(TEST_ROOT_KEY).to_string());
        set_var(PICKY_INTERMEDIATE_CERT_ENV, String::from_utf8_lossy(TEST_INTERMEDIATE).to_string());
        set_var(PICKY_INTERMEDIATE_KEY_ENV, String::from_utf8_lossy(TEST_INTERMEDIATE_KEY).to_string());
    }

    fn run_server(){

        let conf = ServerConfig::new();

        init_logs(&conf);

        Server::run(conf);
    }

    fn initialize_curl_call() -> Easy{
        let mut easy = Easy::new();
        let _ = easy.ssl_verify_host(false);
        let _ = easy.ssl_verify_peer(false);
        easy.post(true).unwrap();
        easy.get(true).unwrap();

        let mut list = List::new();
        list.append("Content-Type: application/json").unwrap();
        list.append("Authorization: Bearer 11d9f888-3334-4b25-a812-7d0d64d5f235");
        easy.http_headers(list).unwrap();
        easy
    }

    fn get_curl_data(easy: &mut Easy) -> Vec<u8>{
        let mut data = Vec::new();
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|new_data|{
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            }).unwrap();

            transfer.perform().unwrap();
        }

        data
    }

    fn call_get_chain() -> Result<(), curl::Error>{
        let mut easy = initialize_curl_call();
        let url = format!("{}{}{}", LISTENING_URL, "chain/", URL_REALM);
        easy.url(&url);

        let chain = String::from_utf8(get_curl_data(&mut easy)).unwrap();
        println!("Chain : {:?}", chain);
        Ok(())
    }

    fn call_sign_cert() -> Result<(), curl::Error>{
        let mut easy = initialize_curl_call();
        let url = format!("{}{}", LISTENING_URL, "signcert/");
        let csr = String::from_utf8_lossy(TEST_CSR);
        easy.url(&url);
        let json_body: String = json!({
                "csr": csr,
                "ca": format!("{} Authority", "my_den.lol")
            }).to_string();

        easy.post_fields_copy(json_body.as_bytes());

        let cert = String::from_utf8(get_curl_data(&mut easy)).unwrap();
        println!("SignCert : {:?}", cert);

        Ok(())
    }

    fn call_request_name() -> Result<(), curl::Error>{
        let mut easy = initialize_curl_call();
        let url = format!("{}{}", LISTENING_URL, "name/");
        let csr = String::from_utf8_lossy(TEST_CSR);
        easy.url(&url);
        let json_body: String = json!({
                "csr": csr
            }).to_string();

        easy.post_fields_copy(json_body.as_bytes());

        let name = String::from_utf8(get_curl_data(&mut easy)).unwrap();
        println!("Request Name : {:?}", name);

        Ok(())
    }

    fn call_get_cert_pem_from_hash() -> Result<(), curl::Error>{
        let mut easy = initialize_curl_call();
        let url = format!("{}{}{}{}", LISTENING_URL, "cert/", "pem/", TEST_HASH);
        easy.url(&url);

        let pem = String::from_utf8(get_curl_data(&mut easy)).unwrap();
        println!("Cert Pem : {:?}", pem);
        Ok(())
    }

    fn call_get_cert_der_from_hash() -> Result<(), curl::Error>{
        let mut easy = initialize_curl_call();
        let url = format!("{}{}{}{}", LISTENING_URL, "cert/", "der/", TEST_HASH);
        easy.url(&url);

        let der = get_curl_data(&mut easy);
        println!("Cert Der : {:?}", der);

        Ok(())
    }

    fn call_rest_api(){
        assert_eq!(call_get_chain(), Ok(()));
        assert_eq!(call_sign_cert(), Ok(()));
        assert_eq!(call_request_name(), Ok(()));
        assert_eq!(call_get_cert_pem_from_hash(), Ok(()));
        assert_eq!(call_get_cert_der_from_hash(), Ok(()));
    }

    #[test]
    fn filebase_server_test(){
        set_env("file");
        let server_thread = thread::spawn(||{
            run_server();
        });

        sleep(Duration::new(5,0));

        call_rest_api();

        server_thread.join().unwrap();
    }

    #[test]
    fn memory_server_test(){
        set_env("memory");
        let server_thread = thread::spawn(||{
            run_server();
        });

        sleep(Duration::new(5,0));

        call_rest_api();

        server_thread.join().unwrap();
    }

    #[test]
    fn mongodb_server_test(){
        set_env("mongodb");
        set_var(PICKY_DATABASE_URL_ENV, "mongodb://127.0.0.1:27017");
        let server_thread = thread::spawn(||{
            run_server();
        });

        sleep(Duration::new(5,0));

        call_rest_api();

        server_thread.join().unwrap();
    }
}