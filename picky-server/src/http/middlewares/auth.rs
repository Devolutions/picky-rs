use saphir::{Middleware, SyncRequest, SyncResponse, RequestContinuation, StatusCode, header};
use crate::configuration::ServerConfig;

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
                error!("Authorization header is missing");
                res.status(StatusCode::UNAUTHORIZED);
                return RequestContinuation::Stop;
            }
        };

        let auth_str = match header.to_str() {
            Ok(s) => s,
            Err(_e) => {
                error!("Authorization header can't be converted in string");
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
        error!("Authorization header wrong format: {}", auth_str);
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

    error!("Wrong authorization method or api_key: {}", auth_str);
    res.status(StatusCode::UNAUTHORIZED);
    RequestContinuation::Stop
}
