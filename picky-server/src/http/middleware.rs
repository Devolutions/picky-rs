use saphir::http::header::HeaderValue;
use saphir::prelude::*;

pub async fn log_middleware(ctx: HttpContext, chain: &dyn MiddlewareChain) -> Result<HttpContext, SaphirError> {
    let req = ctx.state.request().unwrap(); // should not panic because this is before the chain.next(..) call
    let uri = req.uri().path().to_owned();
    let method = req.method().to_owned();

    let ctx = chain.next(ctx).await?;

    let res = ctx.state.response().unwrap(); // should not panic because this is after the chain.next(..) call
    log::info!("{} {} {}", method, uri, res.status());

    Ok(ctx)
}

pub async fn cors_middleware(ctx: HttpContext, chain: &dyn MiddlewareChain) -> Result<HttpContext, SaphirError> {
    let req = ctx.state.request().unwrap(); // should not panic because this is before chain.next(..) call
    let origin_header = req.headers().get("Origin").cloned();

    let mut ctx = chain.next(ctx).await?;

    if let Some(origin_header) = origin_header {
        let res = ctx.state.response_mut().unwrap(); // should not panic because this is after chain.next(..) call
        res.headers_mut().insert("Access-Control-Allow-Origin", origin_header);
        res.headers_mut()
            .insert("Access-Control-Max-Age", HeaderValue::from_static("7200"));
    }

    Ok(ctx)
}
