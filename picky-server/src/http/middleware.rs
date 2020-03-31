use saphir::prelude::*;

pub async fn log_middleware(
    _: &(),
    ctx: HttpContext<Body>,
    chain: &dyn MiddlewareChain,
) -> Result<Response<Body>, SaphirError> {
    let uri = ctx.request.uri().path().to_owned();
    let method = ctx.request.method().to_owned();
    let res = chain.next(ctx).await?;
    log::info!("{} {} {}", method, uri, res.status());
    Ok(res)
}

pub async fn cors_middleware(
    _: &(),
    ctx: HttpContext<Body>,
    chain: &dyn MiddlewareChain,
) -> Result<Response<Body>, SaphirError> {
    let origin_header = ctx.request.headers().get("Origin").cloned();

    let mut response: Response<Body> = chain.next(ctx).await?;

    if let Some(origin_header) = origin_header {
        response
            .headers_mut()
            .insert("Access-Control-Allow-Origin", origin_header);
    }

    Ok(response)
}
