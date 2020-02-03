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
