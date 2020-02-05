use criterion::{criterion_group, criterion_main, Criterion};
use futures::future::join_all;

const GET_CHAIN_ROUTE: &str = "http://127.0.0.1:12345/chain";

fn bench_requests(amount: usize, concurrency: usize) {
    let mut rt = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .core_threads(concurrency)
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    let mut futs = Vec::with_capacity(amount);
    for _ in 0..amount {
        futs.push(reqwest::get(GET_CHAIN_ROUTE));
    }

    rt.block_on(async { join_all(futs).await });
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("get chain low concurrency", |b| b.iter(|| bench_requests(20, 1)));
    c.bench_function("get chain medium concurrency", |b| b.iter(|| bench_requests(20, 10)));
    c.bench_function("get chain high concurrency", |b| b.iter(|| bench_requests(20, 20)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
