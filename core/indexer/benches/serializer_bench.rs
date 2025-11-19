use criterion::{Criterion, black_box, criterion_group, criterion_main};
use indexer::witness_data::{TokenBalance, WitnessData};

fn sample_payload() -> WitnessData {
    WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    }
}

fn bench_serialize(c: &mut Criterion) {
    let payload = sample_payload();

    c.bench_function("cbor4ii serialize WitnessData", |b| {
        b.iter(|| {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), black_box(&payload)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("dag-cbor serialize WitnessData", |b| {
        b.iter(|| {
            let bytes = serde_ipld_dagcbor::to_vec(black_box(&payload)).unwrap();
            black_box(bytes)
        })
    });
}

fn bench_deserialize(c: &mut Criterion) {
    let payload = sample_payload();
    let bytes_cbor4ii = cbor4ii::serde::to_vec(Vec::new(), &payload).unwrap();
    let bytes_dagcbor = serde_ipld_dagcbor::to_vec(&payload).unwrap();

    c.bench_function("cbor4ii deserialize WitnessData", |b| {
        b.iter(|| {
            let value: WitnessData = cbor4ii::serde::from_slice(black_box(&bytes_cbor4ii)).unwrap();
            black_box(value)
        })
    });

    c.bench_function("dag-cbor deserialize WitnessData", |b| {
        b.iter(|| {
            let value: WitnessData =
                serde_ipld_dagcbor::from_slice(black_box(&bytes_dagcbor)).unwrap();
            black_box(value)
        })
    });
}

criterion_group!(benches, bench_serialize, bench_deserialize);
criterion_main!(benches);
