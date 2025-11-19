use criterion::{Criterion, black_box, criterion_group, criterion_main};
use indexer::reactor::types::Inst;
use indexer::runtime::ContractAddress;
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

    c.bench_function("bcs serialize WitnessData", |b| {
        b.iter(|| {
            let bytes = bcs::to_bytes(black_box(&payload)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("postcard serialize WitnessData", |b| {
        b.iter(|| {
            let bytes = postcard::to_allocvec(black_box(&payload)).unwrap();
            black_box(bytes)
        })
    });
}

fn bench_deserialize(c: &mut Criterion) {
    let payload = sample_payload();
    let bytes_cbor4ii = cbor4ii::serde::to_vec(Vec::new(), &payload).unwrap();
    let bytes_dagcbor = serde_ipld_dagcbor::to_vec(&payload).unwrap();
    let bytes_bcs = bcs::to_bytes(&payload).unwrap();
    let bytes_postcard = postcard::to_allocvec(&payload).unwrap();

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

    c.bench_function("bcs deserialize WitnessData", |b| {
        b.iter(|| {
            let value: WitnessData = bcs::from_bytes(black_box(&bytes_bcs)).unwrap();
            black_box(value)
        })
    });

    c.bench_function("postcard deserialize WitnessData", |b| {
        b.iter(|| {
            let value: WitnessData = postcard::from_bytes(black_box(&bytes_postcard)).unwrap();
            black_box(value)
        })
    });
}

fn sample_inst_call() -> Inst {
    Inst::Call {
        gas_limit: 500_000,
        contract: ContractAddress {
            name: "dex:amm".to_string(),
            height: 12345,
            tx_index: 7,
        },
        expr: "(swap (token A) (token B) 1000)".to_string(),
    }
}

fn bench_inst_serialize(c: &mut Criterion) {
    let value = sample_inst_call();

    c.bench_function("inst cbor4ii serialize", |b| {
        b.iter(|| {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), black_box(&value)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("inst dag-cbor serialize", |b| {
        b.iter(|| {
            let bytes = serde_ipld_dagcbor::to_vec(black_box(&value)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("inst bcs serialize", |b| {
        b.iter(|| {
            let bytes = bcs::to_bytes(black_box(&value)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("inst postcard serialize", |b| {
        b.iter(|| {
            let bytes = postcard::to_allocvec(black_box(&value)).unwrap();
            black_box(bytes)
        })
    });
}

fn bench_inst_deserialize(c: &mut Criterion) {
    let value = sample_inst_call();
    let c4 = cbor4ii::serde::to_vec(Vec::new(), &value).unwrap();
    let dag = serde_ipld_dagcbor::to_vec(&value).unwrap();
    let b = bcs::to_bytes(&value).unwrap();
    let pc = postcard::to_allocvec(&value).unwrap();

    c.bench_function("inst cbor4ii deserialize", |bch| {
        bch.iter(|| {
            let v: Inst = cbor4ii::serde::from_slice(black_box(&c4)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst dag-cbor deserialize", |bch| {
        bch.iter(|| {
            let v: Inst = serde_ipld_dagcbor::from_slice(black_box(&dag)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst bcs deserialize", |bch| {
        bch.iter(|| {
            let v: Inst = bcs::from_bytes(black_box(&b)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst postcard deserialize", |bch| {
        bch.iter(|| {
            let v: Inst = postcard::from_bytes(black_box(&pc)).unwrap();
            black_box(v)
        })
    });
}

fn bench_inst_determinism_stress(c: &mut Criterion) {
    // Build the same Inst via different code paths; bytes must match per library
    let a = Inst::Call {
        gas_limit: 500_000,
        contract: ContractAddress {
            name: ["dex", ":", "amm"].concat(),
            height: 12345_i64,
            tx_index: 7_i64,
        },
        expr: format!("({} {} {} {})", "swap", "(token A)", "(token B)", 1000),
    };
    let b = sample_inst_call(); // semantically identical

    c.bench_function("inst determinism stress", |bch| {
        bch.iter(|| {
            let c4_a = cbor4ii::serde::to_vec(Vec::new(), black_box(&a)).unwrap();
            let c4_b = cbor4ii::serde::to_vec(Vec::new(), black_box(&b)).unwrap();
            assert_eq!(c4_a, c4_b, "cbor4ii should be deterministic for Inst");

            let dag_a = serde_ipld_dagcbor::to_vec(black_box(&a)).unwrap();
            let dag_b = serde_ipld_dagcbor::to_vec(black_box(&b)).unwrap();
            assert_eq!(dag_a, dag_b, "dag-cbor should be deterministic for Inst");

            let bcs_a = bcs::to_bytes(black_box(&a)).unwrap();
            let bcs_b = bcs::to_bytes(black_box(&b)).unwrap();
            assert_eq!(bcs_a, bcs_b, "bcs should be deterministic for Inst");

            let pc_a = postcard::to_allocvec(black_box(&a)).unwrap();
            let pc_b = postcard::to_allocvec(black_box(&b)).unwrap();
            assert_eq!(pc_a, pc_b, "postcard should be deterministic for Inst");

            black_box(())
        })
    });
}

fn sample_inst_publish_with_bytes(len: usize) -> Inst {
    let mut bytes_via_push = Vec::with_capacity(len);
    for i in 0..len {
        bytes_via_push.push((i % 251) as u8);
    }
    Inst::Publish {
        gas_limit: 750_000,
        name: "artifact".to_string(),
        bytes: bytes_via_push,
    }
}

fn sample_inst_publish_alt(len: usize) -> Inst {
    // Build bytes via a different constructor path to try to shake out determinism bugs
    let bytes_slice: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    Inst::Publish {
        gas_limit: 750_000,
        name: ["arti", "fact"].concat(),
        bytes: bytes_slice,
    }
}

fn sample_inst_issuance() -> Inst {
    Inst::Issuance
}

fn bench_inst_publish_sizes_serialize(c: &mut Criterion) {
    let small = sample_inst_publish_with_bytes(64);
    let mid = sample_inst_publish_with_bytes(1024);
    let big = sample_inst_publish_with_bytes(16 * 1024);

    c.bench_function("inst publish 64B serialize", |b| {
        b.iter(|| {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), black_box(&small)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 1KB serialize", |b| {
        b.iter(|| {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), black_box(&mid)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 16KB serialize", |b| {
        b.iter(|| {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), black_box(&big)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("inst publish 64B serialize dag-cbor", |b| {
        b.iter(|| {
            let bytes = serde_ipld_dagcbor::to_vec(black_box(&small)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 1KB serialize dag-cbor", |b| {
        b.iter(|| {
            let bytes = serde_ipld_dagcbor::to_vec(black_box(&mid)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 16KB serialize dag-cbor", |b| {
        b.iter(|| {
            let bytes = serde_ipld_dagcbor::to_vec(black_box(&big)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("inst publish 64B serialize bcs", |b| {
        b.iter(|| {
            let bytes = bcs::to_bytes(black_box(&small)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 1KB serialize bcs", |b| {
        b.iter(|| {
            let bytes = bcs::to_bytes(black_box(&mid)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 16KB serialize bcs", |b| {
        b.iter(|| {
            let bytes = bcs::to_bytes(black_box(&big)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("inst publish 64B serialize postcard", |b| {
        b.iter(|| {
            let bytes = postcard::to_allocvec(black_box(&small)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 1KB serialize postcard", |b| {
        b.iter(|| {
            let bytes = postcard::to_allocvec(black_box(&mid)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst publish 16KB serialize postcard", |b| {
        b.iter(|| {
            let bytes = postcard::to_allocvec(black_box(&big)).unwrap();
            black_box(bytes)
        })
    });
}

fn bench_inst_publish_sizes_deserialize(c: &mut Criterion) {
    let small = sample_inst_publish_with_bytes(64);
    let mid = sample_inst_publish_with_bytes(1024);
    let big = sample_inst_publish_with_bytes(16 * 1024);

    let c4_small = cbor4ii::serde::to_vec(Vec::new(), &small).unwrap();
    let c4_mid = cbor4ii::serde::to_vec(Vec::new(), &mid).unwrap();
    let c4_big = cbor4ii::serde::to_vec(Vec::new(), &big).unwrap();
    let dag_small = serde_ipld_dagcbor::to_vec(&small).unwrap();
    let dag_mid = serde_ipld_dagcbor::to_vec(&mid).unwrap();
    let dag_big = serde_ipld_dagcbor::to_vec(&big).unwrap();
    let b_small = bcs::to_bytes(&small).unwrap();
    let b_mid = bcs::to_bytes(&mid).unwrap();
    let b_big = bcs::to_bytes(&big).unwrap();
    let pc_small = postcard::to_allocvec(&small).unwrap();
    let pc_mid = postcard::to_allocvec(&mid).unwrap();
    let pc_big = postcard::to_allocvec(&big).unwrap();

    c.bench_function("inst publish 64B deserialize cbor4ii", |bch| {
        bch.iter(|| {
            let v: Inst = cbor4ii::serde::from_slice(black_box(&c4_small)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 1KB deserialize cbor4ii", |bch| {
        bch.iter(|| {
            let v: Inst = cbor4ii::serde::from_slice(black_box(&c4_mid)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 16KB deserialize cbor4ii", |bch| {
        bch.iter(|| {
            let v: Inst = cbor4ii::serde::from_slice(black_box(&c4_big)).unwrap();
            black_box(v)
        })
    });

    c.bench_function("inst publish 64B deserialize dag-cbor", |bch| {
        bch.iter(|| {
            let v: Inst = serde_ipld_dagcbor::from_slice(black_box(&dag_small)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 1KB deserialize dag-cbor", |bch| {
        bch.iter(|| {
            let v: Inst = serde_ipld_dagcbor::from_slice(black_box(&dag_mid)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 16KB deserialize dag-cbor", |bch| {
        bch.iter(|| {
            let v: Inst = serde_ipld_dagcbor::from_slice(black_box(&dag_big)).unwrap();
            black_box(v)
        })
    });

    c.bench_function("inst publish 64B deserialize bcs", |bch| {
        bch.iter(|| {
            let v: Inst = bcs::from_bytes(black_box(&b_small)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 1KB deserialize bcs", |bch| {
        bch.iter(|| {
            let v: Inst = bcs::from_bytes(black_box(&b_mid)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 16KB deserialize bcs", |bch| {
        bch.iter(|| {
            let v: Inst = bcs::from_bytes(black_box(&b_big)).unwrap();
            black_box(v)
        })
    });

    c.bench_function("inst publish 64B deserialize postcard", |bch| {
        bch.iter(|| {
            let v: Inst = postcard::from_bytes(black_box(&pc_small)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 1KB deserialize postcard", |bch| {
        bch.iter(|| {
            let v: Inst = postcard::from_bytes(black_box(&pc_mid)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst publish 16KB deserialize postcard", |bch| {
        bch.iter(|| {
            let v: Inst = postcard::from_bytes(black_box(&pc_big)).unwrap();
            black_box(v)
        })
    });
}

fn bench_inst_publish_determinism(c: &mut Criterion) {
    let a = sample_inst_publish_with_bytes(1024);
    let b = sample_inst_publish_alt(1024); // identical content via different construction

    c.bench_function("inst publish determinism", |bch| {
        bch.iter(|| {
            let c4_a = cbor4ii::serde::to_vec(Vec::new(), black_box(&a)).unwrap();
            let c4_b = cbor4ii::serde::to_vec(Vec::new(), black_box(&b)).unwrap();
            assert_eq!(
                c4_a, c4_b,
                "cbor4ii should be deterministic for Inst::Publish"
            );

            let dag_a = serde_ipld_dagcbor::to_vec(black_box(&a)).unwrap();
            let dag_b = serde_ipld_dagcbor::to_vec(black_box(&b)).unwrap();
            assert_eq!(
                dag_a, dag_b,
                "dag-cbor should be deterministic for Inst::Publish"
            );

            let bcs_a = bcs::to_bytes(black_box(&a)).unwrap();
            let bcs_b = bcs::to_bytes(black_box(&b)).unwrap();
            assert_eq!(
                bcs_a, bcs_b,
                "bcs should be deterministic for Inst::Publish"
            );

            let pc_a = postcard::to_allocvec(black_box(&a)).unwrap();
            let pc_b = postcard::to_allocvec(black_box(&b)).unwrap();
            assert_eq!(
                pc_a, pc_b,
                "postcard should be deterministic for Inst::Publish"
            );

            black_box(())
        })
    });
}

fn bench_inst_issuance(c: &mut Criterion) {
    let value = sample_inst_issuance();
    let c4 = cbor4ii::serde::to_vec(Vec::new(), &value).unwrap();
    let dag = serde_ipld_dagcbor::to_vec(&value).unwrap();
    let b = bcs::to_bytes(&value).unwrap();
    let pc = postcard::to_allocvec(&value).unwrap();

    c.bench_function("inst issuance serialize", |bch| {
        bch.iter(|| {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), black_box(&value)).unwrap();
            black_box(bytes)
        })
    });
    c.bench_function("inst issuance deserialize cbor4ii", |bch| {
        bch.iter(|| {
            let v: Inst = cbor4ii::serde::from_slice(black_box(&c4)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst issuance deserialize dag-cbor", |bch| {
        bch.iter(|| {
            let v: Inst = serde_ipld_dagcbor::from_slice(black_box(&dag)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst issuance deserialize bcs", |bch| {
        bch.iter(|| {
            let v: Inst = bcs::from_bytes(black_box(&b)).unwrap();
            black_box(v)
        })
    });
    c.bench_function("inst issuance deserialize postcard", |bch| {
        bch.iter(|| {
            let v: Inst = postcard::from_bytes(black_box(&pc)).unwrap();
            black_box(v)
        })
    });
}
criterion_group!(
    benches,
    bench_serialize,
    bench_deserialize,
    bench_inst_serialize,
    bench_inst_deserialize,
    bench_inst_determinism_stress,
    bench_inst_publish_sizes_serialize,
    bench_inst_publish_sizes_deserialize,
    bench_inst_publish_determinism,
    bench_inst_issuance
);
criterion_main!(benches);
