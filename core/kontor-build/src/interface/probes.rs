use super::Probe;
pub const PROBES: &[Probe] = &[
    Probe {
        name: "structural-factories",
        expected: None,
        source: r#"use first::Factory as First;
use second::Factory as Second;
pub fn first_into_second(value: First) -> Second { value }
pub fn second_into_first(value: Second) -> First { value }
"#,
    },
    Probe {
        name: "wasmtime-engine",
        expected: Some("E0308"),
        source: r#"use first_wasmtime::Engine as First;
use second_wasmtime::Engine as Second;
pub fn cross_graph(value: First) -> Second { value }
"#,
    },
    Probe {
        name: "tokio-handle",
        expected: Some("E0308"),
        source: r#"use first_tokio::runtime::Handle as First;
use second_tokio::runtime::Handle as Second;
pub fn cross_graph(value: First) -> Second { value }
"#,
    },
    Probe {
        name: "first-private-runtime",
        expected: Some("E0603"),
        source: r#"use first::runtime::Runtime;
pub fn unselected_runtime(value: Runtime) { drop(value); }
"#,
    },
    Probe {
        name: "second-private-runtime",
        expected: Some("E0603"),
        source: r#"use second::runtime::Runtime;
pub fn unselected_runtime(value: Runtime) { drop(value); }
"#,
    },
];
pub const ADAPTED: &[Probe] = &[
    Probe {
        name: "structural-factories",
        expected: Some("E0308"),
        source: r#"use first::Factory as First;
use second::Factory as Second;
pub fn first_into_second(value: First) -> Second { value }
pub fn second_into_first(value: Second) -> First { value }
"#,
    },
    Probe {
        name: "wasmtime-engine",
        expected: Some("E0308"),
        source: r#"use first_wasmtime::Engine as First;
use second_wasmtime::Engine as Second;
pub fn cross_graph(value: First) -> Second { value }
"#,
    },
    Probe {
        name: "tokio-handle",
        expected: Some("E0308"),
        source: r#"use first_tokio::runtime::Handle as First;
use second_tokio::runtime::Handle as Second;
pub fn cross_graph(value: First) -> Second { value }
"#,
    },
    Probe {
        name: "first-private-runtime",
        expected: Some("E0603"),
        source: r#"use first::runtime::Runtime;
pub fn unselected_runtime(value: Runtime) { drop(value); }
"#,
    },
    Probe {
        name: "second-private-runtime",
        expected: Some("E0603"),
        source: r#"use second::runtime::Runtime;
pub fn unselected_runtime(value: Runtime) { drop(value); }
"#,
    },
    Probe {
        name: "adapted-factories",
        expected: None,
        source: r#"use first::Factory as First;
use second::Factory as Second;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
type MigrationFuture = Pin<Box<dyn Future<Output = Result<
    Result<[u64; 5], (u8, Option<[u64; 5]>)>,
    (u8, String, Option<[u64; 5]>)>> + Send>>;
pub fn first_into_second(value: First) -> Second {
    Arc::new(move |storage, network, limit| {
        let pending = value(storage, network, limit);
        Box::pin(async move {
            let ((a, b, c, d, e, f, g, h, i, j, migration), owner, roots, release) = pending.await?;
            let migration: Arc<dyn Fn(_, _, _, _) -> MigrationFuture + Send + Sync> = Arc::new(move |owner, selection, definition, input| {
                let pending = migration(owner, selection, definition, input);
                Box::pin(async move {
                    pending.await.map(|result| result.map_err(|tag| (tag, None)))
                        .map_err(|(tag, message)| (tag, message, None))
                }) as MigrationFuture
            });
            Ok(((a, b, c, d, e, f, g, h, i, j, migration), owner, roots, release))
        })
    })
}
"#,
    },
];
pub const CONSENSUS: &[Probe] = &[
    Probe {
        name: "typed-runtime",
        expected: None,
        source: r#"use first::api::{EnginePoll, Response};
use first::Engine;
use std::time::Duration;
pub fn drive(engine: &mut Engine) {
    if let Ok(EnginePoll::Event(event)) = engine.poll() {
        if let Some(token) = event.reply {
            let _ = engine.respond(token, Response::HistoryMinHeight(1));
        }
    }
    let _ = engine.request_stop();
    let _ = engine.wait_stopped(Duration::ZERO);
}
"#,
    },
    Probe {
        name: "private-consensus",
        expected: Some("E0603"),
        source: r#"use first::consensus::Ctx;
pub fn private_context(value: Ctx) { drop(value); }
"#,
    },
    Probe {
        name: "private-owner",
        expected: Some("E0603"),
        source: r#"use first::owner::Owner;
pub fn private_owner(value: Owner) { drop(value); }
"#,
    },
    Probe {
        name: "control-thread-owner",
        expected: Some("E0277"),
        source: r#"use first::Engine;
pub fn require_send<T: Send>() {}
pub fn move_owner() { require_send::<Engine>(); }
"#,
    },
];
pub const ADAPTER_TESTS: &[&str] = &[
    "managed::adapter::runtime::tests::height_parameters_preserve_committee_order_and_all_timeouts",
    "managed::adapter::runtime::tests::event_keeps_generation_rounds_and_canonical_payload",
    "managed::adapter::runtime::tests::local_failure_is_not_reclassified_as_a_peer_fault",
    "managed::adapter::tests::publication_rejection_returns_the_original_buffer_for_retry",
];
