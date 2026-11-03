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
