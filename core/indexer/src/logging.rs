use std::panic;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt::try_init();
        panic::set_hook(Box::new(|panic_info| {
            let message = panic_info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| {
                    panic_info
                        .payload()
                        .downcast_ref::<String>()
                        .map(|s| s.as_str())
                })
                .unwrap_or("Unknown panic");
            let location = panic_info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown location".to_string());
            tracing::error!(target: "panic", "Panic at {}: {}", location, message);
        }));
    });
}
