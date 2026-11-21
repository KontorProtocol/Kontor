use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use metrics::counter;
use tokio::sync::oneshot;
use tokio::time::{MissedTickBehavior, interval};

use super::exposition::{gauge, normalize};
use crate::stopper::ShutdownSignal;

type Source = Arc<dyn Fn() -> Result<String, &'static str> + Send + Sync>;

thread_local! {
    static COLLECTING: Cell<bool> = const { Cell::new(false) };
}

/// The process panic hook must leave caught diagnostic panics out of supervision.
pub fn collection_panicking() -> bool {
    COLLECTING.get()
}

#[derive(Default)]
struct State {
    epoch: u64,
    source: Option<(Source, Arc<AtomicBool>)>,
    sample: Option<(Instant, Arc<str>)>,
    busy: bool,
}

#[derive(Clone, Default)]
pub(crate) struct EngineMetrics(Arc<Mutex<State>>);

/// Revoked before engine stop, and on every control-thread exit.
pub(crate) struct Registration {
    cache: EngineMetrics,
    epoch: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.cache.clear(self.epoch);
    }
}

impl EngineMetrics {
    pub(crate) fn install(&self, source: Source, stopped: Arc<AtomicBool>) -> Registration {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.epoch = state.epoch.checked_add(1).expect("metrics epoch exhausted");
        state.source = Some((source, stopped));
        state.sample = None;
        Registration {
            cache: self.clone(),
            epoch: state.epoch,
        }
    }

    fn clear(&self, epoch: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.epoch == epoch {
            state.source = None;
            state.sample = None;
        }
    }

    pub(crate) fn invalidate(&self) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.source = None;
        state.sample = None;
    }

    // Busy is released by the worker, not its async waiter. Cancellation and
    // generation changes therefore cannot start a second blocked exporter.
    fn start_collection(&self) -> Option<oneshot::Receiver<()>> {
        let (epoch, source) = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.busy {
                return None;
            }
            let (source, stopped) = state.source.clone()?;
            if stopped.load(Ordering::Acquire) {
                return None;
            }
            state.busy = true;
            (state.epoch, source)
        };
        let cache = self.clone();
        let (finished, result) = oneshot::channel();
        // A stuck diagnostic must not hold Tokio runtime shutdown open. This
        // detached worker owns only registry data; busy stays set until it exits.
        if thread::Builder::new()
            .name("consensus-metrics".into())
            .spawn(move || {
                COLLECTING.set(true);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    source().and_then(|text| normalize(&text))
                }))
                .unwrap_or(Err("panic"));
                COLLECTING.set(false);
                if result.is_err() {
                    counter!("kontor_observation_errors_total", "source" => "engine").increment(1);
                }
                let mut state = cache.0.lock().unwrap_or_else(|e| e.into_inner());
                state.busy = false;
                if state.epoch == epoch
                    && state
                        .source
                        .as_ref()
                        .is_some_and(|(_, stop)| !stop.load(Ordering::Acquire))
                {
                    state.sample = result.ok().map(|text| (Instant::now(), Arc::from(text)));
                }
                let _ = finished.send(());
            })
            .is_err()
        {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.busy = false;
            state.sample = None;
            counter!("kontor_observation_errors_total", "source" => "engine").increment(1);
            return None;
        }
        Some(result)
    }

    pub(crate) async fn run(&self, shutdown: ShutdownSignal) {
        let mut tick = interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => { self.invalidate(); return; }
                _ = tick.tick() => {
                    if let Some(mut job) = self.start_collection() {
                        tokio::select! {
                            _ = shutdown.cancelled() => { self.invalidate(); return; }
                            _ = &mut job => {}
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn render(&self, output: &mut String) {
        let sample = {
            let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state
                .source
                .as_ref()
                .filter(|(_, stop)| !stop.load(Ordering::Acquire))
                .and(state.sample.clone())
        };
        gauge(
            output,
            "kontor_engine_metrics_available",
            "A sample from the current managed engine is available.",
            u8::from(sample.is_some()),
        );
        if let Some((at, text)) = sample {
            gauge(
                output,
                "kontor_engine_metrics_age_seconds",
                "Age of the current engine sample, in seconds.",
                at.elapsed().as_secs_f64(),
            );
            output.push_str(&text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stopper::Shutdown;
    use std::sync::mpsc;
    use tokio::time::timeout;

    fn raw(value: u64) -> String {
        format!(
            "# HELP malachitebft_core_consensus_height Current height.\n# TYPE malachitebft_core_consensus_height gauge\nmalachitebft_core_consensus_height {value}\n# EOF\n"
        )
    }

    fn rendered(cache: &EngineMetrics) -> String {
        let mut output = String::new();
        cache.render(&mut output);
        output
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_a_blocked_export() {
        let cache = EngineMetrics::default();
        let (entered, started) = oneshot::channel();
        let entered = Mutex::new(Some(entered));
        let (release, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        let _registration = cache.install(
            Arc::new(move || {
                entered.lock().unwrap().take().unwrap().send(()).unwrap();
                wait.lock().unwrap().recv().unwrap();
                Ok(raw(1))
            }),
            Arc::new(AtomicBool::new(false)),
        );
        let shutdown = Shutdown::new();
        let signal = shutdown.signal();
        let collector = cache.clone();
        let task = tokio::spawn(async move { collector.run(signal).await });
        started.await.unwrap();
        shutdown.cancel();
        let result = timeout(Duration::from_secs(2), task).await;
        // Release even on timeout so this regression cannot leave a held worker.
        release.send(()).unwrap();
        result.unwrap().unwrap();
        assert!(rendered(&cache).contains("kontor_engine_metrics_available 0\n"));
    }

    #[tokio::test]
    async fn cancelled_waiter_and_generation_change_cannot_multiply_collection() {
        let cache = EngineMetrics::default();
        let (entered, started) = oneshot::channel();
        let entered = Mutex::new(Some(entered));
        let (release, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        let stopped = Arc::new(AtomicBool::new(false));
        let first = cache.install(
            Arc::new(move || {
                entered.lock().unwrap().take().unwrap().send(()).unwrap();
                wait.lock().unwrap().recv().unwrap();
                Ok(raw(1))
            }),
            stopped.clone(),
        );
        let waiter = cache.start_collection().unwrap();
        started.await.unwrap();
        drop(waiter);
        stopped.store(true, Ordering::Release);
        let second = cache.install(Arc::new(|| Ok(raw(2))), Arc::new(AtomicBool::new(false)));
        drop(first);
        for _ in 0..100 {
            assert!(cache.start_collection().is_none());
            assert!(rendered(&cache).contains("kontor_engine_metrics_available 0\n"));
        }
        release.send(()).unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                if let Some(next) = cache.start_collection() {
                    next.await.unwrap();
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let output = rendered(&cache);
        assert!(output.contains("malachitebft_core_consensus_height 2\n"));
        assert!(!output.contains("malachitebft_core_consensus_height 1\n"));
        drop(second);
        assert!(!rendered(&cache).contains("# HELP malachitebft"));
    }

    #[tokio::test]
    async fn errors_panics_and_invalid_exports_drop_only_the_sample() {
        let cache = EngineMetrics::default();
        let sources: Vec<Source> = vec![
            Arc::new(|| Err("test error")),
            Arc::new(|| {
                assert!(collection_panicking());
                panic!("test collection panic")
            }),
            Arc::new(|| Ok("x".repeat(1024 * 1024 + 1))),
            Arc::new(|| Ok("not metrics".into())),
        ];
        for source in sources {
            let _registration = cache.install(source, Arc::new(AtomicBool::new(false)));
            cache.start_collection().unwrap().await.unwrap();
            assert!(rendered(&cache).contains("kontor_engine_metrics_available 0\n"));
            assert!(!collection_panicking());
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let _registration = cache.install(Arc::new(|| Ok(raw(42))), stopped.clone());
        cache.start_collection().unwrap().await.unwrap();
        assert!(rendered(&cache).contains("malachitebft_core_consensus_height 42\n"));
        stopped.store(true, Ordering::Release);
        assert!(!rendered(&cache).contains("# HELP malachitebft"));
    }
}
