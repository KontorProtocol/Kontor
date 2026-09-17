use std::borrow::Cow;
use std::cell::Cell;
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

use anyhow::Result;
use wasmtime::component::{
    Type, Val,
    wasm_wave::{
        wasm::{WasmTypeKind, WasmValue},
        writer::Writer,
    },
};

use super::Output;

#[test]
fn failed_output_charge_is_independent_of_write_boundaries() {
    for limit in 0..9 {
        for pieces in [
            vec!["éabcdefg"],
            vec!["é", "ab", "cdefg"],
            vec!["é", "a", "b", "c", "d", "e", "f", "g"],
        ] {
            let mut output = Output::new(limit);
            for piece in pieces {
                if output.write_str(piece).is_err() {
                    break;
                }
            }
            assert!(output.exhausted);
            assert_eq!(output.charged_bytes, limit);
            assert!(output.value.len() as u64 <= limit);
        }
    }
}

#[derive(Clone)]
struct CountedList<'a> {
    visited: &'a Cell<usize>,
    element: bool,
}

impl WasmValue for CountedList<'_> {
    type Type = Type;

    fn kind(&self) -> WasmTypeKind {
        if self.element {
            WasmTypeKind::U8
        } else {
            WasmTypeKind::List
        }
    }

    fn unwrap_u8(&self) -> u8 {
        0
    }

    fn unwrap_list(&self) -> Box<dyn Iterator<Item = Cow<'_, Self>> + '_> {
        Box::new((0..10_000).map(|_| {
            self.visited.set(self.visited.get() + 1);
            Cow::Owned(Self {
                visited: self.visited,
                element: true,
            })
        }))
    }
}

#[test]
fn wave_writer_stops_visiting_list_elements_at_the_budget() {
    let visited = Cell::new(0);
    let value = CountedList {
        visited: &visited,
        element: false,
    };
    let mut output = Output::new(8);
    assert!(Writer::new(&mut output).write_value(&value).is_err());
    assert!(output.exhausted);
    assert_eq!(output.charged_bytes, 8);
    assert!(visited.get() <= 4, "visited {} values", visited.get());
}

#[test]
fn fallback_moves_the_existing_string() -> Result<()> {
    let value = "some(\"value\")".to_string();
    let ptr = value.as_ptr();
    let mut output = Output::new(value.len() as u64);
    output.take_raw(value)?;
    assert_eq!(output.value.as_ptr(), ptr);
    assert_eq!(output.value, "some(\"value\")");
    Ok(())
}

#[test]
#[ignore = "manual WAVE output overhead comparison"]
fn encoding_overhead() -> Result<()> {
    for value in [
        Val::U64(42),
        Val::String("é\n".repeat(4096)),
        Val::List(vec![Val::U8(255); 4096]),
    ] {
        let expected = value.to_wave()?;
        let start = Instant::now();
        for _ in 0..1000 {
            black_box(value.to_wave()?);
        }
        let original = start.elapsed();
        let start = Instant::now();
        for _ in 0..1000 {
            let mut output = Output::new(expected.len() as u64);
            Writer::new(&mut output).write_value(black_box(&value))?;
            assert_eq!(output.value.len(), expected.len());
            black_box(output.value);
        }
        println!(
            "bytes={} original={original:?} bounded={:?}",
            expected.len(),
            start.elapsed()
        );
    }
    Ok(())
}
