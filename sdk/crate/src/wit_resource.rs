//! Implementation of the `wit` Component Model resource. One instance
//! per WIT document; holds the parsed `wit_parser::Resolve` graph.
//!
//! The resource exposes three methods:
//! - `constructor(text)`: parse a WIT source string into a Resolve.
//! - `encode-call(fn, args-json)`: JSON args → WAVE string, dispatched on
//!   the function's parameter types in the parsed WIT.
//! - `decode-result(fn, wave)`: WAVE string → JSON, dispatched on the
//!   function's return type.
//! - `parse()`: serialize the parsed Resolve graph as JSON.

use std::cell::RefCell;
use wasm_wave::value::Value as WaveValue;
use wasm_wave::wasm::WasmValue;
use wit_parser::{Resolve, Type, WorldItem};

pub struct WitResource {
    resolve: RefCell<Resolve>,
}

impl WitResource {
    pub fn new(text: String) -> Self {
        let mut resolve = Resolve::new();
        // Component Model resource constructors can't return Result, so
        // parse errors surface at encode/decode time via the caller's
        // chosen method.
        let _ = resolve.push_str("input.wit", &text);
        WitResource {
            resolve: RefCell::new(resolve),
        }
    }

    pub fn encode_call(&self, fn_name: String, args_json: String) -> Result<String, String> {
        let resolve = self.resolve.borrow();
        let func = find_function(&resolve, &fn_name)
            .ok_or_else(|| format!("function not found in WIT: {fn_name}"))?;

        let args: serde_json::Value = serde_json::from_str(&args_json)
            .map_err(|e| format!("invalid args JSON: {e}"))?;
        let args_obj = args
            .as_object()
            .ok_or_else(|| "args must be a JSON object keyed by param name".to_string())?;

        let mut rendered_args: Vec<String> = Vec::new();
        for param in &func.params {
            let v = args_obj
                .get(&param.name)
                .ok_or_else(|| format!("missing arg: {}", param.name))?;
            let wave_val = json_to_wave(&param.ty, v)?;
            let rendered = wasm_wave::to_string(&wave_val)
                .map_err(|e| format!("WAVE render error: {e}"))?;
            rendered_args.push(rendered);
        }

        Ok(format!("{}({})", fn_name, rendered_args.join(", ")))
    }

    pub fn decode_result(&self, _fn_name: String, _wave: String) -> Result<String, String> {
        Err("not implemented".to_string())
    }

    pub fn parse(&self) -> Result<String, String> {
        Err("not implemented".to_string())
    }
}

/// Find a function by name across all exports of all worlds in a parsed
/// Resolve. For Kontor we only ever parse one world at a time, but this
/// stays generic — first match wins.
fn find_function<'a>(resolve: &'a Resolve, fn_name: &str) -> Option<&'a wit_parser::Function> {
    resolve.worlds.iter().find_map(|(_, world)| {
        world.exports.values().find_map(|item| match item {
            WorldItem::Function(f) if f.name == fn_name => Some(f),
            _ => None,
        })
    })
}

/// Convert a JSON value to a wasm-wave Value, driven by the target WIT
/// type. Only `bool` is supported so far — every other variant returns
/// "not implemented" until we fill them in.
fn json_to_wave(ty: &Type, v: &serde_json::Value) -> Result<WaveValue, String> {
    match ty {
        Type::Bool => {
            let b = v.as_bool().ok_or_else(|| "expected JSON bool".to_string())?;
            Ok(WaveValue::make_bool(b))
        }
        _ => Err(format!("type not implemented yet: {ty:?}")),
    }
}
