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
use wasm_wave::value::resolve_wit_func_type;
use wasm_wave::wasm::{WasmFunc, WasmTypeKind, WasmValue};
use wit_parser::{Resolve, Type, WorldItem};

use serde::ser::{Serialize, Serializer};

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

    pub fn decode_result(&self, fn_name: String, wave: String) -> Result<String, String> {
        let resolve = self.resolve.borrow();
        let func = find_function(&resolve, &fn_name)
            .ok_or_else(|| format!("function not found in WIT: {fn_name}"))?;

        let func_type = resolve_wit_func_type(&resolve, func)
            .map_err(|e| format!("could not resolve function type: {e}"))?;
        let result_type = func_type
            .results()
            .next()
            .ok_or_else(|| "function has no return type".to_string())?;

        let value: WaveValue = wasm_wave::from_str(&result_type, &wave)
            .map_err(|e| format!("WAVE parse error: {e}"))?;

        serde_json::to_string(&WaveValueRepr(&value))
            .map_err(|e| format!("JSON serialize error: {e}"))
    }

    pub fn parse(&self) -> Result<String, String> {
        Err("not implemented".to_string())
    }
}

/// Find a function by name across all exports of all worlds in a parsed
/// Resolve. First match wins.
fn find_function<'a>(resolve: &'a Resolve, fn_name: &str) -> Option<&'a wit_parser::Function> {
    resolve.worlds.iter().find_map(|(_, world)| {
        world.exports.values().find_map(|item| match item {
            WorldItem::Function(f) if f.name == fn_name => Some(f),
            _ => None,
        })
    })
}

/// Convert a JSON value to a wasm-wave Value, driven by the target WIT
/// type. Big ints (u64/s64/u128/s128) accept JSON strings holding decimal
/// digits — JS `Number` can't safely hold integers above 2^53.
fn json_to_wave(ty: &Type, v: &serde_json::Value) -> Result<WaveValue, String> {
    match ty {
        Type::Bool => {
            let b = v.as_bool().ok_or_else(|| "expected JSON bool".to_string())?;
            Ok(WaveValue::make_bool(b))
        }
        Type::U64 => {
            let s = v
                .as_str()
                .ok_or_else(|| "expected JSON string holding a u64 decimal".to_string())?;
            let n: u64 = s
                .parse()
                .map_err(|e| format!("invalid u64 string '{s}': {e}"))?;
            Ok(WaveValue::make_u64(n))
        }
        _ => Err(format!("type not implemented yet: {ty:?}")),
    }
}

/// Newtype wrapper enabling `Serialize` for `wasm_wave::value::Value` via
/// the orphan-rule (Value isn't ours, Serialize isn't ours). Dispatches
/// on `WasmTypeKind`. Big ints serialize as JSON strings (quoted decimal)
/// since JS `Number` can't safely hold values above 2^53; round-trips
/// with `json_to_wave`'s big-int branch.
struct WaveValueRepr<'a>(&'a WaveValue);

impl<'a> Serialize for WaveValueRepr<'a> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0.kind() {
            WasmTypeKind::Bool => ser.serialize_bool(self.0.unwrap_bool()),
            WasmTypeKind::U64 => ser.serialize_str(&self.0.unwrap_u64().to_string()),
            kind => Err(serde::ser::Error::custom(format!(
                "WaveValueRepr: kind not implemented yet: {kind:?}"
            ))),
        }
    }
}
