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

use wasm_wave::value::Value as WaveValue;
use wasm_wave::value::resolve_wit_type;
use wasm_wave::wasm::{WasmTypeKind, WasmValue};
use wit_parser::{Resolve, Type, WorldItem};
use wit_validator::Validator;

use serde::ser::{Serialize, Serializer};

/// Cached result of `Validator::validate_str` performed at construction.
/// Component Model resource constructors can't be fallible (WIT 0.2), so
/// we stash the outcome and short-circuit each method with the error if
/// the WIT didn't validate cleanly.
pub struct WitResource {
    parsed: Result<Resolve, String>,
}

impl WitResource {
    pub fn new(text: String) -> Self {
        let parsed = match Validator::validate_str(&text) {
            Ok((result, resolve)) => {
                if result.is_valid() {
                    Ok(resolve)
                } else {
                    let detail: Vec<String> = result
                        .errors
                        .into_iter()
                        .map(|e| {
                            let loc = if e.span.is_known() {
                                resolve.render_location(e.span)
                            } else {
                                "<unknown>".to_string()
                            };
                            format!("{}: {}", loc, e.message)
                        })
                        .collect();
                    Err(format!("WIT validation failed: {}", detail.join("; ")))
                }
            }
            Err(e) => Err(format!("WIT parse error: {}", e.message)),
        };
        WitResource { parsed }
    }

    fn resolve(&self) -> Result<&Resolve, String> {
        self.parsed.as_ref().map_err(|e| e.clone())
    }

    pub fn encode_call(&self, fn_name: String, args_json: String) -> Result<String, String> {
        let resolve = self.resolve()?;
        let func = find_function(resolve, &fn_name)
            .ok_or_else(|| format!("function not found in WIT: {fn_name}"))?;

        let args: serde_json::Value = serde_json::from_str(&args_json)
            .map_err(|e| format!("invalid args JSON: {e}"))?;
        let args_obj = args
            .as_object()
            .ok_or_else(|| "args must be a JSON object keyed by param name".to_string())?;

        // Kontor convention (enforced by wit_validator at construction):
        // every export's first param is a `borrow<context>` injected by
        // the host. WAVE expressions sent to the node only carry the
        // user's args, so we skip the first param when encoding.
        let user_params = func.params.get(1..).unwrap_or(&[]);

        let mut rendered_args: Vec<String> = Vec::new();
        for param in user_params {
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
        let resolve = self.resolve()?;
        let func = find_function(resolve, &fn_name)
            .ok_or_else(|| format!("function not found in WIT: {fn_name}"))?;

        // Resolve just the return type — `resolve_wit_func_type` walks the
        // full signature including `borrow<context>`, which wasm-wave's
        // bridge can't represent (and we don't need anyway since the
        // decode direction is value-only).
        let result_ty = func
            .result
            .as_ref()
            .ok_or_else(|| "function has no return type".to_string())?;
        let wave_ty = wit_type_to_wave_type(result_ty, resolve)?;

        let value: WaveValue = wasm_wave::from_str(&wave_ty, &wave)
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

/// Map a `wit_parser::Type` to a `wasm_wave::value::Type`. Primitives
/// have direct constants; user-defined types resolve via wasm-wave's
/// `resolve_wit_type` bridge using their TypeId.
fn wit_type_to_wave_type(
    ty: &Type,
    resolve: &Resolve,
) -> Result<wasm_wave::value::Type, String> {
    use wasm_wave::value::Type as WaveType;
    match ty {
        Type::Bool => Ok(WaveType::BOOL),
        Type::S8 => Ok(WaveType::S8),
        Type::S16 => Ok(WaveType::S16),
        Type::S32 => Ok(WaveType::S32),
        Type::S64 => Ok(WaveType::S64),
        Type::U8 => Ok(WaveType::U8),
        Type::U16 => Ok(WaveType::U16),
        Type::U32 => Ok(WaveType::U32),
        Type::U64 => Ok(WaveType::U64),
        Type::F32 => Ok(WaveType::F32),
        Type::F64 => Ok(WaveType::F64),
        Type::Char => Ok(WaveType::CHAR),
        Type::String => Ok(WaveType::STRING),
        Type::Id(type_id) => resolve_wit_type(resolve, *type_id)
            .map_err(|e| format!("could not resolve user-defined type: {e}")),
        other => Err(format!("unsupported wit type for codec: {other:?}")),
    }
}

/// Convert a JSON value to a wasm-wave Value, driven by the target WIT
/// type.
///
/// Bigint convention: u64 and s64 accept JSON strings of decimal digits —
/// JS `Number` can't safely hold integers above 2^53. Smaller integers
/// fit in `Number` and pass through as JSON numbers.
fn json_to_wave(ty: &Type, v: &serde_json::Value) -> Result<WaveValue, String> {
    fn as_int<T>(v: &serde_json::Value, ty_name: &str) -> Result<T, String>
    where
        T: TryFrom<i64>,
        <T as TryFrom<i64>>::Error: std::fmt::Display,
    {
        let n = v
            .as_i64()
            .ok_or_else(|| format!("expected JSON integer for {ty_name}"))?;
        T::try_from(n).map_err(|e| format!("{ty_name} out of range: {e}"))
    }
    fn as_uint<T>(v: &serde_json::Value, ty_name: &str) -> Result<T, String>
    where
        T: TryFrom<u64>,
        <T as TryFrom<u64>>::Error: std::fmt::Display,
    {
        let n = v
            .as_u64()
            .ok_or_else(|| format!("expected JSON non-negative integer for {ty_name}"))?;
        T::try_from(n).map_err(|e| format!("{ty_name} out of range: {e}"))
    }
    fn quoted_decimal<T>(v: &serde_json::Value, ty_name: &str) -> Result<T, String>
    where
        T: std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Display,
    {
        let s = v.as_str().ok_or_else(|| {
            format!("expected JSON string holding a {ty_name} decimal")
        })?;
        s.parse()
            .map_err(|e| format!("invalid {ty_name} string '{s}': {e}"))
    }

    match ty {
        Type::Bool => {
            let b = v.as_bool().ok_or_else(|| "expected JSON bool".to_string())?;
            Ok(WaveValue::make_bool(b))
        }
        Type::S8 => Ok(WaveValue::make_s8(as_int(v, "s8")?)),
        Type::S16 => Ok(WaveValue::make_s16(as_int(v, "s16")?)),
        Type::S32 => Ok(WaveValue::make_s32(as_int(v, "s32")?)),
        Type::S64 => Ok(WaveValue::make_s64(quoted_decimal(v, "s64")?)),
        Type::U8 => Ok(WaveValue::make_u8(as_uint(v, "u8")?)),
        Type::U16 => Ok(WaveValue::make_u16(as_uint(v, "u16")?)),
        Type::U32 => Ok(WaveValue::make_u32(as_uint(v, "u32")?)),
        Type::U64 => Ok(WaveValue::make_u64(quoted_decimal(v, "u64")?)),
        Type::F32 => {
            let n = v.as_f64().ok_or_else(|| "expected JSON number for f32".to_string())?;
            Ok(WaveValue::make_f32(n as f32))
        }
        Type::F64 => {
            let n = v.as_f64().ok_or_else(|| "expected JSON number for f64".to_string())?;
            Ok(WaveValue::make_f64(n))
        }
        Type::Char => {
            let s = v
                .as_str()
                .ok_or_else(|| "expected JSON 1-char string for char".to_string())?;
            let mut chars = s.chars();
            let c = chars
                .next()
                .ok_or_else(|| "char string is empty".to_string())?;
            if chars.next().is_some() {
                return Err(format!("char string has more than 1 char: {s:?}"));
            }
            Ok(WaveValue::make_char(c))
        }
        Type::String => {
            let s = v.as_str().ok_or_else(|| "expected JSON string".to_string())?;
            Ok(WaveValue::make_string(s.into()))
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
            WasmTypeKind::S8 => ser.serialize_i8(self.0.unwrap_s8()),
            WasmTypeKind::S16 => ser.serialize_i16(self.0.unwrap_s16()),
            WasmTypeKind::S32 => ser.serialize_i32(self.0.unwrap_s32()),
            WasmTypeKind::S64 => ser.serialize_str(&self.0.unwrap_s64().to_string()),
            WasmTypeKind::U8 => ser.serialize_u8(self.0.unwrap_u8()),
            WasmTypeKind::U16 => ser.serialize_u16(self.0.unwrap_u16()),
            WasmTypeKind::U32 => ser.serialize_u32(self.0.unwrap_u32()),
            WasmTypeKind::U64 => ser.serialize_str(&self.0.unwrap_u64().to_string()),
            WasmTypeKind::F32 => ser.serialize_f32(self.0.unwrap_f32()),
            WasmTypeKind::F64 => ser.serialize_f64(self.0.unwrap_f64()),
            WasmTypeKind::Char => ser.serialize_char(self.0.unwrap_char()),
            WasmTypeKind::String => ser.serialize_str(&self.0.unwrap_string()),
            kind => Err(serde::ser::Error::custom(format!(
                "WaveValueRepr: kind not implemented yet: {kind:?}"
            ))),
        }
    }
}
