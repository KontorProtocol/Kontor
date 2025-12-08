use stdlib::Wavey;
enum Error {
    Message(String),
}
#[automatically_derived]
impl stdlib::WaveType for Error {
    fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::variant([
                ("message", Some(stdlib::wave_type::<String>())),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl stdlib::FromWaveValue for Error {
    fn from_wave_value(value_: stdlib::wasm_wave::value::Value) -> Self {
        let (key_, val_) = stdlib::wasm_wave::wasm::WasmValue::unwrap_variant(&value_);
        match key_ {
            key_ if key_.eq("message") => {
                Error::Message(stdlib::from_wave_value(val_.unwrap().into_owned()))
            }
            key_ => {
                ::core::panicking::panic_fmt(format_args!("Unknown tag {0}", key_));
            }
        }
    }
}
#[automatically_derived]
impl From<Error> for stdlib::wasm_wave::value::Value {
    fn from(value_: Error) -> Self {
        (match value_ {
            Error::Message(operand) => {
                <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_variant(
                    &stdlib::wave_type::<Error>(),
                    "message",
                    Some(stdlib::wasm_wave::value::Value::from(operand)),
                )
            }
        })
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for Error {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        stdlib::from_wave_value(value_)
    }
}
