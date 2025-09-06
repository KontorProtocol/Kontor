use stdlib::Wavey;
enum Error {
    Message(String),
}
impl Error {
    pub fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::variant([
                ("message", Some(stdlib::wasm_wave::value::Type::STRING)),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl From<Error> for stdlib::wasm_wave::value::Value {
    fn from(value_: Error) -> Self {
        (match value_ {
            Error::Message(operand) => {
                <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_variant(
                    &Error::wave_type(),
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
        let (key_, val_) = stdlib::wasm_wave::wasm::WasmValue::unwrap_variant(&value_);
        match key_ {
            key_ if key_.eq("message") => {
                Error::Message(
                    stdlib::wasm_wave::wasm::WasmValue::unwrap_string(
                            &val_.unwrap().into_owned(),
                        )
                        .into_owned(),
                )
            }
            key_ => {
                ::core::panicking::panic_fmt(format_args!("Unknown tag {0}", key_));
            }
        }
    }
}
