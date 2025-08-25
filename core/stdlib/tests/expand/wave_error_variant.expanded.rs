use stdlib::Wavey;
enum Error {
    Message(String),
}
impl Error {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::variant([
                ("message", Some(wasm_wave::value::Type::STRING)),
            ])
            .unwrap()
    }
}
impl From<Error> for wasm_wave::value::Value {
    fn from(value_: Error) -> Self {
        (match value_ {
            Error::Message(operand) => {
                wasm_wave::value::Value::make_variant(
                    &Error::wave_type(),
                    "message",
                    Some(wasm_wave::value::Value::from(operand)),
                )
            }
        })
            .unwrap()
    }
}
impl From<wasm_wave::value::Value> for Error {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let (key_, val_) = value_.unwrap_variant();
        match key_ {
            key_ if key_.eq("message") => {
                Error::Message(val_.unwrap().unwrap_string().into_owned())
            }
            key_ => {
                ::core::panicking::panic_fmt(format_args!("Unknown tag {0}", key_));
            }
        }
    }
}
