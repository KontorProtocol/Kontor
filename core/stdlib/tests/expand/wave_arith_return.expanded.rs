use stdlib::Wavey;
pub struct ArithReturn {
    pub value: u64,
}
impl ArithReturn {
    pub fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::record([
                ("value", stdlib::wasm_wave::value::Type::U64),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl From<ArithReturn> for stdlib::wasm_wave::value::Value {
    fn from(value_: ArithReturn) -> Self {
        stdlib::wasm_wave::value::Value::make_record(
                &ArithReturn::wave_type(),
                [("value", stdlib::wasm_wave::value::Value::from(value_.value))],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for ArithReturn {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        let mut value = None;
        for (key_, val_) in value_.unwrap_record() {
            match key_.as_ref() {
                "value" => value = Some(val_.unwrap_u64()),
                key_ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unknown field: {0}", key_),
                    );
                }
            }
        }
        ArithReturn {
            value: value
                .expect(
                    &::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!("Missing \'{0}\' field", "value"),
                        )
                    }),
                ),
        }
    }
}
