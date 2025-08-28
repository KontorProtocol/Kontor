use stdlib::Wavey;
pub struct ArithReturn {
    pub value: u64,
}
impl ArithReturn {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::record([("value", wasm_wave::value::Type::U64)]).unwrap()
    }
}
#[automatically_derived]
impl From<ArithReturn> for wasm_wave::value::Value {
    fn from(value_: ArithReturn) -> Self {
        wasm_wave::value::Value::make_record(
                &ArithReturn::wave_type(),
                [("value", wasm_wave::value::Value::from(value_.value))],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<wasm_wave::value::Value> for ArithReturn {
    fn from(value_: wasm_wave::value::Value) -> Self {
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
