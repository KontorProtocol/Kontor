use stdlib::Wavey;
pub struct Operand {
    pub y: u64,
}
impl Operand {
    pub fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::record([
                ("y", stdlib::wasm_wave::value::Type::U64),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl From<Operand> for stdlib::wasm_wave::value::Value {
    fn from(value_: Operand) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &Operand::wave_type(),
                [("y", stdlib::wasm_wave::value::Value::from(value_.y))],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for Operand {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        let mut y = None;
        for (key_, val_) in stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_) {
            match key_.as_ref() {
                "y" => {
                    y = Some(
                        stdlib::wasm_wave::wasm::WasmValue::unwrap_u64(
                            &val_.into_owned(),
                        ),
                    );
                }
                key_ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unknown field: {0}", key_),
                    );
                }
            }
        }
        Operand {
            y: y
                .expect(
                    &::alloc::__export::must_use({
                        ::alloc::fmt::format(format_args!("Missing \'{0}\' field", "y"))
                    }),
                ),
        }
    }
}
