use stdlib::Wavey;
pub struct Operand {
    pub y: u64,
}
#[automatically_derived]
impl stdlib::WaveType for Operand {
    fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::record([("y", stdlib::wave_type::<u64>())])
            .unwrap()
    }
}
#[automatically_derived]
impl stdlib::FromWaveValue for Operand {
    fn from_wave_value(value_: stdlib::wasm_wave::value::Value) -> Self {
        let mut record = stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_)
            .collect::<std::collections::BTreeMap<_, _>>();
        Operand {
            y: stdlib::from_wave_value(
                record
                    .remove("y")
                    .expect(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Missing \'{0}\' field", "y"),
                            )
                        }),
                    )
                    .into_owned(),
            ),
        }
    }
}
#[automatically_derived]
impl From<Operand> for stdlib::wasm_wave::value::Value {
    fn from(value_: Operand) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &stdlib::wave_type::<Operand>(),
                [("y", stdlib::wasm_wave::value::Value::from(value_.y))],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for Operand {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        stdlib::from_wave_value(value_)
    }
}
