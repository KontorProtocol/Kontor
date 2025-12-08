use stdlib::Wavey;
pub struct ArithReturn {
    pub value: u64,
}
#[automatically_derived]
impl stdlib::WaveType for ArithReturn {
    fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::record([("value", stdlib::wave_type::<u64>())])
            .unwrap()
    }
}
#[automatically_derived]
impl stdlib::FromWaveValue for ArithReturn {
    fn from_wave_value(value_: stdlib::wasm_wave::value::Value) -> Self {
        let mut record = stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_)
            .collect::<std::collections::BTreeMap<_, _>>();
        ArithReturn {
            value: stdlib::from_wave_value(
                record
                    .remove("value")
                    .expect(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Missing \'{0}\' field", "value"),
                            )
                        }),
                    )
                    .into_owned(),
            ),
        }
    }
}
#[automatically_derived]
impl From<ArithReturn> for stdlib::wasm_wave::value::Value {
    fn from(value_: ArithReturn) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &stdlib::wave_type::<ArithReturn>(),
                [("value", stdlib::wasm_wave::value::Value::from(value_.value))],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for ArithReturn {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        stdlib::from_wave_value(value_)
    }
}
