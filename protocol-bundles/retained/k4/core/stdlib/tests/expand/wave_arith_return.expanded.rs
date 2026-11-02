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
        let mut value = None;
        for (key_, val_) in stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_) {
            match key_.as_ref() {
                "value" => value = Some(val_.into_owned()),
                key_ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unknown field: {0}", key_),
                    );
                }
            }
        }
        ArithReturn {
            value: stdlib::from_wave_value(value.unwrap()),
        }
    }
}
#[automatically_derived]
impl stdlib::IntoWaveValue for ArithReturn {
    fn into_wave_value(self) -> stdlib::wasm_wave::value::Value {
        self.into()
    }
}
#[automatically_derived]
impl From<ArithReturn> for stdlib::wasm_wave::value::Value {
    fn from(value_: ArithReturn) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &stdlib::wave_type::<ArithReturn>(),
                [("value", stdlib::IntoWaveValue::into_wave_value(value_.value))],
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
