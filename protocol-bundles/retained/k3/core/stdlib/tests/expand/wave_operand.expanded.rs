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
        let mut y = None;
        for (key_, val_) in stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_) {
            match key_.as_ref() {
                "y" => y = Some(val_.into_owned()),
                key_ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unknown field: {0}", key_),
                    );
                }
            }
        }
        Operand {
            y: stdlib::from_wave_value(y.unwrap()),
        }
    }
}
#[automatically_derived]
impl stdlib::IntoWaveValue for Operand {
    fn into_wave_value(self) -> stdlib::wasm_wave::value::Value {
        self.into()
    }
}
#[automatically_derived]
impl From<Operand> for stdlib::wasm_wave::value::Value {
    fn from(value_: Operand) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &stdlib::wave_type::<Operand>(),
                [("y", stdlib::IntoWaveValue::into_wave_value(value_.y))],
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
