use stdlib::Wavey;
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}
#[automatically_derived]
impl stdlib::WaveType for ContractAddress {
    fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::record([
                ("name", stdlib::wave_type::<String>()),
                ("height", stdlib::wave_type::<i64>()),
                ("tx-index", stdlib::wave_type::<i64>()),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl stdlib::FromWaveValue for ContractAddress {
    fn from_wave_value(value_: stdlib::wasm_wave::value::Value) -> Self {
        let mut name = None;
        let mut height = None;
        let mut tx_index = None;
        for (key_, val_) in stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_) {
            match key_.as_ref() {
                "name" => name = Some(val_.into_owned()),
                "height" => height = Some(val_.into_owned()),
                "tx-index" => tx_index = Some(val_.into_owned()),
                key_ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unknown field: {0}", key_),
                    );
                }
            }
        }
        ContractAddress {
            name: stdlib::from_wave_value(name.unwrap()),
            height: stdlib::from_wave_value(height.unwrap()),
            tx_index: stdlib::from_wave_value(tx_index.unwrap()),
        }
    }
}
#[automatically_derived]
impl stdlib::IntoWaveValue for ContractAddress {
    fn into_wave_value(self) -> stdlib::wasm_wave::value::Value {
        self.into()
    }
}
#[automatically_derived]
impl From<ContractAddress> for stdlib::wasm_wave::value::Value {
    fn from(value_: ContractAddress) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &stdlib::wave_type::<ContractAddress>(),
                [
                    ("name", stdlib::IntoWaveValue::into_wave_value(value_.name)),
                    ("height", stdlib::IntoWaveValue::into_wave_value(value_.height)),
                    ("tx-index", stdlib::IntoWaveValue::into_wave_value(value_.tx_index)),
                ],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for ContractAddress {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        stdlib::from_wave_value(value_)
    }
}
