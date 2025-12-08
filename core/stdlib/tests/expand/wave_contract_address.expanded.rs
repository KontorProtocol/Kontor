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
        let mut record = stdlib::wasm_wave::wasm::WasmValue::unwrap_record(&value_)
            .collect::<std::collections::BTreeMap<_, _>>();
        ContractAddress {
            name: stdlib::from_wave_value(
                record
                    .remove("name")
                    .expect(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Missing \'{0}\' field", "name"),
                            )
                        }),
                    )
                    .into_owned(),
            ),
            height: stdlib::from_wave_value(
                record
                    .remove("height")
                    .expect(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Missing \'{0}\' field", "height"),
                            )
                        }),
                    )
                    .into_owned(),
            ),
            tx_index: stdlib::from_wave_value(
                record
                    .remove("tx-index")
                    .expect(
                        &::alloc::__export::must_use({
                            ::alloc::fmt::format(
                                format_args!("Missing \'{0}\' field", "tx-index"),
                            )
                        }),
                    )
                    .into_owned(),
            ),
        }
    }
}
#[automatically_derived]
impl From<ContractAddress> for stdlib::wasm_wave::value::Value {
    fn from(value_: ContractAddress) -> Self {
        <stdlib::wasm_wave::value::Value as stdlib::wasm_wave::wasm::WasmValue>::make_record(
                &stdlib::wave_type::<ContractAddress>(),
                [
                    ("name", stdlib::wasm_wave::value::Value::from(value_.name)),
                    ("height", stdlib::wasm_wave::value::Value::from(value_.height)),
                    ("tx-index", stdlib::wasm_wave::value::Value::from(value_.tx_index)),
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
