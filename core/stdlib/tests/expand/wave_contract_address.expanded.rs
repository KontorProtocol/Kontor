use stdlib::Wavey;
pub struct ContractAddress {
    pub name: String,
    pub height: i64,
    pub tx_index: i64,
}
impl ContractAddress {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::record([
                ("name", wasm_wave::value::Type::STRING),
                ("height", wasm_wave::value::Type::S64),
                ("tx-index", wasm_wave::value::Type::S64),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl From<ContractAddress> for wasm_wave::value::Value {
    fn from(value_: ContractAddress) -> Self {
        wasm_wave::value::Value::make_record(
                &ContractAddress::wave_type(),
                [
                    ("name", wasm_wave::value::Value::from(value_.name)),
                    ("height", wasm_wave::value::Value::from(value_.height)),
                    ("tx-index", wasm_wave::value::Value::from(value_.tx_index)),
                ],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<wasm_wave::value::Value> for ContractAddress {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let mut name = None;
        let mut height = None;
        let mut tx_index = None;
        for (key_, val_) in value_.unwrap_record() {
            match key_.as_ref() {
                "name" => name = Some(val_.unwrap_string().into_owned()),
                "height" => height = Some(val_.unwrap_s64()),
                "tx-index" => tx_index = Some(val_.unwrap_s64()),
                key_ => {
                    ::core::panicking::panic_fmt(
                        format_args!("Unknown field: {0}", key_),
                    );
                }
            }
        }
        ContractAddress {
            name: name
                .expect(
                    &::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!("Missing \'{0}\' field", "name"),
                        )
                    }),
                ),
            height: height
                .expect(
                    &::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!("Missing \'{0}\' field", "height"),
                        )
                    }),
                ),
            tx_index: tx_index
                .expect(
                    &::alloc::__export::must_use({
                        ::alloc::fmt::format(
                            format_args!("Missing \'{0}\' field", "tx_index"),
                        )
                    }),
                ),
        }
    }
}
