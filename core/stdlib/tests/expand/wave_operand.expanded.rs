use stdlib::Wavey;
pub struct Operand {
    pub y: u64,
}
impl Operand {
    pub fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::record([("y", wasm_wave::value::Type::U64)]).unwrap()
    }
}
#[automatically_derived]
impl From<Operand> for wasm_wave::value::Value {
    fn from(value_: Operand) -> Self {
        wasm_wave::value::Value::make_record(
                &Operand::wave_type(),
                [("y", wasm_wave::value::Value::from(value_.y))],
            )
            .unwrap()
    }
}
#[automatically_derived]
impl From<wasm_wave::value::Value> for Operand {
    fn from(value_: wasm_wave::value::Value) -> Self {
        let mut y = None;
        for (key_, val_) in value_.unwrap_record() {
            match key_.as_ref() {
                "y" => y = Some(val_.unwrap_u64()),
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
