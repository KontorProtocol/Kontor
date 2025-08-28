use stdlib::Wavey;
pub enum Op {
    Id,
    Sum(Operand),
    Mul(Operand),
    Div(Operand),
}
impl Op {
    pub fn wave_type() -> stdlib::wasm_wave::value::Type {
        stdlib::wasm_wave::value::Type::variant([
                ("id", None),
                ("sum", Some(Operand::wave_type())),
                ("mul", Some(Operand::wave_type())),
                ("div", Some(Operand::wave_type())),
            ])
            .unwrap()
    }
}
#[automatically_derived]
impl From<Op> for stdlib::wasm_wave::value::Value {
    fn from(value_: Op) -> Self {
        (match value_ {
            Op::Id => {
                stdlib::wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "id",
                    None,
                )
            }
            Op::Sum(operand) => {
                stdlib::wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "sum",
                    Some(stdlib::wasm_wave::value::Value::from(operand)),
                )
            }
            Op::Mul(operand) => {
                stdlib::wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "mul",
                    Some(stdlib::wasm_wave::value::Value::from(operand)),
                )
            }
            Op::Div(operand) => {
                stdlib::wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "div",
                    Some(stdlib::wasm_wave::value::Value::from(operand)),
                )
            }
        })
            .unwrap()
    }
}
#[automatically_derived]
impl From<stdlib::wasm_wave::value::Value> for Op {
    fn from(value_: stdlib::wasm_wave::value::Value) -> Self {
        let (key_, val_) = value_.unwrap_variant();
        match key_ {
            key_ if key_.eq("id") => Op::Id,
            key_ if key_.eq("sum") => Op::Sum(val_.unwrap().into_owned().into()),
            key_ if key_.eq("mul") => Op::Mul(val_.unwrap().into_owned().into()),
            key_ if key_.eq("div") => Op::Div(val_.unwrap().into_owned().into()),
            key_ => {
                ::core::panicking::panic_fmt(format_args!("Unknown tag {0}", key_));
            }
        }
    }
}
