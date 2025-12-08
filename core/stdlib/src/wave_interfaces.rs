pub trait WaveType {
    fn wave_type() -> wasm_wave::value::Type;
}

impl WaveType for u64 {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::U64
    }
}

impl WaveType for i64 {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::S64
    }
}

impl WaveType for bool {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::BOOL
    }
}

impl WaveType for String {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::STRING
    }
}

impl<T: WaveType> WaveType for Vec<T> {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::list(T::wave_type())
    }
}

impl<T: WaveType> WaveType for Option<T> {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::option(T::wave_type())
    }
}

impl<V: WaveType, E: WaveType> WaveType for Result<V, E> {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::result(Some(V::wave_type()), Some(E::wave_type()))
    }
}

impl<E: WaveType> WaveType for Result<(), E> {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::result(None, Some(E::wave_type()))
    }
}

impl<V: WaveType> WaveType for Result<V, ()> {
    fn wave_type() -> wasm_wave::value::Type {
        wasm_wave::value::Type::result(Some(V::wave_type()), None)
    }
}

pub fn wave_type<T: WaveType>() -> wasm_wave::value::Type {
    T::wave_type()
}

pub trait FromWaveValue {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self;
}

impl FromWaveValue for u64 {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        wasm_wave::wasm::WasmValue::unwrap_u64(&value)
    }
}

impl FromWaveValue for i64 {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        wasm_wave::wasm::WasmValue::unwrap_s64(&value)
    }
}

impl FromWaveValue for bool {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        wasm_wave::wasm::WasmValue::unwrap_bool(&value)
    }
}

impl FromWaveValue for String {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        wasm_wave::wasm::WasmValue::unwrap_string(&value).into_owned()
    }
}

impl<T: FromWaveValue> FromWaveValue for Vec<T> {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        wasm_wave::wasm::WasmValue::unwrap_list(&value)
            .map(|v| T::from_wave_value(v.into_owned()))
            .collect()
    }
}

impl<T: FromWaveValue> FromWaveValue for Option<T> {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        wasm_wave::wasm::WasmValue::unwrap_option(&value)
            .map(|v| T::from_wave_value(v.into_owned()))
    }
}

impl<V: FromWaveValue, E: FromWaveValue> FromWaveValue for Result<V, E> {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        match wasm_wave::wasm::WasmValue::unwrap_result(&value) {
            Ok(v) => Ok(V::from_wave_value(v.unwrap().into_owned())),
            Err(e) => Err(E::from_wave_value(e.unwrap().into_owned())),
        }
    }
}

impl<E: FromWaveValue> FromWaveValue for Result<(), E> {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        match wasm_wave::wasm::WasmValue::unwrap_result(&value) {
            Ok(_) => Ok(()),
            Err(e) => Err(E::from_wave_value(e.unwrap().into_owned())),
        }
    }
}

impl<V: FromWaveValue> FromWaveValue for Result<V, ()> {
    fn from_wave_value(value: wasm_wave::value::Value) -> Self {
        match wasm_wave::wasm::WasmValue::unwrap_result(&value) {
            Ok(v) => Ok(V::from_wave_value(v.unwrap().into_owned())),
            Err(_) => Err(()),
        }
    }
}

pub fn from_wave_value<T: FromWaveValue>(value: wasm_wave::value::Value) -> T {
    T::from_wave_value(value)
}

pub fn from_wave_expr<T: FromWaveValue + WaveType>(expr: &str) -> T {
    from_wave_value(
        wasm_wave::from_str::<wasm_wave::value::Value>(&wave_type::<T>(), expr)
            .expect("Failed to parse wave expression"),
    )
}

pub fn to_wave_expr<T: Into<wasm_wave::value::Value>>(value: T) -> String {
    wasm_wave::to_string(&value.into()).expect("Failed to format wave expression")
}
