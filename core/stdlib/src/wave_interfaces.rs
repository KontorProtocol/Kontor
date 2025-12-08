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
