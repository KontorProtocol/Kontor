// The shared data interfaces have no functions. Adapt their empty registration
// helpers to our linker instead of exposing its mutable, unmetered inner linker.
macro_rules! facade {
    ($name:ident, $source:ident, $instance:literal) => {
        pub mod $name {
            pub use built_in_types::$source::*;
            use wasmtime::Result;

            use crate::runtime::lowering::{Linker, LinkerInstance};

            pub fn add_to_linker<T: 'static, D>(
                linker: &mut Linker<T>,
                host_getter: fn(&mut T) -> D::Data<'_>,
            ) -> Result<()>
            where
                D: HostWithStore<T>,
                for<'a> D::Data<'a>: Host,
            {
                add_to_linker_instance::<T, D>(&mut linker.instance($instance)?, host_getter)
            }

            pub fn add_to_linker_instance<T: 'static, D>(
                _instance: &mut LinkerInstance<'_, T>,
                _host_getter: fn(&mut T) -> D::Data<'_>,
            ) -> Result<()>
            where
                D: HostWithStore<T>,
                for<'a> D::Data<'a>: Host,
            {
                Ok(())
            }
        }
    };
}

facade!(
    file_registry_types,
    host_facade,
    "kontor:built-in/file-registry-types"
);
facade!(
    numbers_types,
    host_facade_numbers_types,
    "kontor:built-in/numbers-types"
);
facade!(error, host_facade_error, "kontor:built-in/error");
facade!(
    context_types,
    host_facade_context_types,
    "kontor:built-in/context-types"
);

facade!(
    pagination,
    host_facade_pagination,
    "kontor:built-in/pagination"
);
