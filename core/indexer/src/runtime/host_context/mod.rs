use crate::runtime::Runtime;
use crate::runtime::wit::kontor::built_in;

// WIT requires concrete signatures; the runtime operations behind them are generic.
macro_rules! storage_methods {
    ($state:ident, $resource:ty; $(
        fn $name:ident($($arg:ident: $arg_ty:ty),*) -> $ret:ty => $target:ident;
    )*) => {$(
        async fn $name(
            accessor: &Accessor<$state, Self>,
            self_: Resource<$resource>,
            $($arg: $arg_ty),*
        ) -> Result<$ret> {
            accessor
                .with(|mut access| access.get().clone())
                .$target(accessor, self_, $($arg),*)
                .await
        }
    )*};
}

mod contract;
mod core_context;
mod fall_context;
mod holder;
mod keys;
mod proc_context;
mod proc_storage;
mod runtime_ext;
mod signer;
mod storage_rows;
mod transaction;
mod view_context;
mod view_storage;

impl built_in::context::Host for Runtime {}
