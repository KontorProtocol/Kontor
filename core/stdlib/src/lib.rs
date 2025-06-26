wasmtime::component::bindgen!({
    path: "wit/stdlib.wit",
    with: {
        "kontor:contract/stdlib/monoid": MyMonoidHostRep,
        "kontor:contract/stdlib/foreign": ForeignHostRep,
    },
    async: true,
    trappable_imports: true,
});

mod foreign;
mod monoid;

pub use foreign::ForeignHostRep;
pub use foreign::default_val_for_type;
pub use kontor::contract::stdlib::*;
pub use monoid::MyMonoidHostRep;
