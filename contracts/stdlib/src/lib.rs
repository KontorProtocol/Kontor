wasmtime::component::bindgen!({
    path: "wit/stdlib.wit",
    with: {
        "kontor:contract/stdlib/monoid": MyMonoidHostRep,
    },
    async: true,
    trappable_imports: true,
});

mod monoid;

pub use kontor::contract::stdlib::*;
pub use monoid::MyMonoidHostRep;
