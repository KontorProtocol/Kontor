wasmtime::component::bindgen!({
    world: "contract",
    path: "wit/stdlib.wit",
    with: {
        "kontor:contract/stdlib/monoid": MyMonoidHostRep,
    },
    trappable_imports: true,
});

mod monoid;

pub use kontor::contract::stdlib::*;
pub use monoid::MyMonoidHostRep;
