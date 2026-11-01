extern crate alloc;
use stdlib::Storage;

mod error {
    pub type Error = String;
}

#[derive(Clone, PartialEq, Eq, Storage)]
struct Payload {
    number: u64,
}
impl Payload {
    const ONE: Self = Self { number: 1 };
}

#[derive(Clone, PartialEq, Eq, Storage)]
enum State {
    Value(Payload),
}

impl State {
    const ONE: Self = Self::Value(Payload::ONE);
}

#[derive(Storage)]
#[index(live, by = owner, when = matches!(payload, Payload::ONE))]
struct Direct {
    owner: u64,
    payload: Payload,
}

#[derive(Storage)]
#[index(live, by = owner, when = matches!(state, State::Value(Payload::ONE)))]
struct Wrapped {
    owner: u64,
    state: State,
}

#[derive(Storage)]
#[index(live, by = owner, when = matches!(payload, Option::Some(Payload::ONE)))]
struct Optional {
    owner: u64,
    payload: Option<Payload>,
}

#[derive(Storage)]
#[index(live, by = owner, when = matches!(state, State::ONE))]
struct EnumConstant {
    owner: u64,
    state: State,
}

fn main() {}
