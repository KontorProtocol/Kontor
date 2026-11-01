extern crate alloc;

#[derive(stdlib::Store)]
pub struct ArithStorage {
    pub last_op: Option<Op>,
}

#[derive(Clone, stdlib::Model)]
enum Op {
    Id,
}
