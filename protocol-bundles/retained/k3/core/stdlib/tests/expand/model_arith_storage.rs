extern crate alloc;

use stdlib::Model;

#[derive(Model)]
struct ArithStorage {
    pub last_op: Option<Op>,
}

#[derive(Clone, stdlib::Model)]
enum Op {
    Id,
}
