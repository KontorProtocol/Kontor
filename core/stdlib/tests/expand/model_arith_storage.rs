use stdlib::Model;

#[derive(Model)]
struct ArithStorage {
    pub last_op: Option<Op>,
}
