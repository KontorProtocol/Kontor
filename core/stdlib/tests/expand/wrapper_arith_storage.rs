use stdlib::Wrapper;

#[derive(Wrapper)]
struct ArithStorage {
    pub last_op: Option<Op>,
}
