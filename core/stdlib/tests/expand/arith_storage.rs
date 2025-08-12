#[derive(stdlib::Store)]
pub struct ArithStorage {
    pub last_op: Option<Op>,
}
