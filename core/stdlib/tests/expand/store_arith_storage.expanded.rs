pub struct ArithStorage {
    pub last_op: Option<Op>,
}
#[automatically_derived]
impl stdlib::Store for ArithStorage {
    fn __set(
        ctx: &impl stdlib::WriteContext,
        base_path: stdlib::DotPathBuf,
        value: ArithStorage,
    ) {
        match value.last_op {
            Some(inner) => ctx.__set(base_path.push("last_op"), inner),
            None => ctx.__set(base_path.push("last_op"), ()),
        }
    }
}
