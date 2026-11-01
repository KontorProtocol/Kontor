use stdlib::Store;

#[derive(Store)]
enum Test {
    Var(Result<u64, Error>),
}

#[derive(Store)]
enum Test1 {
    Var(anyhow::Result<u64>),
}
