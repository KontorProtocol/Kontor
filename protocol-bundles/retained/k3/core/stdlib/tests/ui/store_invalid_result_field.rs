use stdlib::Store;

#[derive(Store)]
struct Test {
    res: anyhow::Result<u64>,
}

#[derive(Store)]
struct Test1 {
    res: Result<u64, Error>,
}
