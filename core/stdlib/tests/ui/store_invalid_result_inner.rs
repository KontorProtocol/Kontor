use stdlib::Store;

#[derive(Store)]
enum Test {
    Var(Result<u64, std::io::Error>),
}

#[derive(Store)]
enum Test1 {
    Var(Result<u64, std::io::Error>),
}
