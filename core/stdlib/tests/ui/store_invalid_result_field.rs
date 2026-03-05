use stdlib::Store;

#[derive(Store)]
struct Test {
    res: Result<u64, std::io::Error>,
}

#[derive(Store)]
struct Test1 {
    res: Result<u64, std::io::Error>,
}
