use stdlib::Store;

#[derive(Store)]
enum Error {
    Message(String),
}
