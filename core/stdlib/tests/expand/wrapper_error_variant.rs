use stdlib::Wrapper;

#[derive(Wrapper)]
enum Error {
    Message(String),
}
