use stdlib::Model;

#[derive(Model)]
enum Error {
    Message(String),
}
