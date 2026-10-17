extern crate alloc;

use stdlib::Model;

#[derive(Model)]
enum Error {
    Message(String),
}
