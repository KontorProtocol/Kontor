extern crate alloc;

use stdlib::Store;

#[derive(Store)]
enum Error {
    Message(String),
    Overflow,
}
