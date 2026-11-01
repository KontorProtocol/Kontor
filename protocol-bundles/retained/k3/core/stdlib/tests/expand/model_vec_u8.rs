extern crate alloc;

use stdlib::Model;

mod error {
    pub type Error = String;
}

#[derive(Model)]
struct VecU8 {
    pub bytes: Vec<u8>,
    pub bytes_other: Vec::<u8>,
}
