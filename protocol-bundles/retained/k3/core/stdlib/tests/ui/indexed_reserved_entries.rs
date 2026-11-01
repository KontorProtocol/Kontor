extern crate alloc;
use stdlib::Storage;

#[derive(Clone, Storage)]
#[index(entries, by = value)]
struct Record { value: u64 }

fn main() {}
