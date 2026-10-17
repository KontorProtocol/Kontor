extern crate alloc;

use stdlib::Storage;

mod error {
    pub type Error = String;
}

#[derive(Storage)]
struct Challenge {
    id: String,
    #[index]
    status: u64,
    #[index]
    prover_id: u64,
    seed: u64,
}
