use stdlib::Storage;

// `include` must name real fields of the struct.
#[derive(Clone, Storage)]
#[index(by_owner, by = owner, include = (nonexistent))]
struct Nft {
    owner: u64,
    name: String,
}

fn main() {}
