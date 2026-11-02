use stdlib::Storage;

// A field listed twice in `include` is a copy-paste slip — rejected.
#[derive(Clone, Storage)]
#[index(by_owner, by = owner, include = (name, name))]
struct Nft {
    owner: u64,
    name: String,
}

fn main() {}
