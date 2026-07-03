use stdlib::Storage;

// The sort field is already carried in the leaf for free — including it is rejected.
#[derive(Clone, Storage)]
#[index(cheapest, by = active, sort = price, include = (price, title))]
struct Listing {
    active: bool,
    price: u64,
    title: String,
}

fn main() {}
