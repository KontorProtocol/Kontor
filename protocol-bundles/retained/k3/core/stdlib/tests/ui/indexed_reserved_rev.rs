use stdlib::Storage;

#[derive(Clone, Storage)]
#[index(rev, by = active)]
struct Bad {
    active: bool,
}

fn main() {}
