use stdlib::Storage;

// An index named `keys` collides with the field model's own `keys()` accessor. An
// inherent method wins over the generated trait method by name resolution, so the
// index would be silently unreachable — the derive must reject the name.
#[derive(Clone, Storage)]
#[index(keys, by = active)]
struct Bad {
    active: bool,
}

fn main() {}
