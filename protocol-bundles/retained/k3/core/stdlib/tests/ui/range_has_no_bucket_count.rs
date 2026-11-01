use stdlib::{KeyRange, ReadStorage};

fn count<S: ReadStorage + 'static>(range: KeyRange<String, S>) -> u64 {
    range.len()
}

fn main() {}
