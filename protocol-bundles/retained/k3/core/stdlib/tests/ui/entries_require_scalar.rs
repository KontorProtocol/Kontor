use stdlib::{KeyRange, ReadStorage};

struct Record { value: u64 }

fn entries<S: ReadStorage + 'static>(range: KeyRange<String, S, Record>) {
    range.entries();
}

fn main() {}
