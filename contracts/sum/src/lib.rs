macros::contract!(name = "sum");

impl Guest for Sum {
    fn sum(x: u64, y: u64) -> u64 {
        x + y
    }
}

export!(Sum);
