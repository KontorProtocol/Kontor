macros::contract!(name = "sum");

impl Guest for Sum {
    fn sum(args: SumArgs) -> u64 {
        args.x + args.y
    }
}

export!(Sum);
