wit_bindgen::generate!({
    world: "contract",
    path: "wit",
    generate_all,
});

struct Contract;

impl Guest for Contract {
    fn sum(x: u64, y: u64) -> u64 {
        test();
        x + y
    }
}

export!(Contract);
