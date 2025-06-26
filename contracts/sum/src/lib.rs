wit_bindgen::generate!({
  path: "wit/world.wit",
});

struct Contract;

impl Guest for Contract {
    fn sum(x: u64, y: u64) -> u64 {
        x + y
    }
}

export!(Contract);
