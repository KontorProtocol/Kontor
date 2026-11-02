use std::env;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

fn main() {
    let expected = fs::read(env::args().nth(1).expect("expected pristine output file")).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let mut threads = Vec::new();
    for index in 0..4 {
        let expected = expected.clone();
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            // Race first-use CPU initialization in both independent libraries.
            barrier.wait();
            for _ in 0..100 {
                let (first, second) = if index % 2 == 0 {
                    (crypto_first::exercise(), crypto_second::exercise())
                } else {
                    (crypto_second::exercise(), crypto_first::exercise())
                };
                assert_eq!(first, expected);
                assert_eq!(second, expected);
                assert_eq!(crypto_node::exercise(), expected);
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    println!(
        "Node and both independent crypto graphs matched pristine outputs in 1200 concurrent exercises"
    );
}
