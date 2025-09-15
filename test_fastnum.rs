// Test what fastnum types are available
use fastnum::*;

fn main() {
    // Try to use I256
    // let signed: I256 = I256::from(42);
    
    // Try U256
    let unsigned: U256 = U256::from(42u64);
    println!("U256: {:?}", unsigned);
    
    // Check what's in bint module
    use fastnum::bint::*;
}
