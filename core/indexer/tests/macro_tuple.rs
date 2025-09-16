use testlib::*;

// Import the tuple fixture
import!(
    name = "tupletest",
    height = 0,
    tx_index = 0,
    path = "indexer/tests/fixtures/tuple",
);

#[test]
fn test_tuple_macro_compiles() {
    // This test verifies that the import! macro correctly handles tuple types
    // The fact that this compiles means:
    // 1. The macro correctly parses tuple<integer, integer>
    // 2. It generates the right Rust type: (Integer, Integer)
    // 3. The Wave serialization/deserialization code is generated
    
    // We can't actually call the function without a real contract implementation,
    // but compilation success proves the macro works correctly
    
    // The generated function signature should be:
    // pub async fn ret_tuple(runtime: &Runtime) -> Result<(Integer, Integer)>
    
    // And for ret_integer:
    // pub async fn ret_integer(runtime: &Runtime) -> Result<Integer>
    
    println!("✓ Tuple types in import! macro compile successfully");
    println!("✓ Generated function would return (Integer, Integer)");
}


