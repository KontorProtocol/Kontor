use trybuild::TestCases;

#[test]
fn test_resource_type_safety_compile_fail() {
    let t = TestCases::new();

    // Test 1: Resource<Balance> vs Resource<LpBalance> type enforcement
    t.compile_fail("tests/compile_fail/cases/wrong_resource_type.rs");

    // Test 2: LP shares vs token type separation
    t.compile_fail("tests/compile_fail/cases/lp_token_confusion.rs");

    // Test 3: Unauthorized balance construction
    t.compile_fail("tests/compile_fail/cases/unauthorized_balance_creation.rs");

    // Test 4: Wrong WIT resource import
    t.compile_fail("tests/compile_fail/cases/wrong_wit_import.rs");

    // Test 5: Bypass balance constructors
    t.compile_fail("tests/compile_fail/cases/bypass_balance_constructors.rs");

    println!("All compile-fail tests validate linear type safety guarantees");
}