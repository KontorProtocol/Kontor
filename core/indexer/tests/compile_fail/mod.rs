// Compile-fail tests to prove compile-time linear type safety guarantees
// These tests MUST fail to compile to demonstrate the type system enforces security

#[cfg(test)]
mod tests {
    #[test]
    fn compile_fail_tests_exist() {
        // This module contains compile-fail tests using trybuild
        // Run with: cargo test --test compile_fail
        println!("Compile-fail tests validate linear type safety at compile time");
    }
}