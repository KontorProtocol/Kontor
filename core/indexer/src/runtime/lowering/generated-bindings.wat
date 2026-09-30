(component
    (import "kontor:built-in/crypto" (instance $crypto
        (export "sha256" (func async (param "input" (list u8)) (result (list u8))))))
    (alias export $crypto "sha256" (func $hash))
    (core module $memory
        (memory (export "memory") 1)
        (func (export "realloc") (param i32 i32 i32 i32) (result i32)
            i32.const 1024))
    (core instance $memory (instantiate $memory))
    (core func $hash (canon lower (func $hash)
        (memory $memory "memory") (realloc (func $memory "realloc"))))
    (core module $guest
        (import "host" "memory" (memory 1))
        (import "host" "hash" (func $hash (param i32 i32 i32)))
        (func (export "run") (result i32)
            i32.const 0 i32.const 0 i32.const 0 call $hash
            i32.const 0 i32.load i32.load8_u
            i32.const 4 i32.load i32.add))
    (core instance $guest (instantiate $guest
        (with "host" (instance
            (export "memory" (memory $memory "memory"))
            (export "hash" (func $hash))))))
    (func (export "run") async (result u32) (canon lift (core func $guest "run"))))
