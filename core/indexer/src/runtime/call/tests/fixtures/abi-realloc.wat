(component
  (core module $code
    (memory (export "memory") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      i32.const 64)
    (func (export "run") (param i32 i32) (result i32)
      i32.const 0))
  (core instance $code (instantiate $code))
  (func (export "run") (param "values" (list u32)) (result u32)
    (canon lift (core func $code "run")
      (memory $code "memory") (realloc (func $code "realloc")))))
