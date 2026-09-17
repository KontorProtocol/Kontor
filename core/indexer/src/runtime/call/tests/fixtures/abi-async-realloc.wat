(component
  (core func $return (canon task.return (result u32)))
  (core module $code
    (import "host" "return" (func $return (param i32)))
    (memory (export "memory") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      i32.const 64)
    (func (export "run") (param i32 i32) (result i32)
      i32.const 0 call $return
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $code
    (instantiate $code
      (with "host" (instance (export "return" (func $return))))))
  (func (export "run") async (param "values" (list u32)) (result u32)
    (canon lift (core func $code "run") async
      (memory $code "memory") (realloc (func $code "realloc"))
      (callback (func $code "callback")))))
