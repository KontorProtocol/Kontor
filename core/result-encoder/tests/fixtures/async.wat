(component
  (type $payload (record (field "text" string)))
  (import "payload" (type $public-payload (eq $payload)))
  (core module $memory
    (memory (export "memory") 32)
    (data (i32.const 64) "abc"))
  (core instance $memory (instantiate $memory))
  (core func $return
    (canon task.return (result $public-payload) (memory $memory "memory")))
  (core module $code
    (import "env" "return" (func $return (param i32 i32)))
    (import "env" "memory" (memory 32))
    (func (export "read") (param $len i32) (result i32)
      i32.const 64 local.get $len call $return
      i32.const 64 i32.const 122 i32.store8
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
  (core instance $code (instantiate $code (with "env" (instance
    (export "return" (func $return))
    (export "memory" (memory $memory "memory"))))))
  (func (export "read") async (param "length" u32) (result $public-payload)
    (canon lift (core func $code "read") async (memory $memory "memory")
      (callback (func $code "callback")))))
