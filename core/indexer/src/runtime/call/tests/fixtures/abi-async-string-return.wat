(component
  (core module $memory
    (memory (export "memory") 1)
    (data (i32.const 0) "abcdefgh\ff")
    (data (i32.const 16) "\00\d8"))
  (core instance $memory (instantiate $memory))
  (core func $return
    (canon task.return (result string) (memory $memory "memory")))
  (core module $code
    (import "host" "return" (func $return (param i32 i32)))
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      local.get $ptr local.get $len call $return
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $code
    (instantiate $code
      (with "host" (instance (export "return" (func $return))))))
  (func (export "run") async (param "ptr" u32) (param "len" u32) (result string)
    (canon lift (core func $code "run") async
      (memory $memory "memory") (callback (func $code "callback")))))
