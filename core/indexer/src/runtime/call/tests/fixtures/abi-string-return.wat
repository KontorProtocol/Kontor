(component
  (core module $code
    (memory (export "memory") 1)
    (data (i32.const 0) "abcdefgh\ff")
    (data (i32.const 16) "\00\d8")
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      i32.const 64 local.get $ptr i32.store
      i32.const 68 local.get $len i32.store
      i32.const 64))
  (core instance $code (instantiate $code))
  (func (export "run") (param "ptr" u32) (param "len" u32) (result string)
    (canon lift (core func $code "run") (memory $code "memory"))))
