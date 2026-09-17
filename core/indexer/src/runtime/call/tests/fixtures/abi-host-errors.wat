(component
  (import "fail" (func $fail async (param "kind" u32)))
  (core func $fail (canon lower (func $fail)))
  (core func $return (canon task.return (result u32)))
  (core module $code
    (import "host" "fail" (func $fail (param i32)))
    (import "host" "return" (func $return (param i32)))
    (func (export "run") (param $kind i32) (result i32)
      local.get $kind call $fail
      i32.const 42 call $return
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $code
    (instantiate $code
      (with "host" (instance
        (export "fail" (func $fail))
        (export "return" (func $return))))))
  (func (export "run") async (param "kind" u32) (result u32)
    (canon lift (core func $code "run") async
      (callback (func $code "callback")))))
