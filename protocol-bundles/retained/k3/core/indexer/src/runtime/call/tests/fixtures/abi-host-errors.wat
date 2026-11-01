(component
  (import "fail" (func $fail (param "kind" u32)))
  (core func $fail (canon lower (func $fail)))
  (core module $code
    (import "host" "fail" (func $fail (param i32)))
    (func (export "run") (param $kind i32) (result i32)
      local.get $kind call $fail
      i32.const 42))
  (core instance $code
    (instantiate $code
      (with "host" (instance
        (export "fail" (func $fail))))))
  (func (export "run") (param "kind" u32) (result u32)
    (canon lift (core func $code "run"))))
