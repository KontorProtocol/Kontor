(component
  (import "accept" (func $accept (param "input" string)))
  (core module $memory
    (memory (export "memory") 1))
  (core instance $memory (instantiate $memory))
  (core func $accept
    (canon lower (func $accept) (memory (core memory $memory "memory"))))
  (core module $code
    (import "host" "accept" (func $accept (param i32 i32)))
    (func (export "run") (param $length i32) (param $count i32) (result i32)
      (block $done
        (loop $again
          local.get $count i32.eqz br_if $done
          i32.const 0 local.get $length call $accept
          local.get $count i32.const 1 i32.sub local.set $count
          br $again))
      i32.const 42))
  (core instance $code
    (instantiate $code
      (with "host" (instance
        (export "accept" (func $accept))))))
  (func (export "run") (param "length" u32) (param "count" u32) (result u32)
    (canon lift (core func $code "run"))))
