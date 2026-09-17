(component
  (import "accept" (func $accept async (param "input" string)))
  (core module $memory
    (memory (export "memory") 1))
  (core instance $memory (instantiate $memory))
  (core func $accept
    (canon lower (func $accept) (memory $memory "memory")))
  (core func $return (canon task.return (result u32)))
  (core module $code
    (import "host" "accept" (func $accept (param i32 i32)))
    (import "host" "return" (func $return (param i32)))
    (func (export "run") (param $length i32) (param $count i32) (result i32)
      (block $done
        (loop $again
          local.get $count i32.eqz br_if $done
          i32.const 0 local.get $length call $accept
          local.get $count i32.const 1 i32.sub local.set $count
          br $again))
      i32.const 42 call $return
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $code
    (instantiate $code
      (with "host" (instance
        (export "accept" (func $accept))
        (export "return" (func $return))))))
  (func (export "run") async (param "length" u32) (param "count" u32) (result u32)
    (canon lift (core func $code "run") async
      (memory $memory "memory") (callback (func $code "callback")))))
