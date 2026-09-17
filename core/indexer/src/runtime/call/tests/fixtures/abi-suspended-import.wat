(component
  (import "accept" (func $accept async (param "input" string)))
  (core module $memory
    (memory (export "memory") 1)
    (data (i32.const 0) "abcdefgh"))
  (core instance $memory (instantiate $memory))
  (core func $accept
    (canon lower (func $accept) (memory $memory "memory")))
  (core func $return
    (canon task.return (result string) (memory $memory "memory")))
  (core module $code
    (import "host" "accept" (func $accept (param i32 i32)))
    (import "host" "return" (func $return (param i32 i32)))
    (func (export "run") (param $second_length i32) (result i32)
      i32.const 0 i32.const 8 call $accept
      i32.const 0 local.get $second_length call $accept
      i32.const 0 i32.const 8 call $return
      i32.const 0)
    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0))
  (core instance $code
    (instantiate $code
      (with "host" (instance
        (export "accept" (func $accept))
        (export "return" (func $return))))))
  (func (export "run") async (param "second-length" u32) (result string)
    (canon lift (core func $code "run") async
      (memory $memory "memory") (callback (func $code "callback")))))
