(module
  (import "kontor:built-in/context" "[method]proc-context.contract"
    (func $contract (param i32) (result i32)))
  (import "kontor:built-in/context" "[resource-drop]proc-context"
    (func $drop-proc (param i32)))
  (import "kontor:built-in/context" "[resource-drop]view-context"
    (func $drop-view (param i32)))
  (import "kontor:built-in/foreign" "call"
    (func $foreign (param i32 i32 i32 i32 i64 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "wave-target")
  @@DATA@@
  ;; The foreign result buffer is disjoint from expression data and its retptr.
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    i32.const 50000)
  (func (export "init") (param i32) (result i32)
    local.get 0
    call $contract
    local.get 0
    call $drop-proc)
  (func (export "run") (param $ctx i32) (param $sample i32) (result i32)
    (local $expr-ptr i32)
    (local $expr-len i32)
    @@BRANCHES@@
    local.get $expr-len
    i32.eqz
    if unreachable end
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 11
    i64.const 1
    i32.const 0
    local.get $expr-ptr
    local.get $expr-len
    i32.const 40000
    call $foreign
    local.get $ctx
    call $drop-view
    i32.const 40000)
)
