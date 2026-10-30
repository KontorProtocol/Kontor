(module
  (import "kontor:built-in/context" "[method]proc-context.contract"
    (func $contract (param i32) (result i32)))
  (import "kontor:built-in/context" "[resource-drop]proc-context"
    (func $drop-proc (param i32)))
  (import "kontor:built-in/context" "[resource-drop]view-context"
    (func $drop-view (param i32)))
  (memory (export "memory") 1)
  ;; Each fresh invocation lowers at most one string argument.
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    i32.const 1024)
  (func (export "init") (param i32) (result i32)
    local.get 0
    call $contract
    local.get 0
    call $drop-proc)
  (func (export "view-depth") (param i32 i32) (result i32)
    local.get 0
    call $drop-view
    local.get 1)
  (func (export "view-literal") (param i32 i32 i32) (result i32)
    local.get 0
    call $drop-view
    local.get 2)
  (func (export "print-depth64") (param i32) (result i32)
    local.get 0
    call $drop-view
    i32.const 7)
  (func (export "print-depth65") (param i32) (result i32)
    local.get 0
    call $drop-view
    i32.const 7)
)
