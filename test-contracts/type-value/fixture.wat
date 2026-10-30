(module
  (import "kontor:built-in/context" "[method]proc-context.contract"
    (func $contract (param i32) (result i32)))
  (import "kontor:built-in/context" "[resource-drop]proc-context"
    (func $drop-proc (param i32)))
  (import "kontor:built-in/context" "[resource-drop]view-context"
    (func $drop-view (param i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    i32.const 1024)
  (func (export "init") (param i32) (result i32)
    local.get 0
    call $contract
    local.get 0
    call $drop-proc)
  (func (export "view-nested-record") (param i32 i32) (result i32)
    local.get 0
    call $drop-view
    local.get 1)
  (func (export "view-nested-variant") (param i32 i32 i32) (result i32)
    i32.const 40000
    local.get 1
    i32.store
    i32.const 40004
    local.get 2
    i32.store
    local.get 0
    call $drop-view
    i32.const 40000)
  (func (export "view-list-of-records") (param i32 i32 i32) (result i32)
    i32.const 40000
    local.get 1
    i32.store
    i32.const 40004
    local.get 2
    i32.store
    local.get 0
    call $drop-view
    i32.const 40000)
  (func (export "view-large-result") (param i32) (result i32)
    i32.const 1024
    i32.const 120
    i32.const 16384
    memory.fill
    i32.const 40000
    i32.const 1024
    i32.store
    i32.const 40004
    i32.const 16384
    i32.store
    local.get 0
    call $drop-view
    i32.const 40000)
  (func (export "view-result-depth64") (param i32) (result i32)
    local.get 0
    call $drop-view
    i32.const 7)
  (func (export "view-result-depth65") (param i32) (result i32)
    local.get 0
    call $drop-view
    i32.const 7)
)
