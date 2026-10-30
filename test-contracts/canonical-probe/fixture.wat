(module
  (import "kontor:built-in/context" "[method]proc-context.contract"
    (func $contract (param i32) (result i32)))
  (import "kontor:built-in/context" "[resource-drop]proc-context"
    (func $drop-proc-context (param i32)))
  (import "kontor:built-in/context" "[resource-drop]view-context"
    (func $drop-view-context (param i32)))
  (memory (export "memory") 1)
  (func (export "init") (param i32) (result i32)
    local.get 0
    call $contract
    local.get 0
    call $drop-proc-context)
  (func (export "view-run") (param i32 i32 i32)
    local.get 0
    call $drop-view-context)
  (func (export "view-echo") (param i32 i32 i32) (result i32)
    i32.const 32
    local.get 1
    i32.store
    i32.const 36
    local.get 2
    i32.store
    local.get 0
    call $drop-view-context
    i32.const 32)
  (func (export "paid-light") (param i32)
    local.get 0
    call $drop-proc-context)
  (func (export "paid-heavy") (param i32)
    local.get 0
    call $drop-proc-context)
  (func (export "cabi_post_view-run"))
  (func (export "cabi_post_view-echo") (param i32))
  (func (export "cabi_post_paid-light")
    @@POST_LIGHT_BODY@@)
  (func (export "cabi_post_paid-heavy")
    @@POST_HEAVY_BODY@@)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    @@REALLOC_BODY@@)
)
