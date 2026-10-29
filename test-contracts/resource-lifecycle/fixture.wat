(module
  (import "kontor:built-in/context" "[method]proc-context.contract"
    (func $contract (param i32) (result i32)))
  (import "kontor:built-in/context" "[resource-drop]proc-context"
    (func $drop-proc-context (param i32)))
  (import "kontor:built-in/context" "[resource-drop]view-context"
    (func $drop-view-context (param i32)))
  (import "[export]lifecycle" "[resource-new]gadget"
    (func $new-gadget (param i32) (result i32)))
  (import "[export]lifecycle" "[resource-rep]gadget"
    (func $rep-gadget (param i32) (result i32)))
  (import "[export]lifecycle" "[resource-drop]gadget"
    (func $drop-gadget (param i32)))
  (memory (export "memory") 1)
  (global $dtor-count (mut i32) (i32.const 0))
  @@DATA@@
  @@START@@
  (func (export "init") (param i32) (result i32)
    local.get 0
    call $contract
    local.get 0
    call $drop-proc-context)
  (func (export "lifecycle#[dtor]gadget") (param i32)
    global.get $dtor-count
    i32.const 1
    i32.add
    global.set $dtor-count)
  (func (export "success") (param i32) (result i32)
    i32.const 7
    call $new-gadget
    call $drop-gadget
    local.get 0
    call $drop-view-context
    global.get $dtor-count)
  (func (export "trap") (param i32) (result i32)
    i32.const 7
    call $new-gadget
    call $drop-gadget
    local.get 0
    call $drop-view-context
    global.get $dtor-count
    i32.const 1
    i32.ne
    ;; A missing destructor must produce a different trap from the expected unreachable.
    if
      i32.const 65536
      i32.load
      drop
    end
    unreachable)
)
