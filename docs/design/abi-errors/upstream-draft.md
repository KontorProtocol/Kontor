# Typed errors for host-side component conversion failures

I'm using Wasmtime 48.0.2 to execute smart contracts. A failure caused by guest
data should roll back the call, while a host or database failure needs different
handling.

Some component conversion errors are difficult to distinguish without matching
messages:

- `HostcallFuelExhausted` is private, so I can't downcast an allocation-allowance
  failure.
- Host-side string pointer checks return message errors, although
  `Trap::StringOutOfBounds` and `Trap::UnalignedPointer` already exist.
- Invalid UTF-8/UTF-16 returns decoder errors without a component-specific type.

Would exposing the allowance error, using the existing pointer traps, and adding
a typed string-encoding error make sense? I have a small patch tested with sync
and async returns and nested contract calls. It leaves real host allocation
failures and host errors separate.

This is about identifying failures; I'm not asking for the allocation allowance
to debit instruction fuel.
