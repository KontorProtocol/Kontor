# S2 mechanism implementation gate amendment, v1

This amendment applies to `native-stack-s2-proposal-v7.md`, SHA256
`ea3c58c1ecd28de5887597add68d243d65754a732ba442b93d4c09af13a1aa80`.
It changes only the timing of the hardware and operational-workload gate.

1. S2 mechanism implementation may begin after the coordinator and independent
   reviewer agree to v7 plus this amendment. Reference hardware and the declared
   operational workload envelope `W_op` need not be finalized before coding.
2. Reference hardware and `W_op`, including the performance assumptions and
   acceptance criteria required by v7, must be frozen and agreed by the
   coordinator and independent reviewer before performance measurements begin.
   Obtain the operator's deployment and workload inputs for that declaration.
3. Merge requires those frozen inputs, every v7 acceptance item, all three
   implementation reviews, and green CI on the final head. The root-inclusive
   limit of 64 remains conditional on the required six-cell resource and fiber
   margins. Coding authorization does not approve that limit for deployment.

These rules replace v7's requirement to resolve the resource and performance
envelope before production edits. All other scope, implementation, validation,
and deployment constraints remain in force, including the separate OWNERSHIP
gate. The lease is acquired before Store allocation; the owner wrapper is
constructed immediately after Store creation. No lease-lifetime change is made
by this amendment.
