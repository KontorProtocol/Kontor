# Storage reward cost measurements

Measured on 2026-09-10 with the refactored #554 contracts and #556 numeric
foundation, using the existing composite numeric storage. The opt-in indexer test
`reward_costs_across_membership_and_file_counts` recreates the fixture, checks
payouts, and completes exhaustion cleanup for each scenario. It is ignored during
ordinary CI so this measurement does not lengthen the normal suite.

These are single local release-mode runs, with compiled contracts cached and an
in-process database. Timing includes instrumentation and ordinary procedure fee
handling; it is not a production latency guarantee. Host fuel includes metered
host work and storage deposits across the operation. `Set` counts storage host
calls, not SQL queries. The gauge's final start/end pair is overwritten by fee
settlement calls, so this benchmark deliberately does not report it as total
operation fuel. Payload/deposit layout tests belong in the scalar-storage PR.

## Refined contract, before scalar storage

| Members | Files | Operation | Time (ms) | Host fuel | Set calls |
| ---: | ---: | --- | ---: | ---: | ---: |
| 3 | 1 | accrue | 8.78 | 26,175 | 32 |
| 3 | 1 | claim | 16.48 | 269,765 | 65 |
| 3 | 1 | leave | 29.32 | 1,179,810 | 126 |
| 3 | 1 | join | 31.91 | 1,293,940 | 133 |
| 9 | 1 | accrue | 8.80 | 26,225 | 32 |
| 9 | 1 | claim | 16.39 | 269,805 | 65 |
| 9 | 1 | leave | 57.55 | 2,883,140 | 276 |
| 9 | 1 | join | 59.67 | 2,999,180 | 283 |
| 32 | 1 | accrue | 8.80 | 26,245 | 32 |
| 32 | 1 | claim | 16.56 | 269,815 | 65 |
| 32 | 1 | leave | 172.18 | 9,345,795 | 851 |
| 32 | 1 | join | 179.79 | 9,536,545 | 858 |
| 128 | 1 | accrue | 8.61 | 26,295 | 32 |
| 128 | 1 | claim | 16.54 | 268,855 | 65 |
| 128 | 1 | leave | 642.51 | 36,386,215 | 3251 |
| 128 | 1 | join | 659.94 | 36,688,385 | 3258 |
| 3 | 16 | accrue | 8.59 | 26,215 | 32 |
| 3 | 16 | claim | 16.77 | 271,865 | 65 |
| 3 | 16 | leave | 30.04 | 1,248,010 | 131 |
| 3 | 16 | join | 31.22 | 1,303,930 | 133 |
| 3 | 64 | accrue | 8.63 | 26,255 | 32 |
| 3 | 64 | claim | 16.31 | 270,875 | 65 |
| 3 | 64 | leave | 29.34 | 1,241,930 | 131 |
| 3 | 64 | join | 31.04 | 1,300,840 | 133 |

Accrual and claims keep a constant number of state operations across these file
and membership counts. Ordinary joins/leaves scale with the affected file's
membership. No membership cap is introduced; their cost is paid by the initiating
transaction, whose gas limit still bounds executable work.

| Members | Files | Cleanup calls to finish | Slowest call (ms) | Total cleanup (ms) |
| ---: | ---: | ---: | ---: | ---: |
| 3 | 1 | 1 | 39.81 | 39.81 |
| 9 | 1 | 1 | 111.64 | 111.64 |
| 32 | 1 | 3 | 206.75 | 326.12 |
| 128 | 1 | 9 | 205.01 | 1192.62 |
| 3 | 16 | 1 | 352.45 | 352.45 |
| 3 | 64 | 3 | 685.73 | 1343.47 |

Cleanup is bounded by its step budget, but a step that removes a small file's
membership can update several accounts. The 64-file case shows the cost of
filling that budget with such steps. Claims during a pending job remained about
constant in these scenarios. The benchmark rolls those claims back so they do
not shorten the measured background fold work.

## Removing repeated account writes

The earlier structural refactor still persisted a settled account before
membership changes rewrote it, and claims cleared credit in a second write.
Computing the final state first reduced claim Set calls from 70 to 65 and a
128-member leave from 5,811 to 3,251. Claim host fuel fell about 17%; the latter
leave fell about 45%. Those operation counts substantiate the improvement without
relying on timing noise. In these runs, that leave fell from 934 ms to 643 ms.

## Next boundary

Scalar Integer/Decimal storage remains a separate, reusable change. Each number
currently reads/writes limbs and a sign through several host operations. Replacing
that representation with one ordinary versioned storage value should reduce the
cost of every numeric contract field. It must preserve index maintenance,
rollback, deletion, metering and deposits. This is preferable to packing reward
accounts in contract code or moving economic policy into the runtime.
