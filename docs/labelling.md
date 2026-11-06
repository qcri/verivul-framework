# Labels

Every released program carries one of three ESBMC 8.4 verdicts. The exact command, the evidence for each option and the failure modes are in [labelling_evidence.md](labelling_evidence.md).

| label | meaning |
|---|---|
| VULNERABLE | ESBMC found a concrete execution that violates a checked property (counterexample, witness and SARIF CWE ids are stored). For C and C++ the pipeline then searches for an input that makes AddressSanitizer, LeakSanitizer or UBSan fire |
| SAFE | k-induction with the forward condition proved all loops fully unrolled and no checked property violated, under the assumptions stated in section 7 of the evidence note |
| UNKNOWN | timeout, memory limit or front-end error. These programs are not released as labelled data |

## Sanitizer reproduction (C and C++)

`reproduced` is `REPRODUCED`, `NOT_REPRODUCED` or `PENDING`.

* The program is compiled with `-fsanitize=address,signed-integer-overflow,shift,integer-divide-by-zero,null,bounds,object-size,pointer-overflow,float-divide-by-zero,vla-bound` and LeakSanitizer enabled.
* Inputs come from stdin, files named in the source and environment variables read by the source. They are boundary values, mutations and ESBMC counterexample hints (at most 20,000 runs or 40 s, 3 s per run).
* If nothing crashes, the generating model is asked for a proof-of-concept input (`esbmc.poc_rounds`), then an AFL++ campaign runs.
* An original program that stays `NOT_REPRODUCED` is regenerated (`esbmc.max_regenerations`). An injected one is rejected and re-paired.
* The outcome compares the sanitizer report with the ESBMC property: `confirmed_exact` (same function and line), `confirmed_function`, `confirmed_class`, `other_defect`, `not_reproduced`. SAFE programs get `no_crash_found` or `counterexample_found`.
* `env_dependent` marks programs that call functions whose results ESBMC leaves unconstrained (`stat`, `open`, `localtime_r`, `rand`, ...). A real run cannot enumerate those results.

`not_reproduced` is not evidence that a label is wrong. It means the campaign did not reach the counterexample.

## Known limits

* Unconstrained environment-call results can make a VULNERABLE label unrealisable on a real machine.
* ESBMC's library models have gaps (for example `strstr` on a literal with an embedded NUL), so a SAFE label can be wrong. `tests/esbmc_cases/false_safe_strcmp_null.c` is one case.
* argv is not modelled. Programs that read `argv` are rejected before verification.
* Unsigned wraparound, pointer alignment, uninitialised reads and data races are not checked.
* SAFE depends on the bounds of the command: allocation never fails, still-reachable memory at exit is not a leak, and the verification budget is large enough for the loops to unroll.
