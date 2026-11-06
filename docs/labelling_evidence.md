# Labelling evidence: ESBMC 8.4 configuration study

This note records why the label command is what it is and what each verdict guarantees. Every verdict quoted below is reproducible with `tests/esbmc_cases/run_cases.sh` inside the `esbmc:8.4` image (`docker build -t esbmc:8.4 .`). Option texts are quoted from `tests/esbmc_cases/help_8.4.txt`. The expected verdict of each probe is asserted by `tests/test_esbmc_cases.py`.

## 1. ESBMC 8.4 options that matter for labelling

| option | help text (8.4) | relevance |
|---|---|---|
| `--argv-max-args nr` | "Maximum number of argv entries backed with nondet strings" | without it `argv[i]` is NULL for i >= 1 |
| `--argv-max-strlen nr` | "Maximum length (in bytes, including the null terminator) of each backed argv string" | cost knob. SAFE becomes conditional on this width |
| `--check-vacuity` | "After UNSAT discharge, re-solve path assumptions alone; if also UNSAT, report VERIFICATION UNKNOWN" | did not catch a contradictory `__ESBMC_assume` in k-induction mode (section 6) |
| `--uninitialised-vars-check` | "reads of uninitialised local variables (CWE-457)" | correct on scalars and structs, false positive on a bounded-loop array (section 5) |
| `--unchecked-return-value-check` | "unchecked return values of fallible calls (CWE-252)" | did not fire on an unchecked `fgets` (section 5) |
| `--sarif-output` | "SARIF 2.1.0 report ... annotated with the matching CWE ids (CWE 4.20)" | structured CWE per violation |
| `--all-witnesses`, `--max-witnesses` | enumerate further violating input vectors | implies `--multi-property`, which crashes with witness output (section 5) |
| `--loop-invariant`, `--loop-frame-rule` | invariant-based proving | not needed. Every SAFE observed came from the forward condition |
| `--sv-comp` | suppress GCC-acceptable diagnostics, physical line numbers, no malloc/free in the fopen model | not used. It would hide frontend errors that we want to see |

## 2. Verdict semantics under k-induction

Configuration: `--k-induction --unlimited-k-steps --no-unwinding-assertions` plus the checks.

* **VULNERABLE** is `VERIFICATION FAILED`. The base case at some k found a satisfying assignment for the negation of one property. The counterexample is a concrete execution of the program under ESBMC's environment model. The guarantee is exact relative to that model.
* **SAFE** is `VERIFICATION SUCCESSFUL` by the **forward condition**: all loops in the program were fully unrolled at the reached k and no property is violated in any state. This is an exhaustive proof for the program as written, not an inductive generalisation. Every one of the SUCCESSFUL runs in the probe battery reports "Solution found by the forward condition". A bounded loop with an input-dependent count up to 256 was unrolled to k = 257 in 7 s.
* **UNKNOWN** is a timeout or memory limit before the forward condition holds. Programs with unbounded input loops (`while (fgets(...))`) and programs that read argv content under the argv model end here.
* `--no-unwinding-assertions` does not weaken SAFE. The forward condition is the proof obligation that loops are fully unrolled, and it is checked regardless of that flag. The flag only prevents plain-BMC unwinding assertions from being reported as violations.
* The interval analysis and value-set passes add assumptions derived from static analysis. They are sound over-approximations. No probe changed verdict with them on or off, and they stay for performance.

Consequence for generation: a SAFE label requires every loop to terminate within the budget. Programs read a bounded amount of input (a fixed number of records, a fixed-size buffer) and never spin on `while (fgets)` or `while (read)` without a static bound. The generation prompt states this.

## 3. Environment model: where nondeterminism comes from

Each probe is vulnerable only if the input channel is adversarial, and has a correctly guarded twin. Verdicts under the pipeline configuration:

| channel | vulnerable twin | guarded twin | reading |
|---|---|---|---|
| `fgets(stdin)` | FAILED (off-by-one in helper) | SUCCESSFUL | content and length nondeterministic, 1 s |
| `fread(stdin)` | FAILED (length field drives memcpy) | SUCCESSFUL | 1 s |
| `getchar()` loop | FAILED | SUCCESSFUL | |
| `scanf("%d")` as index | FAILED | SUCCESSFUL | |
| POSIX `read(0, ...)` | FAILED | | buffer bytes nondeterministic |
| `recv(fd, ...)` | FAILED | | same |
| `fopen` + `fread` | FAILED | | success path explored, content nondeterministic |
| `getenv("HOME")` | FAILED (strcpy into 8 bytes) | SUCCESSFUL (snprintf) | string of nondeterministic content and length |
| `rand()`, `time(NULL)` | FAILED | | nondeterministic return |
| uninitialised local array or scalar | FAILED (as OOB or signed overflow) | | uninitialised memory is nondeterministic. The report names the consequence, not the CWE-457 cause |
| undefined external function | return value nondeterministic (FAILED when used as index) | pointer arguments not havocked (SUCCESSFUL) | a stub can hide a bug. Generated programs must be fully defined, which the compile-and-link step enforces |
| argv content | FAILED in `strlen` or `atoi` without the argv model, SUCCESSFUL with it (23 s) | | section 4 |

Every realistic input channel (stdin, files, environment, sockets, time, randomness) is already adversarial under ESBMC's model. Programs do not need argv to be realistic. File and socket-style parsing is what the seeds do, and it verifies fast.

## 4. argv: what the model guarantees and what it costs

* Without the argv flags `argv[i]` is NULL for i >= 1. A guarded `atoi(argv[1])` fails inside `atoi`. `__ESBMC_assume(argv[1] != NULL)` makes proofs vacuous (`assert(0)` then verifies).
* With `--argv-max-args 6 --argv-max-strlen 16` the same program is SUCCESSFUL in 23 s (0.5 s otherwise). `strcpy(argv[1])` into `char[4]` is FAILED in `strcpy` (correct). `assert(0)` after the argv read is still FAILED (not vacuous). SAFE then means "no violation for up to 6 arguments of up to 15 bytes", a bound that must ship with every SAFE label.
* Programs that read argv content stall under the argv model (k = 7 to 11, timeouts at 120 s in a sample of 20 SAFE programs). Programs without argv content finished in at most 36 s.

Decision: the compile stage rejects `argc`/`argv` (the prompt requires `int main(void)`). The two flags stay in the command as a safety net (zero cost when unused), so a program that slips through is labelled on its logic rather than on the NULL model. No released program reads command-line arguments.

## 5. Checks: what is enabled, with evidence per flag

| flag | 8.4 result | decision |
|---|---|---|
| default pointer and bounds checks | NULL dereference, stack OOB write, double free, free of stack memory, use-after-free and division by zero all FAILED with the expected CWE | on |
| `--overflow-check` | signed `x*2` on input FAILED (CWE-190) | on |
| `--unsigned-overflow-check` | idioms such as `while(n--)`, `(uint32_t)p[0]<<24` and a correct `fread` FAILED with it and were SUCCESSFUL without. A used wrapped length still FAILS as the memcpy OOB it causes | off. Strict class only as a metadata tag |
| `--force-malloc-success` | `p = malloc(); p->f = ...` SUCCESSFUL with it, FAILED "NULL pointer" without | on |
| `--force-realloc-success` | separate switch. `q = realloc(p); q[0]` FAILED without it even with force-malloc-success | on |
| `--memory-leak-check` | lost local allocation FAILED (correct). Still-reachable global at exit FAILED. Allocation live at `abort()` FAILED inside `abort`. Allocation live at `exit(1)` SUCCESSFUL | on, with the two scoping flags below |
| `--no-reachable-memory-leak` | still-reachable global at exit becomes SUCCESSFUL. The lost allocation stays FAILED | on (matches LeakSanitizer semantics) |
| `--no-abnormal-memory-leak` | `abort()` path becomes SUCCESSFUL | on (deliberate termination is not a leak) |
| `--no-align-check` | On a sample of 30 programs flagged by an alignment violation, only 3 were explicit unaligned casts such as `*(uint16_t *)(data + offset)`. The other 27 were plain field reads through a header pointer obtained by casting a byte buffer (`hdr->magic`), the standard parser idiom, benign on x86-64 and not a memory-safety defect. With the check off, 24 of the 30 still FAIL on a real property | off |
| `--nan-check`, `--ub-shift-check`, `--floatbv` | | on |
| `--uninitialised-vars-check` | correct on a scalar and a partially initialised struct, no false positive on an fgets buffer, false positive on `int b[256]` written in a bounded loop then read | off for the label |
| `--unchecked-return-value-check` | no report on unchecked `fgets` | off |
| `--printf-check` | did not report `printf("%s", NULL)` | off |
| `--struct-fields-check` | no effect on probes | off |
| `--no-unlimited-scanf-check` | turns a genuine `scanf("%s", buf8)` from FAILED to SUCCESSFUL | never |
| `--multi-property` | crashes when combined with `--witness-output` after printing the first FAILED claim | never in the label pass |
| `--check-vacuity` | a contradictory `__ESBMC_assume(x>5)` with `x=3` is still SUCCESSFUL. Verdicts on 20 SAFE programs were identical with and without it, only the runtime changed (one program 2.2 s to 66.7 s) | off. Generated code may not use `__ESBMC_assume`, `__VERIFIER_assume` or similar intrinsics |
| `--witness-output P` | writes `P.graphml` and `P.yml` | the stem is passed without a suffix and both witnesses are stored |
| `--sarif-output` | one result per violation with `taxa` CWE ids and rule id | on. The SARIF CWE ids are the primary CWE source |
| `--generate-json-report` | writes `report.json` with line coverage of the counterexample | optional |

## 6. Failure modes to design around

1. **Configuration drift.** Verdict and violated property depend on the flag set. Every record carries the flag string, ESBMC version and image digest, and all programs are verified under one string.
2. **Frontend sensitivity.** Some programs fail to parse on 8.4 (missing macro, header redefinition, internal error). They end as UNKNOWN and are excluded. Report the rate.
3. **Unbounded input loops and argv content** time out.
4. **Near-duplicate expansions** of one seed inflate counts and leak between splits. Cap per seed and de-duplicate.
5. **Uninitialised reads** are labelled by their consequence (OOB, overflow) at the use site, so the recorded root cause can mislead.
6. **Undefined functions** are under-approximated (pointer arguments not havocked). Only fully defined, linked programs are verified.
7. **Intrinsics** (`__ESBMC_assume`, `__VERIFIER_*`, `__ESBMC_assert`) can make SAFE vacuous and are not caught by `--check-vacuity`. The compile stage rejects them.
8. **Threads.** A two-thread mutex program verified in 2.6 s, but data races are not checked without `--data-races-check`.

## 7. Label command (8.4)

Adopted in `src/agents/esbmc_verification.py`:

```
ulimit -s unlimited && esbmc \
  --k-induction --interval-analysis --unlimited-k-steps --state-hashing --add-symex-value-sets \
  --timeout 590s --memlimit 4096m --64 --function main \
  --force-malloc-success --force-realloc-success \
  --memory-leak-check --no-reachable-memory-leak --no-abnormal-memory-leak \
  --overflow-check --nan-check --ub-shift-check --floatbv \
  --no-align-check --no-unwinding-assertions \
  --argv-max-args 6 --argv-max-strlen 16 \
  -Wno-int-conversion -D_GNU_SOURCE \
  --witness-output /work/witness --sarif-output /work/out.sarif \
  --input-file /work/source.c
```

Definitions that ship with the data:

* **VULNERABLE**: ESBMC 8.4 with this command found a concrete execution violating one of the checked properties. The property, its location, the counterexample, the witnesses and the SARIF CWE ids are the record.
* **SAFE**: under the same command all loops were fully unrolled within the budget and no checked property is violated on any execution, assuming allocation never fails, still-reachable memory at exit is not a leak, abnormal termination does not leak, pointer alignment is not checked, unsigned wraparound is not a defect, and inputs (stdin, files, environment, time, randomness) are arbitrary. No program reads command-line arguments.

## 8. Dynamic confirmation

`src/utils/dynamic_confirm.py` and `scripts/confirm_labels.py` check each verdict independently. The program is compiled with AddressSanitizer, LeakSanitizer and the UBSan classes that ESBMC also checks (signed overflow, shift, division by zero, null, bounds). The runner drives stdin, files named in the source and environment variables read by the source with boundary-value and mutated inputs, and compares any sanitizer report with the property ESBMC violated. It runs in the pinned image because the `gcc:latest` compile image has no sanitizer runtime. ESBMC's testcase output cannot be replayed, because it is a flat list of values consumed by ESBMC's own library models rather than stdin bytes.

The full sanitizer report, the triggering input (base64), the exit code and the sanitizer flags are stored with each finding, so a result can be replayed.

Outcomes: VULNERABLE gives `confirmed_exact`, `confirmed_function`, `confirmed_class`, `other_defect` or `not_reproduced`. SAFE gives `no_crash_found` or `counterexample_found`. `not_reproduced` is not evidence against a label, only that the campaign did not reach it. `env_dependent` records calls (`stat`, `open`, `localtime_r`, `rand`, ...) whose results ESBMC leaves unconstrained and a real run cannot enumerate.

Pilot on 300 argv-free programs verified under the label command (253 conclusive):

| | n | result |
|---|---:|---|
| VULNERABLE | 72 | 54 confirmed (12 at the exact line, 42 same defect class), 7 crash with a different real defect, 11 not reproduced |
| SAFE | 181 | 177 no crash found, 2 crash, 2 do not compile with the sanitizer flags |

* The 2 crashing SAFE programs are one defect in two near-identical programs and a real false SAFE: `strstr` on a literal with an embedded `\0` returns NULL on a real machine, ESBMC's model does not stop at the `\0`, so it proves `strtoul(strstr(...))` safe (`tests/esbmc_cases/false_safe_strcmp_null.c`).
* Not-reproduced VULNERABLE programs mostly depend on environment results that ESBMC leaves unconstrained, for example `t->tm_year + 1900` overflowing only if `localtime_r` returns a year near INT_MAX. These labels are valid under the model and unrealisable on a real machine.
* UBSan `nonnull-attribute` reports (NULL to `memcpy` or `strcmp`) are outside ESBMC's property set and are not counted.

The headline subset of a release is the ESBMC-VULNERABLE or SAFE programs that are dynamically confirmed or show no crash and are not environment-dependent. The fields `dynamic_check`, `dynamic_confirmed` and `env_dependent` carry this per record.
