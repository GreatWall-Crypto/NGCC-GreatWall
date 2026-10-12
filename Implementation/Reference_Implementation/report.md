# Reference Implementation Performance Report

## Measurement Conditions — 2026-10-10

These results replace the previous measurements in this report. The server was `office-wsl`, with an Intel Core i9-14900HX, WSL2 Linux 6.6.87.2, GCC 11.4.0, and OpenSSL 3.0.2.

All ten instances used the same C compiler flags:

```text
-O2 -std=c99 -Wpedantic -Wall -Wextra -Wno-missing-braces
```

The reference builds used scalar C, without AVX2, AES-NI, or PCLMULQDQ compiler options.

The benchmark used a 64-byte message, 100 iterations for 128/160/192/256, and 10 iterations for 512f/s. Each measured run followed one additional full warmup run with one iteration. Builds finished before timing began; timings ran serially, pinned to logical CPU 0, with segment timing disabled. CPU frequency was not fixed, and WSL host scheduling remained uncontrolled.

Times are arithmetic means in milliseconds. PK, SK, signature, and memory sizes are in bytes. `Static` is the sum of the executable's text, data, and BSS sections reported by `size bench_sig`, not its file size or total runtime memory. `Max RSS` is the peak resident memory of the entire benchmark process measured by `/usr/bin/time -v`, converted from KiB to bytes; it is not a per-operation measurement. The `f` parameter sets prioritize speed; the `s` parameter sets produce smaller signatures.

## SHAKE Backend

These benchmarks use OS randomness.

| Instance | Iterations | PK | SK | Signature | KeyGen ms | Sign ms | Verify ms | Static | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GreatWall128f | 100 | 36 | 36 | 3396 | 1.069 | 27.708 | 21.036 | 198331 | 2097152 |
| GreatWall128s | 100 | 36 | 36 | 2758 | 0.971 | 130.018 | 109.783 | 197088 | 4235264 |
| GreatWall160f | 100 | 42 | 42 | 5720 | 1.791 | 68.857 | 50.803 | 102659 | 2195456 |
| GreatWall160s | 100 | 42 | 42 | 4976 | 1.874 | 293.844 | 272.686 | 105104 | 7954432 |
| GreatWall192f | 100 | 50 | 50 | 8012 | 2.295 | 88.702 | 61.545 | 219169 | 2527232 |
| GreatWall192s | 100 | 50 | 50 | 6804 | 2.459 | 389.516 | 361.676 | 219299 | 10899456 |
| GreatWall256f | 100 | 66 | 66 | 14260 | 4.401 | 208.326 | 138.344 | 284109 | 3854336 |
| GreatWall256s | 100 | 66 | 66 | 12236 | 4.810 | 730.283 | 655.604 | 284191 | 17547264 |
| GreatWall512f | 10 | 132 | 132 | 57812 | 14.643 | 1999.747 | 1220.867 | 471980 | 11194368 |
| GreatWall512s | 10 | 132 | 132 | 50012 | 17.945 | 5216.079 | 4439.361 | 473729 | 78286848 |

## SM3 Backend

These benchmarks use the official deterministic DRNG. Submission KAT generation also uses SM3 and the official DRNG, initialized from each recorded seed; benchmark seeds are separate from KAT seeds.

| Instance | Iterations | PK | SK | Signature | KeyGen ms | Sign ms | Verify ms | Static | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GreatWall128f | 100 | 36 | 36 | 3396 | 0.985 | 25.128 | 18.294 | 209814 | 2359296 |
| GreatWall128s | 100 | 36 | 36 | 2758 | 0.967 | 104.297 | 91.449 | 208811 | 5033984 |
| GreatWall160f | 100 | 42 | 42 | 5720 | 1.713 | 65.285 | 46.655 | 112006 | 2310144 |
| GreatWall160s | 100 | 42 | 42 | 4976 | 1.628 | 262.256 | 243.004 | 115011 | 8245248 |
| GreatWall192f | 100 | 50 | 50 | 8012 | 2.795 | 85.137 | 59.109 | 231188 | 2666496 |
| GreatWall192s | 100 | 50 | 50 | 6804 | 2.831 | 364.555 | 335.625 | 231302 | 10854400 |
| GreatWall256f | 100 | 66 | 66 | 14260 | 4.413 | 201.362 | 133.063 | 297000 | 3702784 |
| GreatWall256s | 100 | 66 | 66 | 12236 | 4.320 | 687.098 | 621.971 | 297050 | 17850368 |
| GreatWall512f | 10 | 132 | 132 | 57812 | 17.617 | 1772.354 | 989.344 | 491287 | 11247616 |
| GreatWall512s | 10 | 132 | 132 | 50012 | 17.513 | 3269.101 | 2489.218 | 493116 | 78315520 |

## Validation and Evidence

All 20 reference configurations (ten instances, two backends) passed clean builds, benchmarks, input regressions, and post-test `make clean` checks. Input regressions covered valid signatures, invalid lengths and null inputs, public-key padding, eight random key bit flips and eight random canonical fake keys per configuration, selected signature/message modifications, and empty messages.

Each of the ten reference SM3 instances generated ten KAT records twice. Both runs matched the shared `Test_Vector` files and the corresponding optimized implementation byte-for-byte. The uploaded source snapshot passed its final hash check. These results are functional and performance checks, not a security proof, exhaustive fuzzing, or an allocation/RNG-failure audit. Compiler warnings remain recorded in the build logs.

In particular, both backends of reference 512f/s emitted a possible-uninitialized-value warning in `quicksilver.h:319` while compiling `qs_gf521_dot_constraint`. This warning was not diagnosed or fixed as part of this test run.

The complete run covered 40 optimized/reference configurations. Raw timings, cycle counts, and throughput are in [benchmark_results.csv](../Optimized_Implementation/test/results/office-wsl-20261010-T4wiIler/benchmark_results.csv). Environment, coverage, limitations, and historical comparisons are in [full_test_report.txt](../Optimized_Implementation/test/results/office-wsl-20261010-T4wiIler/full_test_report.txt). Per-configuration build, binary-size, memory, KAT, and regression logs are under [Reference_Implementation results](../Optimized_Implementation/test/results/office-wsl-20261010-T4wiIler/Reference_Implementation/).

Server run directory: `/mnt/d/VsCode/GreatWall_full_validation_20261010.T4wiIler`.
