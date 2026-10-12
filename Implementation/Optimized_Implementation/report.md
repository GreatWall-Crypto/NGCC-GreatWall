# Optimized Implementation Performance Report

## Measurement Conditions — 2026-10-10

These results replace the previous measurements in this report. The server was `office-wsl`, with an Intel Core i9-14900HX, WSL2 Linux 6.6.87.2, GCC 11.4.0, and OpenSSL 3.0.2.

All ten instances used the same C compiler flags:

```text
-O3 -march=x86-64 -mavx2 -maes -mpclmul -mtune=native -flto -fomit-frame-pointer -std=c99 -Wpedantic -Wall -Wextra
```

The optimized builds enabled AVX2, AES-NI, PCLMULQDQ, and LTO.

The benchmark used a 64-byte message, 100 iterations for 128/160/192/256, and 10 iterations for 512f/s. Each measured run followed one additional full warmup run with one iteration. Builds finished before timing began; timings ran serially, pinned to logical CPU 0, with segment timing disabled. CPU frequency was not fixed, and WSL host scheduling remained uncontrolled.

Times are arithmetic means in milliseconds. PK, SK, signature, and memory sizes are in bytes. `Static` is the sum of the executable's text, data, and BSS sections reported by `size bench_sig`, not its file size or total runtime memory. `Max RSS` is the peak resident memory of the entire benchmark process measured by `/usr/bin/time -v`, converted from KiB to bytes; it is not a per-operation measurement. The `f` parameter sets prioritize speed; the `s` parameter sets produce smaller signatures.

## SHAKE Backend

These benchmarks use OS randomness.

| Instance | Iterations | PK | SK | Signature | KeyGen ms | Sign ms | Verify ms | Static | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GreatWall128f | 100 | 36 | 36 | 3396 | 0.009 | 0.493 | 0.942 | 127561 | 2359296 |
| GreatWall128s | 100 | 36 | 36 | 2758 | 0.008 | 4.002 | 6.550 | 127705 | 7024640 |
| GreatWall160f | 100 | 42 | 42 | 5720 | 0.013 | 1.350 | 2.094 | 165669 | 2396160 |
| GreatWall160s | 100 | 42 | 42 | 4976 | 0.013 | 9.335 | 15.541 | 173393 | 7995392 |
| GreatWall192f | 100 | 50 | 50 | 8012 | 0.014 | 1.337 | 2.112 | 170085 | 2568192 |
| GreatWall192s | 100 | 50 | 50 | 6804 | 0.015 | 10.763 | 18.359 | 171281 | 10936320 |
| GreatWall256f | 100 | 66 | 66 | 14260 | 0.019 | 1.879 | 3.062 | 215201 | 8044544 |
| GreatWall256s | 100 | 66 | 66 | 12236 | 0.018 | 12.589 | 22.082 | 214473 | 51290112 |
| GreatWall512f | 10 | 132 | 132 | 57812 | 0.035 | 43.860 | 59.156 | 404065 | 12460032 |
| GreatWall512s | 10 | 132 | 132 | 50012 | 0.056 | 369.849 | 507.635 | 403525 | 87949312 |

## SM3 Backend

These benchmarks use the official deterministic DRNG. Submission KAT generation also uses SM3 and the official DRNG, initialized from each recorded seed; benchmark seeds are separate from KAT seeds.

| Instance | Iterations | PK | SK | Signature | KeyGen ms | Sign ms | Verify ms | Static | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GreatWall128f | 100 | 36 | 36 | 3396 | 0.013 | 2.425 | 2.114 | 108672 | 2621440 |
| GreatWall128s | 100 | 36 | 36 | 2758 | 0.013 | 22.351 | 15.032 | 107092 | 6168576 |
| GreatWall160f | 100 | 42 | 42 | 5720 | 0.015 | 5.005 | 4.988 | 152136 | 2351104 |
| GreatWall160s | 100 | 42 | 42 | 4976 | 0.016 | 36.440 | 37.568 | 152060 | 8294400 |
| GreatWall192f | 100 | 50 | 50 | 8012 | 0.019 | 6.737 | 6.492 | 152904 | 2703360 |
| GreatWall192s | 100 | 50 | 50 | 6804 | 0.021 | 59.876 | 59.887 | 153640 | 10964992 |
| GreatWall256f | 100 | 66 | 66 | 14260 | 0.024 | 10.098 | 10.024 | 198924 | 6320128 |
| GreatWall256s | 100 | 66 | 66 | 12236 | 0.024 | 80.545 | 81.766 | 199496 | 37638144 |
| GreatWall512f | 10 | 132 | 132 | 57812 | 0.059 | 274.078 | 272.656 | 378414 | 11558912 |
| GreatWall512s | 10 | 132 | 132 | 50012 | 0.061 | 2423.396 | 2485.376 | 383060 | 78684160 |

## Validation and Evidence

All 20 optimized configurations (ten instances, two backends) passed clean builds, benchmarks, input regressions, and post-test `make clean` checks. Input regressions covered valid signatures, invalid lengths and null inputs, public-key padding, eight random key bit flips and eight random canonical fake keys per configuration, selected signature/message modifications, and empty messages.

Each of the ten optimized SM3 instances generated ten KAT records twice. Both runs matched the shared `Test_Vector` files and the corresponding reference implementation byte-for-byte. The uploaded source snapshot passed its final hash check. These results are functional and performance checks, not a security proof, exhaustive fuzzing, or an allocation/RNG-failure audit. Compiler warnings remain recorded in the build logs.

The complete run covered 40 optimized/reference configurations. Raw timings, cycle counts, and throughput are in [benchmark_results.csv](test/results/office-wsl-20261010-T4wiIler/benchmark_results.csv). Environment, coverage, limitations, and historical comparisons are in [full_test_report.txt](test/results/office-wsl-20261010-T4wiIler/full_test_report.txt). Per-configuration build, binary-size, memory, KAT, and regression logs are under [Optimized_Implementation results](test/results/office-wsl-20261010-T4wiIler/Optimized_Implementation/).

Server run directory: `/mnt/d/VsCode/GreatWall_full_validation_20261010.T4wiIler`.
