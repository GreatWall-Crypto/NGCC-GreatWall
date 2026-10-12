# GreatWall/Pylon Reference Implementation

## Variants and environment

This directory contains ten independent reference instances:

- `GreatWall128f`, `GreatWall128s`
- `GreatWall160f`, `GreatWall160s`
- `GreatWall192f`, `GreatWall192s`
- `GreatWall256f`, `GreatWall256s`
- `GreatWall512f`, `GreatWall512s`

The `f` parameter sets prioritize speed; the `s` parameter sets produce smaller signatures and are typically slower.

Build and run under **Linux or WSL**. The reference implementation uses scalar C with C99 and `-O2` compilation, without requiring AVX2, AES-NI, or PCLMULQDQ.

## Building and cleaning

Run the following commands from this directory, `Reference_Implementation`.

The top-level Makefile builds all ten instances by default:

```bash
# Build with the default SM3 backend, including each instance's KAT_SIG.
# Use this configuration to reproduce the KAT vectors.
make -j8

# Build all benchmark programs with SHAKE (recommended for timing).
make -j8 bench_sig HASH_BACKEND=shake

# Remove build artifacts.
make clean
```

Use `INSTANCES` to select individual instances:

```bash
make -j8 INSTANCES="GreatWall128f GreatWall160f"
make clean INSTANCES="GreatWall128f GreatWall160f"
```

The existing helper scripts are also available:

```bash
bash clean_all_instances.sh
bash make_all_instances.sh
bash run_all_kat_sig.sh
bash run_all_bench_sig.sh 100
bash run_all_memory_sig.sh 100
```

The benchmark and memory scripts default to SM3. Prefix either command with `HASH_BACKEND=shake` to use SHAKE.

To obtain timing results more quickly, we recommend reducing the number of benchmark iterations for the 512-bit parameter sets.

## Running selected instances

Pass instance names as script arguments:

```bash
bash make_all_instances.sh GreatWall128f GreatWall512s
bash run_all_kat_sig.sh GreatWall128f GreatWall512s
bash run_all_bench_sig.sh 100 GreatWall128f
bash run_all_memory_sig.sh 100 GreatWall128f
bash make_all_instances.sh --hash-backend sm3 GreatWall128f
```

## Note on the 512-bit implementation

The current 512-bit implementation is not yet complete. Its temporary use of SHAKE256 introduces a security-strength limitation, which can be resolved by replacing it with a hash function that meets the required security strength. This limitation is unrelated to our core contribution, the design of GreatWall.
