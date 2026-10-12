#!/usr/bin/env bash
set -euo pipefail

# All builds occur in a disposable Linux directory, never in the source trees.
if [[ $(uname -s) != Linux ]]; then
    printf 'Run this regression in Linux or WSL.\n' >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -- "$script_dir/../.." && pwd -P)
tree=${1:-Optimized_Implementation}
variant=${2:-GreatWall128f}
backend=${3:-sm3}
case "$tree" in Optimized_Implementation|Reference_Implementation) ;; *) exit 2 ;; esac
case "$variant" in GreatWall128[fs]|GreatWall160[fs]|GreatWall192[fs]|GreatWall256[fs]|GreatWall512[fs]) ;; *) exit 2 ;; esac
case "$backend" in shake|sm3) ;; *) exit 2 ;; esac
trials=${TRIALS:-8}
jobs=${JOBS:-4}
[[ "$trials" =~ ^[1-9][0-9]*$ && "$jobs" =~ ^[1-9][0-9]*$ ]] || exit 2
compiler=${CC:-cc}
results_root=${RESULTS_ROOT:-"$script_dir/results"}
mkdir -p "$results_root"
results=$(mktemp -d "$results_root/verify-$tree-$variant-$backend-$(date +%Y%m%d-%H%M%S).XXXXXX")
build_dir=$(mktemp -d /tmp/greatwall-verify-input.XXXXXX)
cleanup() {
    if [[ -d "$build_dir" && ! -L "$build_dir" &&
          "$build_dir" == /tmp/greatwall-verify-input.* &&
          $(realpath -- "$build_dir") == "$build_dir" ]]; then
        rm -rf -- "$build_dir"
    fi
}
trap cleanup EXIT
ulimit -c 0
printf '==> %s/%s %s\nResults: %s\n' "$tree" "$variant" "$backend" "$results"
tar -C "$project_dir/$tree/$variant" --exclude=output --exclude='*.o' --exclude='*.d' \
    --exclude=KAT_SIG --exclude='*.a' --exclude='bench_sig*' -cf - . |
    tar -C "$build_dir" -xf -
if ! make -C "$build_dir" -j"$jobs" CC="$compiler" HASH_BACKEND="$backend" \
          KAT_SIG > "$results/build.log" 2>&1; then
    tail -n 30 "$results/build.log" >&2
    exit 2
fi
objects=()
for object in "$build_dir"/*.o; do
    case "${object##*/}" in KAT_SIG.o|randomness_*.o) continue ;; esac
    objects+=("$object")
done
flags=(-O2 -std=c99 -Wpedantic -Wall -Wextra -I"$build_dir")
if [[ "$tree" == Optimized_Implementation ]]; then
    flags=(-O3 -march=x86-64 -mavx2 -maes -mpclmul -mtune=native -flto
           -fomit-frame-pointer -std=c99 -Wpedantic -Wall -Wextra -I"$build_dir")
fi
if [[ "$backend" == sm3 ]]; then flags+=(-DGREATWALL_HASH_BACKEND_SM3); fi
if ! "$compiler" "${flags[@]}" "$script_dir/verification_input_test.c" "${objects[@]}" \
        -Wl,--wrap=malloc,--wrap=aligned_alloc,--wrap=posix_memalign \
        -lcrypto -o "$build_dir/verification_input_test" > "$results/link.log" 2>&1; then
    tail -n 30 "$results/link.log" >&2
    exit 2
fi
input=--fresh
if [[ "$backend" == sm3 ]]; then input="$project_dir/Test_Vector/KAT_SIG_$variant.txt"; fi
set +e
timeout 900 "$build_dir/verification_input_test" "$input" "$trials" \
    2> "$results/verification_stderr.log" | tee "$results/summary.log"
statuses=("${PIPESTATUS[@]}")
set -e
status=${statuses[0]}
if ((status == 0 && statuses[1] != 0)); then status=2; fi
printf 'tree=%s variant=%s backend=%s trials=%s exit_status=%s\n' \
    "$tree" "$variant" "$backend" "$trials" "$status" | tee "$results/status.log"
exit "$status"
