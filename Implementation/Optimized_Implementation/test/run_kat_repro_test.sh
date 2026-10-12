#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Linux ]] || { printf 'Run in Linux or WSL.\n' >&2; exit 2; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -- "$script_dir/../.." && pwd -P)
tree=${1:-Optimized_Implementation}
variant=${2:-GreatWall128f}
case "$tree" in Optimized_Implementation|Reference_Implementation) ;; *) exit 2 ;; esac
case "$variant" in GreatWall128[fs]|GreatWall160[fs]|GreatWall192[fs]|GreatWall256[fs]|GreatWall512[fs]) ;; *) exit 2 ;; esac
jobs=${JOBS:-4}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || exit 2
mkdir -p "$script_dir/results"
results=$(mktemp -d "$script_dir/results/kat-repro-$tree-$variant-$(date +%Y%m%d-%H%M%S).XXXXXX")
build_dir=$(mktemp -d /tmp/greatwall-kat-repro.XXXXXX)
cleanup() {
    if [[ -d "$build_dir" && ! -L "$build_dir" &&
          "$build_dir" == /tmp/greatwall-kat-repro.* &&
          $(realpath -- "$build_dir") == "$build_dir" ]]; then
        rm -rf -- "$build_dir"
    fi
}
trap cleanup EXIT
printf '==> %s/%s SM3 KAT reproducibility\nResults: %s\n' "$tree" "$variant" "$results"
tar -C "$project_dir/$tree/$variant" --exclude=output --exclude='*.o' --exclude='*.d' \
    --exclude=.build-config --exclude=KAT_SIG --exclude='*.a' -cf - . |
    tar -C "$build_dir" -xf -
if ! make -C "$build_dir" -j"$jobs" HASH_BACKEND=sm3 KAT_SIG > "$results/build.log" 2>&1; then
    printf 'build=FAIL\n' | tee "$results/status.log"
    tail -n 25 "$results/build.log" >&2
    exit 1
fi
for round in 1 2; do
    printf '%s/%s run=%s\n' "$tree" "$variant" "$round"
    if ! (cd "$build_dir" && timeout 1800 ./KAT_SIG) > "$results/run$round.log" 2>&1; then
        printf 'run%s=FAIL\n' "$round" | tee "$results/status.log"
        exit 1
    fi
    cp "$build_dir/output/KAT_SIG_$variant.txt" "$results/run$round.txt"
done
if ! cmp -s "$results/run1.txt" "$results/run2.txt"; then
    printf 'repeat_equal=FAIL\n' | tee "$results/status.log"
    exit 1
fi
if ! cmp -s "$results/run1.txt" "$project_dir/Test_Vector/KAT_SIG_$variant.txt"; then
    printf 'repeat_equal=PASS saved_equal=FAIL\n' | tee "$results/status.log"
    exit 1
fi
printf 'tree=%s variant=%s backend=sm3 vectors=10 runs=2 repeat_equal=PASS saved_equal=PASS status=PASS\n' \
    "$tree" "$variant" | tee "$results/status.log"
