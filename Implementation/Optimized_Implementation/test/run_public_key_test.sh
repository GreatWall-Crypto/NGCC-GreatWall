#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: bash %s [GreatWall128f|GreatWall128s|GreatWall160f|GreatWall160s|GreatWall192f|GreatWall192s|GreatWall256f|GreatWall256s|GreatWall512f|GreatWall512s] [shake|sm3]\n' "$0" >&2
}
if (($# > 2)); then usage; exit 2; fi
variant=${1:-GreatWall128f}
backend=${2:-shake}
case "$variant" in
    GreatWall128f|GreatWall128s|GreatWall160f|GreatWall160s|GreatWall192f|GreatWall192s|GreatWall256f|GreatWall256s|GreatWall512f|GreatWall512s) ;;
    *) usage; exit 2 ;;
esac
case "$backend" in shake|sm3) ;; *) usage; exit 2 ;; esac
if [[ $(uname -s) != Linux ]]; then
    printf 'Run this test in Linux or WSL, not native Windows.\n' >&2
    exit 2
fi
jobs=${JOBS:-8}
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]]; then
    printf 'JOBS must be a positive integer.\n' >&2
    exit 2
fi
compiler=${CC:-cc}
for command in "$compiler" make tar mktemp realpath tee; do
    command -v "$command" >/dev/null || {
        printf 'Missing required command: %s\n' "$command" >&2
        exit 2
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -- "$script_dir/.." && pwd -P)
mkdir -p "$script_dir/results"
results=$(mktemp -d "$script_dir/results/$variant-$backend-$(date +%Y%m%d-%H%M%S).XXXXXX")
build_dir=$(mktemp -d /tmp/greatwall-public-key-test.XXXXXX)
cleanup() {
    if [[ -d "$build_dir" && ! -L "$build_dir" &&
          "$build_dir" == /tmp/greatwall-public-key-test.* &&
          $(realpath -- "$build_dir") == "$build_dir" ]]; then
        rm -rf -- "$build_dir"
    fi
}
trap cleanup EXIT

printf '==> %s (%s): isolated Linux build\n' "$variant" "$backend"
printf 'Results: %s\n' "$results"
tar -C "$project_dir/$variant" --exclude=output --exclude='*.o' --exclude='*.d' \
    --exclude=KAT_SIG --exclude='*.a' -cf - . | tar -C "$build_dir" -xf -
if ! make -C "$build_dir" -j"$jobs" CC="$compiler" HASH_BACKEND="$backend" \
          KAT_SIG > "$results/build.log" 2>&1; then
    tail -n 30 "$results/build.log" >&2
    exit 2
fi

objects=()
for object in "$build_dir"/*.o; do
    case "${object##*/}" in
        KAT_SIG.o|randomness_*.o) continue ;;
    esac
    objects+=("$object")
done
flags=(-O3 -march=x86-64 -mavx2 -maes -mpclmul -mtune=native -flto
       -fomit-frame-pointer -std=c99 -Wpedantic -Wall -Wextra -I"$build_dir")
if [[ "$backend" == sm3 ]]; then flags+=(-DGREATWALL_HASH_BACKEND_SM3); fi
if ! "$compiler" "${flags[@]}" "$script_dir/public_key_test.c" "${objects[@]}" \
        -lcrypto -o "$build_dir/public_key_test" > "$results/link.log" 2>&1; then
    tail -n 30 "$results/link.log" >&2
    exit 2
fi

printf '==> %s: public-key mutation and random-key tests\n' "$variant"
set +e
"$build_dir/public_key_test" "$results/cases.log" \
    2> "$results/verification_stderr.log" | tee "$results/summary.log"
statuses=("${PIPESTATUS[@]}")
set -e
status=${statuses[0]}
if ((status == 0 && statuses[1] != 0)); then status=2; fi
printf 'Exit status: %s\nDetailed cases: %s/cases.log\n' "$status" "$results"
exit "$status"
