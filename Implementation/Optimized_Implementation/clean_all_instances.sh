#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

args=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --hash-backend)
      if [[ "$#" -lt 2 ]]; then
        echo "ERROR: --hash-backend requires shake or sm3." >&2
        exit 1
      fi
      shift 2
      ;;
    --hash-backend=*)
      shift
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

if [[ "${#args[@]}" -gt 0 ]]; then
  instances=("${args[@]}")
else
  mapfile -t instances < <(find "${script_dir}" -maxdepth 1 -type d -name 'GreatWall*[fs]' -printf '%f\n' | sort)
fi

if [[ "${#instances[@]}" -eq 0 ]]; then
  echo "ERROR: no instances specified or found." >&2
  exit 1
fi

make -C "${script_dir}" INSTANCES="${instances[*]}" clean

echo "All instances cleaned."
