#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

hash_backend="${HASH_BACKEND:-sm3}"
args=()
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --hash-backend)
      if [[ "$#" -lt 2 ]]; then
        echo "ERROR: --hash-backend requires shake or sm3." >&2
        exit 1
      fi
      hash_backend="$2"
      shift 2
      ;;
    --hash-backend=*)
      hash_backend="${1#*=}"
      shift
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

case "${hash_backend}" in
  shake|sm3) ;;
  *)
    echo "ERROR: unsupported HASH_BACKEND=${hash_backend}; use shake or sm3." >&2
    exit 1
    ;;
esac

if [[ "${#args[@]}" -gt 0 ]]; then
  instances=("${args[@]}")
else
  mapfile -t instances < <(find "${script_dir}" -maxdepth 1 -type d -name 'GreatWall*[fs]' -printf '%f\n' | sort)
fi

if [[ "${#instances[@]}" -eq 0 ]]; then
  echo "ERROR: no instances specified or found." >&2
  exit 1
fi

make -C "${script_dir}" HASH_BACKEND="${hash_backend}" INSTANCES="${instances[*]}" all

echo "All instances built."
