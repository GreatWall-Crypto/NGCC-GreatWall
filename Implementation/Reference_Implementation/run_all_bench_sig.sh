#!/usr/bin/env bash

set -euo pipefail

original_args=("$@")
iterations=100
if [[ "$#" -gt 0 && "$1" =~ ^[1-9][0-9]*$ ]]; then
  iterations="$1"
  shift
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_file="${script_dir}/benchmark_results.csv"
log_file="${script_dir}/benchmark_run.log.txt"

hash_backend="${HASH_BACKEND:-sm3}"
jobs="${JOBS:-8}"
case "${hash_backend}" in
  shake|sm3) ;;
  *) echo "ERROR: HASH_BACKEND must be shake or sm3." >&2; exit 2 ;;
esac
if [[ ! "${jobs}" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: JOBS must be a positive integer." >&2
  exit 2
fi

if [[ "${BENCH_SIG_LOG_ACTIVE:-0}" != "1" ]]; then
  BENCH_SIG_LOG_ACTIVE=1 exec bash "${script_dir}/run_all_bench_sig.sh" "${original_args[@]}" > >(tee "${log_file}") 2>&1
fi

if [[ "$#" -gt 0 ]]; then
  instances=("$@")
else
  mapfile -t instances < <(find "${script_dir}" -maxdepth 1 -type d -name 'GreatWall*' -printf '%f\n' | sort)
fi

if [[ "${#instances[@]}" -eq 0 ]]; then
  echo "ERROR: no instances specified or found under ${script_dir}" >&2
  exit 1
fi

cat > "${results_file}" <<'CSV'
algorithm,iterations,message_bytes,pk_bytes,sk_bytes,sig_bytes,keygen_avg_ms,sign_avg_ms,verify_avg_ms,keygen_avg_cycles,sign_avg_cycles,verify_avg_cycles,keygen_ops_s,sign_ops_s,verify_ops_s
CSV

for instance in "${instances[@]}"; do
  instance_dir="${script_dir}/${instance}"
  if [[ ! -d "${instance_dir}" ]]; then
    echo "ERROR: missing instance directory: ${instance_dir}" >&2
    exit 1
  fi

  echo "==> ${instance}: build bench_sig (HASH_BACKEND=${hash_backend})"
  make -C "${instance_dir}" -j"${jobs}" HASH_BACKEND="${hash_backend}" bench_sig

  echo "==> ${instance}: ./bench_sig ${iterations}"
  (cd "${instance_dir}" && ./bench_sig "${iterations}") | tee -a "${results_file}"
done

echo "Benchmark results written to ${results_file}"
echo "Full benchmark log written to ${log_file}"
