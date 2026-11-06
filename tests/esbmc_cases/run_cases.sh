#!/usr/bin/env bash
# Run every .c case in this directory under one or more named ESBMC flag sets
# inside the pinned image and print a verdict table.
#   bash run_cases.sh                 # all configs, all cases
#   bash run_cases.sh scoped argv1.c  # one config, one case
set -u
DIR="${CASES_DIR:-$(cd "$(dirname "$0")" && pwd)}"
IMAGE="${ESBMC_IMAGE:-esbmc:8.4}"
TIMEOUT="${ESBMC_TIMEOUT:-120}"
KIND="--k-induction --interval-analysis --unlimited-k-steps --state-hashing --add-symex-value-sets"
BASE="--timeout ${TIMEOUT}s --memlimit 4g --64 --function main --no-unwinding-assertions --witness-output /work/witness.graphml -Wno-int-conversion -D_GNU_SOURCE"
CHECKS_UNSIGNED="--force-malloc-success --memory-leak-check --overflow-check --unsigned-overflow-check --nan-check --ub-shift-check --floatbv"
CHECKS_SCOPED="--force-malloc-success --memory-leak-check --overflow-check --nan-check --ub-shift-check --floatbv --no-align-check"
ARGV="--argv-max-args 6 --argv-max-strlen 16"
declare -A CFG
CFG[unsigned]="$KIND $BASE $CHECKS_UNSIGNED"                   # adds the unsigned-wraparound check
CFG[scoped]="$KIND $BASE $CHECKS_SCOPED $ARGV"                 # pipeline configuration
CFG[scoped_noargv]="$KIND $BASE $CHECKS_SCOPED"                # scoped without the argv model
CFG[scoped_strlen8]="$KIND $BASE $CHECKS_SCOPED --argv-max-args 6 --argv-max-strlen 8"
CFG[scoped_align]="$KIND $BASE ${CHECKS_SCOPED/--no-align-check/}$ARGV"
CFG[scoped_vacuity]="$KIND $BASE $CHECKS_SCOPED $ARGV --check-vacuity"
CFG[recommended]="$KIND $BASE $CHECKS_SCOPED --force-realloc-success --no-reachable-memory-leak --no-abnormal-memory-leak $ARGV"
CFG[scoped_uninit]="$KIND $BASE $CHECKS_SCOPED $ARGV --uninitialised-vars-check"
CFG[scoped_unchecked]="$KIND $BASE $CHECKS_SCOPED $ARGV --unchecked-return-value-check"
CFG[scoped_realloc]="$KIND $BASE $CHECKS_SCOPED $ARGV --force-realloc-success"
CFG[scoped_noreach]="$KIND $BASE $CHECKS_SCOPED $ARGV --no-reachable-memory-leak --no-abnormal-memory-leak"
CFG[scoped_printf]="$KIND $BASE $CHECKS_SCOPED $ARGV --printf-check"
CFG[scoped_multi]="$KIND $BASE $CHECKS_SCOPED $ARGV --multi-property"
CFG[scoped_structf]="$KIND $BASE $CHECKS_SCOPED $ARGV --struct-fields-check"
cfgs="${1:-unsigned scoped scoped_noargv}"; [ "$#" -ge 1 ] && cfgs="$1"
cases="${2:-$(ls "$DIR"/*.c | xargs -n1 basename)}"
printf '%-24s %-16s %-12s %7s  %s\n' case config verdict secs property
for c in $cases; do for k in $cfgs; do
  t0=$(date +%s.%N)
  out=$(docker run --rm -v "$DIR/$c":/work/source.c:ro -w /work --entrypoint bash "$IMAGE" -c \
        "ulimit -s unlimited && esbmc ${CFG[$k]} --input-file /work/source.c 2>&1")
  t1=$(date +%s.%N)
  if grep -q 'VERIFICATION SUCCESSFUL' <<<"$out"; then v=SUCCESSFUL
  elif grep -q 'VERIFICATION FAILED' <<<"$out"; then v=FAILED
  elif grep -qi 'timeout\|Timed out' <<<"$out"; then v=TIMEOUT
  else v=ERROR; fi
  nviol=$(grep -c 'Violated property' <<<"$out"); prop=$(grep -A3 'Violated property' <<<"$out" | grep -v 'Violated\|^--' | sed -n '1p;2p' | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-110)
  cwe=$(grep -m1 '^ *CWE:' <<<"$out" | tr -d ' ')
  printf '%-28s %-16s %-12s %7.1f %3s  %s %s\n' "$c" "$k" "$v" "$(echo "$t1 - $t0" | bc)" "$nviol" "$prop" "$cwe"
  [ -n "${SAVE_LOGS:-}" ] && mkdir -p "$DIR/logs" && printf '%s' "$out" > "$DIR/logs/${c%.c}.$k.log"
done; done
