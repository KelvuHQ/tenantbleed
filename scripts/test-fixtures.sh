#!/bin/bash
# Fast regression gate: scans every planted app in parallel (about a minute) and checks each against
# what must be found and what must stay clean, then checks that every judge rule and test-data
# strategy in scripts/rules.json was produced by at least one planted case. Run it after every
# engine or judge change, before any full corpus run.
#
# A planted app is a folder fixtures/<name>/ with a fixture.json:
#   { "engine": "supabase", "checker": "check-<name>.mjs",
#     "replays": [{ "suffix": "single", "hints": { "tenancy": "single" } }] }
# engine picks how to start, scan and stop it (below; default supabase). Each replay judges the same
# scan facts again with changed hints, written as <name>-<suffix>.json; the checker gets the scan
# report first, then each replay's report. Adding an app, or an app for another database type, is a
# new folder: this script and the rules gate find it.
#
# usage: scripts/test-fixtures.sh [path to a tenantbleed.mjs build]   (default: dist/tenantbleed.mjs)
# Reports and scan logs go to $OUT (default: a temp folder), never into the repo.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/lib/docker-lock.sh"
# Five stacks at once: every Docker slot (waits for the other jobs to finish their current app).
[ -n "${TENANTBLEED_LOCK_HELD:-}" ] || take_docker_slots all "planted suite" wait
TP=${1:-$ROOT/dist/tenantbleed.mjs}
OUT=${OUT:-${TMPDIR:-/tmp}/tenantbleed-fixtures}
mkdir -p "$OUT"
# Stale reports from an earlier run must not count.
rm -f -- "${OUT:?}"/*.json "${OUT:?}"/*.check
# Freeze the build, so rebuilding while the gate runs cannot mix two versions.
cp "$TP" "$OUT/tenantbleed.mjs"

field() { node -e 'const c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));const v=process.argv[2].split(".").reduce((o,k)=>o?.[k],c);console.log(typeof v==="object"?JSON.stringify(v??null):v??"")' "$1" "$2"; }

# Per engine: start the local stack, scan it into $OUT/<name>, stop it.
start_supabase() { npx -y supabase@2.122.1 start -x studio,imgproxy,mailpit,inbucket,edge-runtime,logflare,vector,realtime,supavisor,postgres-meta > "$OUT/$1.start.log" 2>&1 < /dev/null; }
scan_supabase() { TENANTBLEED_DEBUG_RPC=1 TENANTBLEED_SAVE_INPUT=1 node "$OUT/tenantbleed.mjs" supabase --workdir . --out "$OUT/$1" --fail-on none > /dev/null 2> "$OUT/$1.err" < /dev/null; }
stop_supabase() { npx -y supabase@2.122.1 stop --no-backup > /dev/null 2>&1 < /dev/null; }

run() { # fixture folder
  local dir=$1 name
  name=$(basename "$dir")
  (
    cd "$dir" || exit 1
    local engine checker
    engine=$(field fixture.json engine); engine=${engine:-supabase}
    checker=$(field fixture.json checker)
    "start_$engine" "$name" || { echo "$name: the local stack did not start (see $OUT/$name.start.log)"; "stop_$engine"; exit 1; }
    "scan_$engine" "$name"
    "stop_$engine"
    args=("$OUT/$name.json")
    # Replays: the same facts judged again with changed hints (a single-workspace app).
    n=$(field fixture.json "replays.length"); n=${n:-0}
    for ((i = 0; i < n; i++)); do
      suffix=$(field fixture.json "replays.$i.suffix")
      node -e 'const fs=require("fs");const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));j.hints={...j.hints,...JSON.parse(process.argv[3])};fs.writeFileSync(process.argv[2],JSON.stringify(j));' "$OUT/$name.input.json" "$OUT/$name-$suffix.input.json" "$(field fixture.json "replays.$i.hints")"
      node "$OUT/tenantbleed.mjs" judge --input "$OUT/$name-$suffix.input.json" --out "$OUT/$name-$suffix" --fail-on none > /dev/null 2>&1
      args+=("$OUT/$name-$suffix.json")
    done
    node "$ROOT/scripts/$checker" "${args[@]}" > "$OUT/$name.check" 2>&1
    status=$?
    grep -E '^(FAIL|GAP)|^  (MISSING|UNEXPECTED|FALSE POS)' "$OUT/$name.check" | sed "s/^/$name: /"
    echo "$name: $(grep -E '^(expected |[a-z]+ cases: )' "$OUT/$name.check" | tail -1)"
    exit $status
  )
}

start=$(date +%s)
pids=()
for f in "$ROOT"/fixtures/*/fixture.json; do
  run "$(dirname "$f")" & pids+=($!)
done
failed=0
for p in "${pids[@]}"; do wait "$p" || failed=1; done
# Every judge rule and strategy in scripts/rules.json must have been produced by a planted case.
node "$ROOT/scripts/check-rules.mjs" "$OUT" > "$OUT/rules.check" 2>&1 || failed=1
grep -E '^(UNTESTED|UNLISTED)' "$OUT/rules.check"
tail -1 "$OUT/rules.check"
echo "fixtures: $([ $failed = 0 ] && echo PASS || echo FAIL) in $(( $(date +%s) - start ))s (reports in $OUT)"
exit $failed
