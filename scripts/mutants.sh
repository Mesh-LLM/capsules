#!/usr/bin/env bash
# Every plugin mutant in gates/mutants.json must fail its tests, and print
# what the table says it must: an exact line, or a named test reported FAILED.
# Each mutant is built first, so a compile error never passes as "caught".
# cargo gets no stdin: the loop reads the rows from it.
#
#   scripts/mutants.sh [feature ...]   (default: every mutant listed)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
table="$root/gates/mutants.json"
cd "$root/crates/evidence-plugin"

# One mutant per line, fields split by \x1f (never whitespace, so an empty
# field is kept): feature, test target ("" for the binary's own tests),
# test filter, expectation kind, expected text. An empty table would pass with
# nothing checked.
rows=$(python3 - "$table" <<'EOF'
import json, sys
mutants = json.load(open(sys.argv[1]))["mutants"]
if not mutants:
    sys.exit(f"{sys.argv[1]} lists no mutant")
for m in mutants:
    (kind, text), = m["must_print"].items()
    print("\x1f".join([m["feature"], m.get("test", ""), m["tests"], kind, text]))
EOF
)

if [ $# -gt 0 ]; then
  for feature in "$@"; do
    cut -d $'\x1f' -f1 <<<"$rows" | grep -qxF -- "$feature" \
      || { echo "::error::$feature is not in $table"; exit 1; }
  done
  rows=$(awk -F'\037' 'NR == FNR { want[$0] = 1; next } $1 in want' <(printf '%s\n' "$@") <(printf '%s\n' "$rows"))
fi

status=0
while IFS=$'\x1f' read -r feature test filter kind text; do
  if [ -n "$test" ]; then
    # Integration tests start the plugin process; they run one at a time.
    target=(--test "$test")
    threads=(--test-threads=1)
  else
    target=(--bin capsules)
    threads=()
  fi
  cargo test --locked "${target[@]}" --features "$feature" --no-run -q </dev/null
  if out=$(cargo test --locked "${target[@]}" --features "$feature" -- "$filter" ${threads[@]+"${threads[@]}"} </dev/null 2>&1); then
    echo "::error::the tests passed a build with $feature"
    status=1
    continue
  fi
  case "$kind" in
    line) grep -qxF -- "$text" <<<"$out" && found=1 || found=0 ;;
    failed_test) grep -qE "^test (.*::)?${text} \.\.\. FAILED$" <<<"$out" && found=1 || found=0 ;;
    *) echo "::error::$feature: unknown expectation $kind"; status=1; continue ;;
  esac
  if [ "$found" = 1 ]; then
    echo "caught: $feature"
  else
    echo "$out"
    echo "::error::$feature failed, but did not print its $kind: $text"
    status=1
  fi
done <<<"$rows"
exit $status
