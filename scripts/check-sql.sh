#!/usr/bin/env bash
# check-sql.sh — SQL safety gate for go-p2pmesh.
#
# Enforces invariant I4: "SQL 的拼接与标识符（表名/列名/排序方向）
# 都不得来自外部输入". The check is *executable*, not a document
# convention — D10's lesson is that untested invariants decay into wishes.
#
# Two rules, both backed by a Go scanner (scripts/sqlscan.go) that parses
# real Go ASTs rather than grepping, so string-literal false positives
# (a comment mentioning fmt.Sprintf) are not reported:
#
#   R1  No fmt.Sprintf / string concatenation used to build SQL.
#   R2  No user data interpolated into SQL text via format verb.
#
# The scanner also ships a self-test (scripts/sqlscan_test.go) that
# constructs deliberately violating samples and asserts they are caught;
# that self-test runs here so a regression in the checker itself fails CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== SQL safety gate =="

# 1. Run the scanner's own self-test first: if the checker cannot detect
#    a planted violation, every "pass" below is meaningless.
echo "-- scanner self-test --"
go test ./scripts/sqlscan/ -run 'TestSelfTest' -count=1

# 2. Scan the real source tree.
echo "-- scan source --"
if out="$(go run ./scripts/sqlscan/ scan ./internal ./pkg ./cmd 2>&1)"; then
    echo "$out"
    echo "OK: no SQL construction violations found."
else
    echo "$out" >&2
    echo "FAIL: SQL construction violations detected (see above)." >&2
    exit 1
fi