#!/usr/bin/env bash
# release.sh — release assembly and the pre-delivery audit gate.
#
# P12 (DESIGN.md §22.2): "三平台可安装运行；审计报告出具有结论".
# This script is the *gate runner*, not the auditor — the audit itself
# (A2, a full security audit before delivery) must produce the report
# this script references.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-dev}"
DIST="$ROOT/dist"
RELEASES="$DIST/releases"
AUDIT_REPORT="docs/security-audit-report.md"

cmd_package() {
    mkdir -p "$RELEASES"

    # Only package the six matrix targets (matching the CI build matrix).
    local goos goarch ext name
    for pair in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64" "windows arm64"; do
        set -- $pair
        goos=$1; goarch=$2
        ext=""; [ "$goos" = windows ] && ext=".exe"
        name="gop2pmesh-${goos}-${goarch}"
        stage="$RELEASES/$name"
        mkdir -p "$stage"
        cp "$DIST/bin/gop2pmesh-server-${goos}-${goarch}${ext}" "$stage/gop2pmesh-server${ext}"
        cp "$DIST/bin/gop2pmesh-client-${goos}-${goarch}${ext}" "$stage/gop2pmesh-client${ext}"
        cp configs/server.ini.example configs/client.ini.example README.md LICENSE "$stage/"
        # Flat tar so the archive extracts into the current directory.
        tar -C "$stage" -czf "$RELEASES/${name}-${VERSION}.tar.gz" .
        echo "packaged $RELEASES/${name}-${VERSION}.tar.gz"
    done

    ( cd "$RELEASES" && sha256sum *-"${VERSION}".tar.gz > "SHA256SUMS-${VERSION}.txt" )
    echo "checksums: $RELEASES/SHA256SUMS-${VERSION}.txt"
}

cmd_audit() {
    echo "== pre-delivery audit gate (A2) =="

    # 1. Formatting — the minimum bar; a repo that cannot gofmt has no
    #    business being audited.
    if ! out="$(gofmt -l cmd internal pkg scripts)"; then
        echo "gofmt failed" >&2; exit 1
    fi
    if [ -n "$out" ]; then
        echo "gofmt needed on:" >&2
        echo "$out" >&2
        exit 1
    fi
    echo "OK: gofmt clean"

    # 2. Static analysis.
    CGO_ENABLED=0 go vet ./...
    echo "OK: go vet"

    # 3. Tests — including the security-relevant invariant tests
    #    (I4 SQL gate, I7 room salting, I8 ID conflicts, I10 scan defence,
    #    chain verification in crypto).
    CGO_ENABLED=0 go test ./...
    echo "OK: go test"

    # 4. The SQL safety scanner, with its self-test so a broken checker
    #    fails the gate instead of rubber-stamping.
    bash scripts/check-sql.sh
    echo "OK: SQL safety gate"

    # 5. Secret scan: refuse to ship credentials in examples or code.
    if grep -rniE 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' configs cmd internal pkg >/dev/null 2>&1; then
        echo "FAIL: private key material found in the tree" >&2
        exit 1
    fi
    echo "OK: no key material in the tree"

    # 6. The audit report itself is the deliverable (A2): it must exist
    #    and carry a conclusion. The release refuses to proceed without it.
    if [ ! -f "$AUDIT_REPORT" ]; then
        cat >&2 <<EOF
FAIL: $AUDIT_REPORT missing.

P12 requires a *concluded* security audit before delivery (A2: "交付前完整
安全审计"). Run the audit, record findings and verdicts in that file, then
re-run this gate.
EOF
        exit 1
    fi
    if ! grep -qiE '结论|conclusion|verdict' "$AUDIT_REPORT"; then
        echo "FAIL: audit report carries no conclusion" >&2
        exit 1
    fi
    echo "OK: audit report present with conclusion: $AUDIT_REPORT"
    echo "== audit gate passed =="
}

case "${1:-}" in
    package) cmd_package ;;
    audit)   cmd_audit ;;
    *)
        echo "usage: $0 {package|audit}" >&2
        exit 2
        ;;
esac