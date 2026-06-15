#!/usr/bin/env bash
set -euo pipefail

run_smoke=0
if [[ "${1:-}" == "--smoke" ]]; then
	run_smoke=1
fi

go_modules=(
	"devices/light-sim"
	"devices/lock-sim"
	"devices/sensor-sim"
	"gateway/go-api"
	"holder/go-wallet"
	"issuer/go-issuer"
	"scenarios"
)

export GOCACHE="${GOCACHE:-$PWD/.cache/go-build}"
mkdir -p "$GOCACHE"

echo "== gofmt =="
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
	echo "$unformatted"
	exit 1
fi

echo "== go test =="
for module in "${go_modules[@]}"; do
	echo "-- $module"
	( cd "$module" && go test ./... )
done

echo "== go vet =="
for module in "${go_modules[@]}"; do
	echo "-- $module"
	( cd "$module" && go vet ./... )
done

echo "== rust fmt/check/clippy/test =="
( cd gateway/rust-authz && cargo fmt --check )
( cd gateway/rust-authz && cargo check )
( cd gateway/rust-authz && cargo clippy --all-targets -- -D warnings )
( cd gateway/rust-authz && cargo test )

if [[ "$run_smoke" -eq 1 ]]; then
	echo "== scenario smoke =="
	go run ./scenarios/smoke -device "${SMOKE_DEVICE:-all}" -flow "${SMOKE_FLOW:-all}"
fi
