#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

echo "[1/8] Contract conformance"
python3 "$repo_dir/testkit/conformance/run.py" --contracts-root "$repo_dir/contracts"
python3 -m unittest discover -s "$repo_dir/testkit/conformance" -p 'test_*.py'

echo "[2/8] Host reference core"
(cd "$repo_dir/connector" && cargo fmt --check && cargo test --quiet && cargo clippy --all-targets -- -D warnings)

echo "[3/8] Relay opaque mailbox"
(cd "$repo_dir/relay" && test -z "$(gofmt -l .)" && go test ./... && go test -race ./...)

echo "[4/8] Synthetic fault injection"
(cd "$repo_dir" && python3 -m unittest discover -s testkit/faults -t . -p 'test_*.py')

echo "[5/8] Synthetic session E2E"
(cd "$repo_dir" && python3 -m unittest discover -s testkit/e2e -t . -p 'test_*.py')

echo "[6/8] Mobile reference unit/build"
(cd "$repo_dir/mobile-reference" && npm ci && npm test -- --run && npm run build && npm run build:process-bridge)

echo "[7/8] Process readiness"
(cd "$repo_dir/connector" && cargo run --quiet --bin nomad-connector)

echo "[8/8] Real local process loop"
(cd "$repo_dir" && python3 testkit/process-loop/run_process_loop.py --timeout 60)

echo "LOCAL_SLICE_PASS"
echo "Scope: synthetic/disposable validation only; not Private Alpha evidence."
