# Controlled Pilot quality gates

Run all gates locally:

```text
python3 -m unittest discover -s testkit/pilot -t . -p 'test_*.py'
python3 -m testkit.pilot.doctor --json
python3 -m testkit.pilot.acceptance /path/to/result.json
python3 -m testkit.pilot.run_vertical_slice
python3 -m testkit.pilot.run_gateway_slice
```

`doctor` only reports check names, error codes and recovery actions. `telemetry`
rejects nested or non-allowlisted fields. `acceptance` expects a content-free
summary produced by the integration harness; it never consumes Session content.
`run_vertical_slice` launches the fixed fake OpenCode interface, Rust Host
adapter and file-backed Go Relay, restarts Relay before consumption, then runs
Host command/idempotency and acceptance gates without writing repository state.
