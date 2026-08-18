# Fake OpenCode HTTP server

This stdlib-only executable implements the fixed HTTP interface consumed by the
Controlled Pilot Host adapter. It supplies deterministic question, permission,
diff, and reconnect events and deduplicates reply, deny, and Stop by
`request_id`. It is an interface substitute, not a live OpenCode certification.

```bash
python3 testkit/fake-opencode/server.py --scenario happy
python3 -m unittest discover -s testkit/fake-opencode -p 'test_*.py' -v
```

Fail-closed scenarios are selectable with `--scenario version-mismatch`,
`unknown-event`, or `event-gap`. The server refuses non-loopback binds.
