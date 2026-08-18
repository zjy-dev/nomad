# Stock OpenCode 1.18.16 Certification Report

| Field | Result |
| --- | --- |
| Package | official npm opencode-ai@1.18.16 installed in a temporary directory |
| Server | stock opencode serve --pure --hostname 127.0.0.1 --port 4096 |
| Verdict | NO-GO for the current Nomad HTTP adapter contract |
| Data | health, OpenAPI and an empty Session list only; no Provider credential or user task |

## Verified stock facts

- The official binary prints version 1.18.16.
- GET /global/health returns healthy=true and version=1.18.16.
- OpenAPI JSON is served from GET /doc; GET /openapi.json serves the Web UI HTML.
- GET /session returns a Session list; the disposable empty workspace returned an empty list.
- GET /event is an unbounded text/event-stream. The first stock event was server.connected with id, type and properties.
- Permission lifecycle is permission.asked/replied and question lifecycle includes question.asked.

## Adapter incompatibility

The Nomad compatibility adapter expects a finite capture containing positive
contiguous seq, timestamp, durable, sessionID, turnID and data. Stock 1.18.16
events expose id, type and properties; stock OpenAPI does not provide Nomad
seq, timestamp or durable. Stock /event is an observation stream, not the
adapter's finite session/after replay contract. The fake server is therefore a
Nomad compatibility interface substitute, not a stock OpenCode emulator.

## Permission and diff status

No Provider credential or real task was used, so this run did not produce a
pending permission, workspace diff or Stop lifecycle. PRD-207 remains No-Go
until a disposable real task creates permission.asked, the same request is
rejected through the stock endpoint, and permission.replied or an authoritative
snapshot confirms the winner.

## Required rework

1. Consume stock id/type/properties and assign Host-owned monotonic Nomad seq transactionally.
2. Recover final state from stock Session/message/permission/diff snapshots instead of assuming upstream replay.
3. Map stock permission/question/status/message/tool events with unknown events fail closed.
4. Capture a disposable real question, permission, diff, Stop and reconnect before changing the verdict.

## Reproduction

    temp_dir=$(mktemp -d)
    npm install --prefix "$temp_dir" opencode-ai@1.18.16
    "$temp_dir/node_modules/.bin/opencode" serve --pure --hostname 127.0.0.1 --port 4096
    python3 testkit/stock-opencode/capture_contract.py

The script records only version, selected route names and schema field presence.
