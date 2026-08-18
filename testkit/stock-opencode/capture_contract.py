#!/usr/bin/env python3
"""Capture content-free contract facts from a running stock OpenCode server."""
from __future__ import annotations
import argparse, json, urllib.request

def get_json(base_url: str, path: str):
    with urllib.request.urlopen(f"{base_url.rstrip('/')}{path}", timeout=10.0) as response:
        return json.load(response)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:4096")
    args = parser.parse_args()
    health = get_json(args.base_url, "/global/health")
    openapi = get_json(args.base_url, "/doc")
    paths = openapi.get("paths", {})
    selected = [path for path in ("/global/health", "/event", "/session", "/session/{sessionID}", "/session/{sessionID}/diff", "/session/{sessionID}/prompt_async", "/session/{sessionID}/abort", "/session/{sessionID}/permissions/{permissionID}") if path in paths]
    schemas = openapi.get("components", {}).get("schemas", {})
    names = sorted(name for name in schemas if name in {"EventPermissionAsked", "EventPermissionReplied", "EventSessionStatus", "EventQuestionAsked"})
    content = paths.get("/event", {}).get("get", {}).get("responses", {}).get("200", {}).get("content", {})
    output = {
        "health": {"healthy": health.get("healthy"), "version": health.get("version")},
        "openapi": {"path": "/doc", "version": openapi.get("openapi"), "selected_paths": selected},
        "event_contract": {"transport": next(iter(content), None), "selected_schemas": names, "required_top_level": {name: schemas[name].get("required", []) for name in names}, "nomad_adapter_fields_present": {field: any(field in json.dumps(schemas[name]) for name in names) for field in ("seq", "timestamp", "durable")}},
    }
    print(json.dumps(output, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
