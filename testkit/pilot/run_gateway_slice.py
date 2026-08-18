#!/usr/bin/env python3
"""Run the real compatibility server, Relay, Host bridge and same-origin Gateway."""
from __future__ import annotations
import argparse, json, secrets, socket, subprocess, tempfile, time, urllib.error, urllib.request
from pathlib import Path

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); return sock.getsockname()[1]

def wait(url, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status < 500: return
        except Exception: time.sleep(.1)
    raise RuntimeError(f"service timeout: {url}")

def http_json(url, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="GET" if data is None else "POST")
    with urllib.request.urlopen(request, timeout=10) as response: return response.status, json.load(response)

def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try: process.wait(5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(5)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(); repo = args.repo.resolve()
    relay_port, gateway_port = port(), port(); token = secrets.token_urlsafe(24); channel = "pilot-gateway-slice"
    processes = []; logs = []
    with tempfile.TemporaryDirectory(prefix="nomad-gateway-slice-") as temp_name:
        temp = Path(temp_name)
        try:
            def launch(command, cwd, name):
                handle = (temp / f"{name}.log").open("w+", encoding="utf-8"); logs.append(handle)
                process = subprocess.Popen(command, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT, text=True); processes.append(process); return process
            launch(["python3", "testkit/fake-opencode/server.py"], repo, "compat")
            wait("http://127.0.0.1:4096/global/health")
            relay_url = f"http://127.0.0.1:{relay_port}"
            launch(["go", "run", "./cmd/relay", "-addr", f"127.0.0.1:{relay_port}", "-db", str(temp / "relay.db"), "-enable-test-bridge", "-test-token", token], repo / "relay", "relay")
            wait(f"{relay_url}/health")
            host_command = ["cargo", "run", "--quiet", "--bin", "pilot-host-bridge", "--", "--relay-url", relay_url, "--relay-token", token, "--channel", channel, "--journal", str(temp / "host.db")]
            host = launch(host_command, repo / "connector", "host")
            subprocess.run(["npm", "run", "build"], cwd=repo / "mobile-reference", check=True, capture_output=True, text=True)
            gateway_url = f"http://127.0.0.1:{gateway_port}"
            launch(["node", "pilot-gateway/server.mjs", "--host", "127.0.0.1", "--port", str(gateway_port), "--relay-url", relay_url, "--relay-token", token, "--channel", channel], repo / "mobile-reference", "gateway")
            wait(f"{gateway_url}/api/pilot/session")
            _, session = http_json(f"{gateway_url}/api/pilot/session")
            assert session["state"]["session"]["turn_state"] == "NeedsPermission"
            assert session["changes"]["status"] == "invalid"  # no verified baseline yet
            command = {"command_type": "stop", "request_id": "req-gateway-stop", "session_id": "pilot-session", "seq": 7, "target_turn_id": "turn-1"}
            status, received = http_json(f"{gateway_url}/api/pilot/commands", command)
            assert status == 202 and received["status"] == "RelayReceived"
            deadline = time.monotonic() + 20; result = None
            while time.monotonic() < deadline:
                _, result = http_json(f"{gateway_url}/api/pilot/commands/req-gateway-stop")
                if result["status"] != "RelayReceived": break
                time.sleep(.2)
            assert result and result["status"] == "HostAccepted"
            stop(host)
            # Re-deliver the same request after a real Host restart. Journal and
            # stable result IDs must keep the operation idempotent.
            host = launch(host_command, repo / "connector", "host-restart")
            status, replay_received = http_json(f"{gateway_url}/api/pilot/commands", command)
            assert status == 202 and replay_received["status"] == "RelayReceived"
            deadline = time.monotonic() + 20; replay = None
            while time.monotonic() < deadline:
                _, replay = http_json(f"{gateway_url}/api/pilot/commands/req-gateway-stop")
                if replay["status"] != "RelayReceived": break
                time.sleep(.2)
            assert replay and replay["status"] == "HostAccepted"
            print(json.dumps({"ok": True, "gate": "GATEWAY_HOST_RELAY_SLICE", "session": "NeedsPermission", "changes": "invalid_without_baseline", "initial": "RelayReceived", "host": result["status"], "host_restart_replay": replay["status"]}, sort_keys=True))
            return 0
        except Exception:
            for handle in logs:
                handle.flush(); handle.seek(0); print(handle.read())
            raise
        finally:
            for process in reversed(processes): stop(process)
            for handle in logs: handle.close()

if __name__ == "__main__": raise SystemExit(main())
