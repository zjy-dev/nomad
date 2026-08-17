#!/usr/bin/env python3
"""Launch and validate the real TEST-ONLY Host/Relay/Mobile process loop."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional


REQUIRED_STEPS = {
    "pair.request",
    "pair.confirmed",
    "session.checkpoint",
    "command.deny",
    "command.result.deny",
    "command.stop",
    "command.result.stop",
    "command.allow_once",
    "done",
}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_health(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    data = json.load(response)
                    if data.get("protocol") == "TEST-ONLY/1":
                        return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"relay health timeout: {url}")


def validate_transcript(transcript: Dict) -> None:
    steps = transcript.get("steps")
    if not isinstance(steps, list):
        raise AssertionError("transcript.steps must be a list")
    names = [item.get("step") for item in steps]
    missing = sorted(REQUIRED_STEPS - set(names))
    if missing:
        raise AssertionError(f"missing transcript steps: {missing}")

    pair_request = next(item for item in steps if item.get("step") == "pair.request")
    pair_confirmed = next(item for item in steps if item.get("step") == "pair.confirmed")
    if pair_request["detail"].get("comparison_code") != pair_confirmed["detail"].get("comparison_code"):
        raise AssertionError("pair comparison code mismatch")

    checkpoint = next(item for item in steps if item.get("step") == "session.checkpoint")
    if checkpoint["detail"].get("state") != "NeedsPermission":
        raise AssertionError("checkpoint is not NeedsPermission")
    if int(checkpoint["detail"].get("diff_file_count", 0)) <= 0:
        raise AssertionError("checkpoint has no diff metadata")

    deny = next(item for item in steps if item.get("step") == "command.result.deny")
    stop = next(item for item in steps if item.get("step") == "command.result.stop")
    if deny["detail"].get("status") != "HostAccepted":
        raise AssertionError("deny was not HostAccepted")
    if stop["detail"].get("status") != "HostAccepted":
        raise AssertionError("Stop was not HostAccepted")
    if deny["detail"].get("relay_received_was") != "not_host_accepted":
        raise AssertionError("RelayReceived was conflated with HostAccepted")

    allow_entries = [item for item in steps if item.get("step") == "command.allow_once"]
    response = next((item for item in allow_entries if item.get("direction") == "relay→mobile"), None)
    if not response or response["detail"].get("status") != "Rejected":
        raise AssertionError("allow_once was not rejected")
    if response["detail"].get("error_code") != "ERR_SAFETY_BLOCKED":
        raise AssertionError("allow_once rejection code mismatch")
    if response["detail"].get("allowed") is not False:
        raise AssertionError("allow_once capability must remain false")


def terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    port = free_port()
    relay_url = f"http://127.0.0.1:{port}"
    token = "nomad-local-process-token"
    channel = "nomad-process-loop"

    with tempfile.TemporaryDirectory(prefix="nomad-process-loop-") as tmp:
        tmp_path = Path(tmp)
        transcript_path = tmp_path / "transcript.json"
        logs = {name: (tmp_path / f"{name}.log").open("w+", encoding="utf-8") for name in ("relay", "host", "mobile")}
        processes: List[subprocess.Popen] = []
        try:
            relay_cmd = [
                "go", "run", "./cmd/relay",
                "-addr", f"127.0.0.1:{port}",
                "-db", str(tmp_path / "relay.db"),
                "-enable-test-bridge",
                "-test-token", token,
            ]
            relay = subprocess.Popen(relay_cmd, cwd=repo / "relay", stdout=logs["relay"], stderr=subprocess.STDOUT, text=True)
            processes.append(relay)
            wait_health(relay_url + "/health", timeout=args.timeout)

            host_cmd = [
                "cargo", "run", "--quiet", "--bin", "process-bridge", "--",
                relay_url, token, channel,
            ]
            host = subprocess.Popen(host_cmd, cwd=repo / "connector", stdout=logs["host"], stderr=subprocess.STDOUT, text=True)
            processes.append(host)

            # Build the standalone Node bridge after main npm dependencies are installed.
            subprocess.run(["npm", "run", "build:process-bridge"], cwd=repo / "mobile-reference", check=True, timeout=args.timeout)
            mobile_cmd = [
                "node", "process-bridge/dist/cli.js",
                "--relay-url", relay_url,
                "--token", token,
                "--channel", channel,
                "--out", str(transcript_path),
            ]
            mobile = subprocess.Popen(mobile_cmd, cwd=repo / "mobile-reference", stdout=logs["mobile"], stderr=subprocess.STDOUT, text=True)
            processes.append(mobile)
            try:
                mobile.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise RuntimeError("mobile bridge timed out")
            if mobile.returncode != 0:
                raise RuntimeError(f"mobile bridge exited {mobile.returncode}")
            transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
            validate_transcript(transcript)

            output = repo / "testkit/process-loop/last-transcript.json"
            output.write_text(json.dumps(transcript, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print("PROCESS_LOOP_PASS pair checkpoint deny stop ack allow_once=false")
            print(f"transcript={output}")
            return 0
        except Exception as exc:
            for name, handle in logs.items():
                handle.flush()
                handle.seek(0)
                print(f"--- {name}.log ---\n{handle.read()}", file=sys.stderr)
            print(f"PROCESS_LOOP_FAIL: {exc}", file=sys.stderr)
            return 1
        finally:
            for process in reversed(processes):
                terminate(process)
            for handle in logs.values():
                handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
