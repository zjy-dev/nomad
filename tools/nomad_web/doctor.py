from __future__ import annotations

import os
import shutil
import socket
from pathlib import Path
from typing import Any

from .config import Config
from .bundle import verify_bundle

PROVIDERS = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENERATIVE_AI_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
)


def run_doctor(config: Config) -> dict[str, Any]:
    bundle_mode = config.bundle_root is not None
    tool_names = ("python3", "node") if bundle_mode else ("python3", "go", "cargo", "node", "npm")
    tools = {name: shutil.which(name) is not None for name in tool_names}
    paths = {
        "relay_source": (config.repo_root / "relay" / "cmd" / "relay").is_dir(),
        "gateway_entry": (config.repo_root / "mobile-reference" / "pilot-gateway" / "server.mjs").is_file(),
        "mobile_package": (config.repo_root / "mobile-reference" / "package.json").is_file(),
    }
    if bundle_mode:
        try:
            verify_bundle(config.bundle_root)
            paths = {"prebuilt_bundle": True}
        except Exception:
            paths = {"prebuilt_bundle": False}
    ports = {"relay": _free(config.relay_port), "gateway": _free(config.gateway_port), "agent": _free(config.agent_port)}
    provider_names = [name for name in PROVIDERS if name in os.environ]
    foundation_ready = all(tools.values()) and all(paths.values()) and all(ports.values())
    missing_tools = [name for name, present in tools.items() if not present]
    missing_paths = [name for name, present in paths.items() if not present]
    occupied_ports = [name for name, available in ports.items() if not available]
    return {
        "schema": "nomad.web-companion.doctor.v1",
        "classification": "repo-local-foundation-not-production-authority",
        "runtime_mode": "prebuilt-bundle" if bundle_mode else "source-build",
        "foundation_ready": foundation_ready,
        "real_agent_enabled": False,
        "blocked_on": ["B1_PROVIDER_CREDENTIAL", "PRODUCTION_DEVICE_IDENTITY"],
        "tools": tools,
        "paths": paths,
        "ports": ports,
        "provider_env_name_count": len(provider_names),
        "provider_env_names": provider_names,
        "missing_tools": missing_tools,
        "missing_paths": missing_paths,
        "occupied_ports": occupied_ports,
        "next_step": "nomad-web start" if foundation_ready else "repair failed preflight checks and rerun doctor",
        "production_ready": False,
    }


def _free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
