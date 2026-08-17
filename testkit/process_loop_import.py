"""Import helper for the hyphenated process-loop script directory."""

import importlib.util
from pathlib import Path


def validate_transcript_module():
    path = Path(__file__).with_name("process-loop") / "run_process_loop.py"
    spec = importlib.util.spec_from_file_location("nomad_process_loop", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module
