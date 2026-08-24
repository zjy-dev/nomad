#!/usr/bin/env python3
"""Emit the reviewed deterministic NOMADREL parity vector as lowercase hex."""
from __future__ import annotations
import importlib.util,sys
from pathlib import Path
path=Path(__file__).with_name("test_nomadrel.py");spec=importlib.util.spec_from_file_location("nomadrel_vector_source",path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
if __name__=="__main__":print(module.vector()[0].hex())
