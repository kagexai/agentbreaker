#!/usr/bin/env python3
"""Compatibility launcher for running AgentBreaker from repo root."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agentbreaker.cli import main  # noqa: E402


if __name__ == "__main__":
    main()
