#!/usr/bin/env python3
"""Run the accuracy harness from repo root (system_design.md §10 & Step 6b)."""

import os
import sys

# Ensure api directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "api")))

from curator.eval.harness import evaluate_accuracy, print_cli_report

if __name__ == "__main__":
    data = evaluate_accuracy()
    print_cli_report(data)
