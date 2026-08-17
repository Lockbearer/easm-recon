#!/usr/bin/env python3
"""Entry shim: run easm without installing the package (adds repo to sys.path)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from easm.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
