#!/usr/bin/env python3
"""Snaffler - Python port. See README.md."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pysnaffler.main import main

if __name__ == "__main__":
    main()
