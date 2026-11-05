"""Launch Module 3; optional arguments are passed to its service command."""
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
from module3.__main__ import main

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "serve", *sys.argv[1:]]
    main()
