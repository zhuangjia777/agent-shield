#!/usr/bin/env python3
# count file words/lines, fully local
import sys
from pathlib import Path


def count(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return {
        "chars": len(text),
        "lines": text.count("\n") + 1,
        "words": len(text.split()),
    }


if __name__ == "__main__":
    print(count(sys.argv[1]))
