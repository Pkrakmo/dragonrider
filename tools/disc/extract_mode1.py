#!/usr/bin/env python3
import sys
from pathlib import Path

def extract(source, destination):
    source = Path(source)
    destination = Path(destination)
    if source.stat().st_size % 2352:
        raise ValueError("Invalid raw sector length")

    with source.open("rb") as src, destination.open("wb") as dst:
        while sector := src.read(2352):
            if sector[:12] != b"\x00" + b"\xff" * 10 + b"\x00":
                raise ValueError("Invalid sector sync pattern")
            if sector[15] != 1:
                raise ValueError("Not a Mode 1 sector")
            dst.write(sector[16:2064])

if __name__ == "__main__":
    extract(sys.argv[1], sys.argv[2])
