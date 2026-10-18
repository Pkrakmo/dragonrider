#!/usr/bin/env python3
"""Create a disposable CI source snapshot without private research inputs."""
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
paths = subprocess.check_output(
    ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
).split(b"\0")
destination = Path(tempfile.mkdtemp(prefix="dragonrider-act-"))
allowed_roots = {".github", "apps", "include", "src", "tests", "tools"}
allowed_extensions = {".cmake", ".cpp", ".h", ".hpp", ".java", ".json", ".py", ".sh", ".yml", ".yaml"}
for raw in paths:
    if not raw:
        continue
    relative = Path(raw.decode("utf-8"))
    allowed = relative.as_posix() in {"CMakeLists.txt", "CMakePresets.json"} or (
        relative.parts[0] in allowed_roots and relative.suffix in allowed_extensions
    )
    if not allowed:
        continue
    source = root / relative
    if source.is_symlink() or not source.is_file() or any(p.is_symlink() for p in source.parents if p != root and root in p.parents):
        raise SystemExit(f"Refusing missing file or symlink: {relative}")
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
print(destination)
