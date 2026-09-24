"""Content manifest for bounded local Skill inputs; never follow symlinks."""
import hashlib
import json
from pathlib import Path


def manifest(root: Path) -> dict:
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or not (root / "SKILL.md").is_file():
        raise ValueError("需要包含 SKILL.md 的本地目录。")
    files, total = [], 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Skill 输入不可包含符号链接。")
        if not path.is_file():
            continue
        size = path.stat().st_size
        total += size
        if size > 10_000_000 or total > 50_000_000 or len(files) >= 1000:
            raise ValueError("Skill 超过扫描大小限制。")
        content = path.read_bytes()
        files.append({"path": path.relative_to(root).as_posix(), "size": len(content),
                      "sha256": hashlib.sha256(content).hexdigest()})
    payload = json.dumps(files, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return {"dir": root.name, "files": len(files), "entries": files,
            "input_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "hash_method": "sha256(path,size,sha256(content))"}
