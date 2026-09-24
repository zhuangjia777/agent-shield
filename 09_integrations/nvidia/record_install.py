"""Record a verified local installation after installing requirements.lock."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "05_skill_eval"))
from nvidia_scan import package_hash

lock_path = Path(__file__).with_name("component-lock.json")
lock = json.loads(lock_path.read_text())
python = ROOT / ".venv-skillspector/bin/python"
package = Path(subprocess.check_output([str(python), "-c", "import importlib.util; print(next(iter(importlib.util.find_spec('skillspector').submodule_search_locations)))"], text=True).strip())
if not package.is_relative_to(ROOT / ".venv-skillspector"):
    raise RuntimeError("Unexpected installation path")
if package_hash(package) != lock["installed_package_sha256"]:
    raise RuntimeError("Package differs from pinned source; investigate before updating the lock")
lock["installed_package"] = package.relative_to(ROOT).as_posix()
lock_path.write_text(json.dumps(lock, indent=2) + "\n")
print("Pinned SkillSpector package verified; installation path recorded.")
