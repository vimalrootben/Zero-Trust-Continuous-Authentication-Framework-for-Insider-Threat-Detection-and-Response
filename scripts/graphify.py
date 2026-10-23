"""Generate local code graphs with the separately installed Graphify CLI."""
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import subprocess
import sys


def main():
    try:
        installed = version("graphifyy")
    except PackageNotFoundError:
        installed = None
    if installed != "0.9.91":
        raise SystemExit("Install the verified tool: python -m pip install graphifyy==0.9.91")
    root = Path(__file__).resolve().parents[1]
    for args in (
        ["extract", str(root), "--code-only", "--max-workers", "1"],
        ["cluster-only", str(root), "--no-label"],
        ["export", "callflow-html", str(root / "graphify-out"),
         "--output", str(root / "graphify-out" / "callflow.html")],
    ):
        subprocess.run([sys.executable, "-m", "graphify", *args], cwd=root, check=True)


if __name__ == "__main__":
    main()
