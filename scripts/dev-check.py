#!/usr/bin/env python3
"""Run focused local checks without deployment or network/device mutations."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def commands(area, dotnet=None):
    python = ROOT / ".venv/bin/python"
    if not python.exists():
        python = Path(sys.executable)
    if area == "backend":
        return [([str(python), "-m", "pytest", "backend/tests", "-q"], ROOT)]
    if area == "frontend":
        npm = shutil.which("npm")
        if not npm:
            raise SystemExit("npm is required; install Node 24 or select another area.")
        return [([npm, "test"], ROOT / "frontend"), ([npm, "run", "build"], ROOT / "frontend")]
    if area == "agent":
        binary = dotnet or os.environ.get("DOTNET_BIN") or shutil.which("dotnet")
        if not binary:
            raise SystemExit(".NET 10 is required; set DOTNET_BIN or --dotnet.")
        return [([binary, "build", "agent/src/NetworkPolicyClient.csproj", "-c", "Release"], ROOT),
                ([binary, "build", "agent/ui/Suro.Identity.UI.csproj", "-c", "Release"], ROOT),
                ([binary, "run", "--project", "agent/tests/AgentContractTests.csproj", "-c", "Release"], ROOT)]
    return [([str(python), "scripts/check_docs.py"], ROOT)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--area", choices=["backend", "frontend", "agent", "docs", "all"], required=True)
    parser.add_argument("--dotnet")
    parser.add_argument("--dry-run", action="store_true", help="Print the exact checks without running them")
    args = parser.parse_args()
    areas = ["backend", "frontend", "agent", "docs"] if args.area == "all" else [args.area]
    for area in areas:
        for command, cwd in commands(area, args.dotnet):
            print(f"[{area}] cwd={cwd.relative_to(ROOT) or '.'}: {' '.join(command)}", flush=True)
            if not args.dry_run:
                result = subprocess.run(command, cwd=cwd)
                if result.returncode:
                    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
