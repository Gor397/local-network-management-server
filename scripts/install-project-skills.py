#!/usr/bin/env python3
"""Expose tracked Lantern skills in a user's Codex skill directory without overwriting other skills."""
import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("lantern-development", "lantern-windows", "lantern-infrastructure")


def install(target):
    target.mkdir(parents=True, exist_ok=True)
    # Inspect every destination before making any links, to avoid a partially conflicting install.
    for name in NAMES:
        source, destination = ROOT / ".agents/skills" / name, target / name
        if not (source / "SKILL.md").is_file():
            raise SystemExit(f"Missing tracked skill: {source}")
        if destination.exists() or destination.is_symlink():
            if not destination.is_symlink() or destination.resolve() != source.resolve():
                raise SystemExit(f"Existing unrelated skill preserved: {destination}. Choose another --target.")
    for name in NAMES:
        destination = target / name
        if not destination.is_symlink():
            destination.symlink_to(ROOT / ".agents/skills" / name, target_is_directory=True)
        print(f"Available: {name} -> {destination.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "skills"
    parser.add_argument("--target", type=Path, default=default)
    install(parser.parse_args().target.expanduser())
