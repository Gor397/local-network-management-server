#!/usr/bin/env python3
"""Check repository documentation links and project skill entry points."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    files = [root / "README.md", root / "AGENTS.md"]
    files += sorted((root / "docs").rglob("*.md"))
    files += sorted((root / ".agents/skills").rglob("SKILL.md"))
    errors = []
    for file in files:
        if not file.is_file():
            errors.append(f"Missing documentation: {file.relative_to(root)}")
            continue
        text = file.read_text(encoding="utf-8")
        # Link targets only; anchor-only references and URLs are outside this filesystem check.
        for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", text):
            raw = match.group(1).strip().strip("<>")
            parsed = urlparse(raw)
            if parsed.scheme or raw.startswith("#"):
                continue
            target = (file.parent / unquote(parsed.path)).resolve()
            if not target.exists():
                line = text[:match.start()].count("\n") + 1
                errors.append(f"{file.relative_to(root)}:{line}: missing {raw}")
        if file.name == "SKILL.md":
            if not text.startswith("---\n") or len(text.split("---", 2)) < 3:
                errors.append(f"{file.relative_to(root)}: missing skill frontmatter")
            elif not all(re.search(rf"^{field}:\s*\S", text.split("---", 2)[1], re.M) for field in ("name", "description")):
                errors.append(f"{file.relative_to(root)}: incomplete skill metadata")
            if re.search(r"\bTODO\b|\[INSERT|\[PLACEHOLDER", text):
                errors.append(f"{file.relative_to(root)}: unfinished skill scaffold")
        if text.count("```") % 2:
            errors.append(f"{file.relative_to(root)}: unmatched fenced block")
    return errors, len(files)


if __name__ == "__main__":
    errors, count = check()
    for error in errors:
        print(error, file=sys.stderr)
    print(f"Checked {count} documentation/skill files; {len(errors)} errors.")
    raise SystemExit(bool(errors))
