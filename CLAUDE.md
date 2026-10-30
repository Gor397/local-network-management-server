@AGENTS.md

## Claude Code notes

- The shared skills are linked under `.claude/skills/` (symlinks to `.agents/skills/`); edit the originals.
- `.claude/settings.json` denies reading `.env`/`data/` and commands that change host networking, and asks before `sudo`, `nmcli`, `docker compose` and the deployment scripts. Do not work around these rules.
- Another agent (Codex) may edit this working tree. If files change unexpectedly between commands, stop and tell the user instead of overwriting them.
