#!/usr/bin/env python3
import argparse
from pathlib import Path

from tools.asg_package import cmd_uninstall


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove installed Agent Secret Guard files and ASG hook entries.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--keep-active-hooks", action="store_true")
    parser.add_argument("--claude-config", default=str(Path.home() / ".claude/settings.json"))
    parser.add_argument("--codex-config", default=str(Path.home() / ".codex/hooks.json"))
    parser.add_argument("--cursor-config", default=str(Path.home() / ".cursor/hooks.json"))
    raise SystemExit(cmd_uninstall(parser.parse_args()))
