#!/usr/bin/env python3
import argparse

from tools.asg_package import cmd_install


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install Agent Secret Guard from this package tree.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply-hooks", action="store_true", help="merge active Claude/Codex/Cursor hook configs after installing files")
    raise SystemExit(cmd_install(parser.parse_args()))
