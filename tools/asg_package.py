#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404 - package commands execute fixed local tools without shell=True.
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "package_manifest.json"
HOME_TEMPLATE = "{{ASG_HOME}}"
HOOK_MARKERS = (
    "agent-secret-guard",
    "asg-fast",
    "asg-codex-hook",
    "asg-cursor-",
    "asg-hook-lib",
    "cmd-leak-guard",
    "file-leak-guard",
    "infisical-guard",
    "secret-filter",
    "secret-mcp-guard",
    "secret-push-guard",
    "secret-scan",
    "secret-url-guard",
    "secret-wrap",
)
BUILD_TIMEOUT_SECONDS = 30
LEGACY_INSTALLER_TIMEOUT_SECONDS = 120


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: unable to read JSON: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON is not an object")
    return data


def load_manifest() -> dict[str, Any]:
    manifest = load_json_object(MANIFEST_PATH)
    validate_manifest(manifest)
    return manifest


def require_string(mapping: dict[str, Any], key: str, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{MANIFEST_PATH}: {context}.{key} must be a non-empty string")
    return value


def require_string_list(mapping: dict[str, Any], key: str, context: str) -> list[str]:
    value = mapping.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{MANIFEST_PATH}: {context}.{key} must be a list of non-empty strings")
    return value


def require_entry_list(manifest: dict[str, Any], key: str, *, required: bool = False) -> list[dict[str, Any]]:
    if key not in manifest:
        if required:
            raise ValueError(f"{MANIFEST_PATH}: {key} is required")
        return []
    value = manifest[key]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{MANIFEST_PATH}: {key} must be a list of objects")
    return value


def validate_mode(value: str, context: str) -> None:
    try:
        int(value, 8)
    except ValueError as exc:
        raise ValueError(f"{MANIFEST_PATH}: {context}.mode must be an octal string") from exc


def validate_manifest(manifest: dict[str, Any]) -> None:
    for index, entry in enumerate(require_entry_list(manifest, "files", required=True)):
        context = f"files[{index}]"
        require_string(entry, "repo", context)
        require_string(entry, "live", context)
        require_string(entry, "install", context)
        validate_mode(require_string(entry, "mode", context), context)

    for index, build in enumerate(require_entry_list(manifest, "builds")):
        context = f"builds[{index}]"
        require_string(build, "source", context)
        require_string(build, "target", context)
        validate_mode(require_string(build, "mode", context), context)
        require_string_list(build, "compilers", context)
        require_string_list(build, "args", context)

    if "generated_state" not in manifest:
        raise ValueError(f"{MANIFEST_PATH}: generated_state is required")
    generated_state = manifest["generated_state"]
    if not isinstance(generated_state, list) or not all(isinstance(item, str) and item for item in generated_state):
        raise ValueError(f"{MANIFEST_PATH}: generated_state must be a list of non-empty strings")


def expand(value: str) -> Path:
    return Path(value).expanduser()


def repo_path(value: str) -> Path:
    return ROOT / value


def mode_int(value: str) -> int:
    return int(value, 8)


def executable(path: Path) -> bool:
    return path.exists() and os.access(path, os.X_OK)


def render_home_template(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return text.replace(HOME_TEMPLATE, str(Path.home())).encode("utf-8")


def normalize_home_template(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return text.replace(str(Path.home()), HOME_TEMPLATE).encode("utf-8")


def copy_atomic(
    src: Path,
    dst: Path,
    mode: int,
    *,
    dry_run: bool,
    render_home: bool = False,
    normalize_home: bool = False,
) -> bool:
    if not src.exists():
        raise FileNotFoundError(str(src))
    if dry_run:
        return True
    data = src.read_bytes()
    if render_home:
        data = render_home_template(data)
    if normalize_home:
        data = normalize_home_template(data)
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_temp = tempfile.mkstemp(prefix=f".{dst.name}.asg-tmp-", dir=str(dst.parent))
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
        temp.chmod(mode)
        os.replace(temp, dst)
    finally:
        if temp.exists():
            temp.unlink()
    return True


def write_json_atomic(path: Path, data: dict[str, Any], mode: int = 0o600) -> None:
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.asg-tmp-", dir=str(path.parent))
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as target:
            json.dump(data, target, indent=2, sort_keys=True)
            target.write("\n")
        temp.chmod(mode)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def backup(path: Path, *, dry_run: bool) -> str | None:
    if not path.exists():
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = path.with_name(f"{path.name}.asg-uninstall-backup-{stamp}")
    if not dry_run:
        shutil.copy2(path, target)
        target.chmod(0o600)
    return str(target)


def command_values(value: Any) -> list[str]:
    commands: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "command" and isinstance(child, str):
                commands.append(child)
            else:
                commands.extend(command_values(child))
    elif isinstance(value, list):
        for child in value:
            commands.extend(command_values(child))
    return commands


def has_asg_marker(value: Any) -> bool:
    return any(marker in command for marker in HOOK_MARKERS for command in command_values(value))


def prune_hook_entries(entries: Any) -> tuple[list[Any], int]:
    if not isinstance(entries, list):
        return [], 0
    kept: list[Any] = []
    removed = 0
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
            hooks = [hook for hook in entry["hooks"] if not has_asg_marker(hook)]
            removed += len(entry["hooks"]) - len(hooks)
            if hooks:
                next_entry = dict(entry)
                next_entry["hooks"] = hooks
                kept.append(next_entry)
            else:
                removed += 1
            continue
        if has_asg_marker(entry):
            removed += 1
            continue
        kept.append(entry)
    return kept, removed


def remove_active_hooks(path: Path, *, dry_run: bool) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "present": False, "changed": False, "removed": 0}
    try:
        data = load_json_object(path)
    except ValueError as exc:
        return {"path": str(path), "present": True, "changed": False, "removed": 0, "error": str(exc)}
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return {"path": str(path), "present": True, "changed": False, "removed": 0}

    removed = 0
    for event, entries in list(hooks.items()):
        next_entries, event_removed = prune_hook_entries(entries)
        removed += event_removed
        hooks[event] = next_entries
    changed = removed > 0
    backup_path = None
    try:
        backup_path = backup(path, dry_run=dry_run) if changed else None
        if changed and not dry_run:
            write_json_atomic(path, data)
    except OSError as exc:
        return {
            "path": str(path),
            "present": True,
            "changed": False,
            "removed": 0,
            "backup_path": backup_path,
            "error": f"{path}: unable to update hooks: {exc.strerror}",
        }
    return {
        "path": str(path),
        "present": True,
        "changed": changed,
        "removed": removed,
        "backup_path": backup_path,
    }


def cmd_inventory(_: argparse.Namespace) -> int:
    manifest = load_manifest()
    files = []
    for entry in manifest["files"]:
        files.append(
            {
                "repo": entry["repo"],
                "repo_present": repo_path(entry["repo"]).exists(),
                "live": entry["live"],
                "live_present": expand(entry["live"]).exists(),
                "install": entry["install"],
            }
        )
    print(json.dumps({"ok": True, "root": str(ROOT), "files": files}, indent=2, sort_keys=True))
    return 0


def cmd_consolidate(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    missing: list[str] = []
    copied: list[str] = []
    for entry in manifest["files"]:
        live = expand(entry["live"])
        target = repo_path(entry["repo"])
        if not live.exists():
            missing.append(str(live))
            continue
        copy_atomic(live, target, mode_int(entry["mode"]), dry_run=args.dry_run, normalize_home=True)
        copied.append(entry["repo"])
    result = {"ok": not missing, "mode": "dry-run" if args.dry_run else "apply", "copied": copied, "missing": missing}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not missing else 1


def build_fast_client(build: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    source = repo_path(build["source"])
    target = expand(build["target"])
    compiler = next((shutil.which(name) for name in build["compilers"] if shutil.which(name)), None)
    result = {"source": str(source), "target": str(target), "compiler": compiler, "built": False}
    if not source.exists():
        result["error"] = "missing-source"
        return result
    if not compiler:
        result["error"] = "missing-compiler"
        return result
    if dry_run:
        result["built"] = True
        result["dry_run"] = True
        return result
    target.parent.mkdir(parents=True, exist_ok=True)
    source_data = source.read_bytes()
    rendered_source = render_home_template(source_data)
    temp_source: Path | None = None
    temp_target: Path | None = None
    compile_source = source
    if rendered_source != source_data:
        fd, raw_temp = tempfile.mkstemp(prefix="asg-fast-rendered-", suffix=".c")
        temp_source = Path(raw_temp)
        with os.fdopen(fd, "wb") as handle:
            handle.write(rendered_source)
        compile_source = temp_source
    try:
        fd, raw_temp = tempfile.mkstemp(prefix=f".{target.name}.asg-build-", dir=str(target.parent))
        os.close(fd)
        temp_target = Path(raw_temp)
        try:
            proc = subprocess.run(  # nosec B603 - compiler path is selected from the package manifest; shell is never used.
                [compiler, *build["args"], "-o", str(temp_target), str(compile_source)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=BUILD_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            result["error"] = "compile-timeout"
            result["returncode"] = 124
            result["timeout_seconds"] = BUILD_TIMEOUT_SECONDS
            return result
        result["built"] = proc.returncode == 0
        result["returncode"] = proc.returncode
        if proc.returncode == 0:
            temp_target.chmod(mode_int(build["mode"]))
            os.replace(temp_target, target)
            temp_target = None
    finally:
        if temp_source and temp_source.exists():
            temp_source.unlink()
        if temp_target and temp_target.exists():
            temp_target.unlink()
    return result


def cmd_install(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    missing = [entry["repo"] for entry in manifest["files"] if not repo_path(entry["repo"]).exists()]
    if missing:
        print(json.dumps({"ok": False, "error": "package-files-missing", "missing": missing}, indent=2, sort_keys=True))
        return 1

    installed = []
    for entry in manifest["files"]:
        copy_atomic(
            repo_path(entry["repo"]),
            expand(entry["install"]),
            mode_int(entry["mode"]),
            dry_run=args.dry_run,
            render_home=True,
        )
        installed.append(entry["install"])

    builds = [build_fast_client(build, dry_run=args.dry_run) for build in manifest.get("builds", [])]
    build_ok = all(item.get("built") for item in builds)
    legacy_installer = expand("~/.local/bin/agent-secret-guard-install")
    legacy_result: dict[str, Any] = {"skipped": True}
    if not args.dry_run and build_ok and executable(legacy_installer):
        legacy_args = [str(legacy_installer)]
        if args.apply_hooks:
            legacy_args.append("--apply")
        try:
            proc = subprocess.run(  # nosec B603 - legacy installer path is fixed under ~/.local/bin; shell is never used.
                legacy_args,
                text=True,
                capture_output=True,
                check=False,
                timeout=LEGACY_INSTALLER_TIMEOUT_SECONDS,
            )
            legacy_result = {"returncode": proc.returncode, "stdout_bytes": len(proc.stdout), "stderr_bytes": len(proc.stderr)}
        except subprocess.TimeoutExpired as exc:
            legacy_result = {
                "returncode": 124,
                "stdout_bytes": len(exc.stdout or ""),
                "stderr_bytes": len(exc.stderr or ""),
                "timeout": True,
                "timeout_seconds": LEGACY_INSTALLER_TIMEOUT_SECONDS,
            }

    ok = build_ok and (args.dry_run or legacy_result.get("returncode", 0) == 0)
    print(
        json.dumps(
            {
                "ok": ok,
                "mode": "dry-run" if args.dry_run else "apply",
                "installed": installed,
                "builds": builds,
                "legacy_installer": legacy_result,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if ok else 1


def remove_path(path: Path, *, dry_run: bool) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    if dry_run:
        return True
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
    return True


def cmd_uninstall(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    removed: list[str] = []
    for entry in reversed(manifest["files"]):
        target = expand(entry["install"])
        if remove_path(target, dry_run=args.dry_run):
            removed.append(str(target))
    for build in manifest.get("builds", []):
        target = expand(build["target"])
        if remove_path(target, dry_run=args.dry_run):
            removed.append(str(target))

    for raw_path in manifest.get("generated_state", []):
        if raw_path.startswith("**/"):
            continue
        path = expand(raw_path)
        if remove_path(path, dry_run=args.dry_run):
            removed.append(str(path))

    hook_results = []
    if not args.keep_active_hooks:
        for raw in (args.claude_config, args.codex_config, args.cursor_config):
            hook_results.append(remove_active_hooks(Path(raw).expanduser(), dry_run=args.dry_run))
    ok = not any("error" in result for result in hook_results)

    print(
        json.dumps(
            {
                "ok": ok,
                "mode": "dry-run" if args.dry_run else "apply",
                "removed": removed,
                "active_hooks": hook_results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if ok else 1


def cmd_verify_layout(_: argparse.Namespace) -> int:
    manifest = load_manifest()
    missing = [entry["repo"] for entry in manifest["files"] if not repo_path(entry["repo"]).exists()]
    source_runtime = [path for path in manifest["generated_state"] if path.startswith("~/.local/state") or path.startswith("~/.local/run")]
    hardcoded_home = []
    home = str(Path.home())
    for entry in manifest["files"]:
        path = repo_path(entry["repo"])
        if not path.exists():
            continue
        try:
            if home in path.read_text(encoding="utf-8"):
                hardcoded_home.append(entry["repo"])
        except UnicodeDecodeError:
            continue
    result = {
        "ok": not missing and bool(source_runtime) and not hardcoded_home,
        "missing": missing,
        "hardcoded_home": hardcoded_home,
        "generated_state_rules": manifest["generated_state"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Package, install, and uninstall Agent Secret Guard from one source tree.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("inventory").set_defaults(func=cmd_inventory)

    consolidate = sub.add_parser("consolidate", help="copy current live ASG files into this package tree")
    consolidate.add_argument("--dry-run", action="store_true")
    consolidate.set_defaults(func=cmd_consolidate)

    install = sub.add_parser("install", help="install ASG from this package tree")
    install.add_argument("--dry-run", action="store_true")
    install.add_argument("--apply-hooks", action="store_true", help="merge active Claude/Codex/Cursor hook configs after installing files")
    install.set_defaults(func=cmd_install)

    uninstall = sub.add_parser("uninstall", help="remove installed ASG files and ASG hook entries")
    uninstall.add_argument("--dry-run", action="store_true")
    uninstall.add_argument("--keep-active-hooks", action="store_true")
    uninstall.add_argument("--claude-config", default=str(Path.home() / ".claude/settings.json"))
    uninstall.add_argument("--codex-config", default=str(Path.home() / ".codex/hooks.json"))
    uninstall.add_argument("--cursor-config", default=str(Path.home() / ".cursor/hooks.json"))
    uninstall.set_defaults(func=cmd_uninstall)

    sub.add_parser("verify-layout").set_defaults(func=cmd_verify_layout)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
