#!/usr/bin/env python3
"""
Agent Secret Guard: portable local secret detection, blocking, and redaction.

Design constraints:
- no network calls
- no third-party runtime dependencies
- no secret values in JSON findings or denial reasons
- usable from any agent harness that can pipe text/JSON through a command
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import contextlib
import hashlib
import hmac
import html
import io
import json
import math
import os
import shutil
import re
import secrets
import shlex
import socket
import socketserver
import struct
import subprocess  # nosec B404 - this CLI intentionally wraps local tools without shell=True.
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit


DEFAULT_REDACT_THRESHOLD = 0.65
DEFAULT_BLOCK_THRESHOLD = 0.8
MAX_DECODE_DEPTH = 2
DEFAULT_CORPUS = Path.home() / ".local/share/agent-secret-guard/eval-corpus.json"
DEFAULT_FINGERPRINT_KEY = Path.home() / ".local/share/agent-secret-guard/fingerprint.key"
DEFAULT_HOOK_TELEMETRY = Path.home() / ".local/state/agent-secret-guard/hook-events.jsonl"
DEFAULT_SOCKET = Path.home() / ".local/run/agent-secret-guard/asg.sock"
DEFAULT_PID = Path.home() / ".local/run/agent-secret-guard/asg.pid"
DEFAULT_DAEMON_WORKER_TIMEOUT = 1.5
HOOK_TELEMETRY_MAX_BYTES = 512 * 1024
DAEMON_HEADER_LIMIT = 64 * 1024
DAEMON_BODY_LIMIT = 64 * 1024 * 1024
DAEMON_HEADER_STRUCT = struct.Struct("!IQ")
DAEMON_RESPONSE_STRUCT = struct.Struct("!IIQ")
DAEMON_STATE = threading.local()
DAEMON_ENV_OVERRIDES = {"ASG_HOOK_TELEMETRY_PATH", "ASG_DISABLE_HOOK_TELEMETRY"}
ESCAPE_SEQUENCE_RE = re.compile(r"(?:\\\\|\\)(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{3})")
ESCAPED_SEQUENCE_RUN_RE = re.compile(r"(?:(?:\\\\|\\)(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{3})){8,}")
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))|\x9b[0-?]*[ -/]*[@-~]")
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?[A-Za-z_][A-Za-z0-9_]*['\"]?")
RECONSTRUCTION_HINT_RE = re.compile(
    r"sk|proj-|github_pat_|gh[pousr]_|gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|agent|wt|soat|ffct)-|"
    r"xox|SG\.|sg\.|npm_|pypi-|hf_|vc[piarck]_|cf(?:k|ut|at)_|lin_(?:api|oauth)_|ntn_|"
    r"sntrys_|hvs\.|dp\.st\.|PMAK-|pmak-"
)
CHUNKED_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"([A-Za-z0-9._~+/=-]{2,24}(?:(?:[ \t:]+)[A-Za-z0-9._~+/=-]{2,32}){2,})"
    r"(?![A-Za-z0-9_])"
)
HTML_ENTITY_CANDIDATE_RE = re.compile(
    r"(?:[A-Za-z0-9._~:/?#\[\]@!$'()*+,;=%-]|&(?:#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});){16,}"
)
PERCENT_ENCODED_RUN_RE = re.compile(r"(?:(?:%[0-9A-Fa-f]{2})){8,}")
HEX_ENCODED_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){12,}(?![0-9A-Fa-f])")


def emit(*values: Any, sep: str = " ", end: str = "\n", file: Any = None, flush: bool = False) -> None:
    stream = sys.stdout if file is None else file
    stream.write(sep.join(str(value) for value in values))
    stream.write(end)
    if flush:
        stream.flush()


def asg_env(name: str, default: str = "") -> str:
    overrides = getattr(DAEMON_STATE, "env", None)
    if isinstance(overrides, dict) and name in overrides:
        return str(overrides[name])
    return os.environ.get(name, default)


def hook_telemetry_path() -> Path:
    configured = asg_env("ASG_HOOK_TELEMETRY_PATH")
    return Path(configured).expanduser() if configured else DEFAULT_HOOK_TELEMETRY


def hook_telemetry_disabled() -> bool:
    value = asg_env("ASG_DISABLE_HOOK_TELEMETRY")
    return value.lower() in {"1", "true", "yes", "on"}


def record_hook_observation(harness: str, event: str) -> None:
    if hook_telemetry_disabled():
        return
    safe_harness = harness if harness in PRIMARY_HARNESSES else "unknown"
    allowed_events = {
        "claude": set(CLAUDE_HOOK_MARKERS),
        "codex": set(CODEX_HOOK_EVENTS),
        "cursor": set(CURSOR_HOOK_EVENTS),
    }.get(safe_harness, set())
    safe_event = event if event in allowed_events else "unknown"
    path = hook_telemetry_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        if path.exists() and path.stat().st_size > HOOK_TELEMETRY_MAX_BYTES:
            path.unlink()
        line = json.dumps(
            {"ts": round(time.time(), 3), "harness": safe_harness, "event": safe_event},
            separators=(",", ":"),
            sort_keys=True,
        ) + "\n"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
        path.chmod(0o600)
    except Exception:
        return


def hook_observation_summary(path: Path | None = None, *, window_seconds: int = 7 * 24 * 60 * 60) -> dict[str, Any]:
    telemetry_path = path or hook_telemetry_path()
    result: dict[str, Any] = {
        "path": str(telemetry_path),
        "present": telemetry_path.exists(),
        "window_seconds": window_seconds,
        "events": {},
    }
    if not telemetry_path.exists():
        return result

    cutoff = time.time() - window_seconds
    events: dict[str, dict[str, Any]] = {}
    try:
        lines = telemetry_path.read_text(encoding="utf-8", errors="replace").splitlines()[-5000:]
    except Exception as exc:
        result["error"] = exc.__class__.__name__
        return result

    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = row.get("ts")
        harness = row.get("harness")
        event = row.get("event")
        if not isinstance(ts, (int, float)) or not isinstance(harness, str) or not isinstance(event, str):
            continue
        if ts < cutoff:
            continue
        key = f"{harness}:{event}"
        item = events.setdefault(key, {"harness": harness, "event": event, "count": 0, "last_seen": 0.0})
        item["count"] += 1
        item["last_seen"] = max(float(item["last_seen"]), float(ts))
    result["events"] = events
    return result


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    confidence: float
    reason: str

    def public(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "confidence": round(self.confidence, 3),
            "span": {"start": self.start, "end": self.end},
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RegexDetector:
    kind: str
    pattern: re.Pattern[str]
    confidence: float
    reason: str
    group: int = 0
    validator: Any = None


@dataclass(frozen=True)
class CommandRule:
    kind: str
    name: str
    pattern: re.Pattern[str]
    reason: str
    confidence: float = 0.91


@dataclass(frozen=True)
class PathRule:
    kind: str
    name: str
    pattern: re.Pattern[str]
    reason: str
    confidence: float = 0.93


@dataclass(frozen=True)
class StaticString:
    value: str
    spans: tuple[tuple[int, int], ...]


SENSITIVE_KEY_RE = re.compile(
    r"(?ix)"
    r"(^|[_\-.])("
    r"api[_\-.]?key|apikey|secret|secretkey|token|password|passwd|pwd|"
    r"credential|credentials|private[_\-.]?key|auth|bearer|"
    r"access[_\-.]?token|refresh[_\-.]?token|session[_\-.]?secret|"
    r"signing[_\-.]?key|encryption[_\-.]?key|client[_\-.]?secret|"
    r"webhook[_\-.]?secret|database[_\-.]?url|db[_\-.]?url"
    r")([_\-.]|$)"
)
SENSITIVE_KEY_WORD_RE = re.compile(
    r"(?i)("
    r"api|apikey|key|secret|token|password|passwd|pwd|credential|credentials|"
    r"private|auth|bearer|access|refresh|session|signing|encryption|client|"
    r"webhook|database|db|connection|string"
    r")"
)

PLACEHOLDER_RE = re.compile(
    r"(?ix)^("
    r"your[_\-. -]?.*|replace[_\-. -]?me|insert[_\-. -]?here|"
    r"change[_\-. -]?me|changeme|todo|tbd|null|none|undefined|"
    r"example|sample|dummy|fake|test|testing|secret|password|token|"
    r"api[_\-. -]?key|x{4,}|0{4,}|1{4,}|1234567890|"
    r"abc123|abcdefghijklmnopqrstuvwxyz|abcdefghijklmnop|"
    r"<[^>]+>|\$\{[^}]+\}|process\.env\..*|import\.meta\.env\..*"
    r")$"
)
ASG_REDACTION_MARKER_RE = re.compile(r"^(?:[A-Za-z0-9_.-]+[:=])*\[REDACTED:[A-Z][A-Z0-9_:-]*\]?$")

COMMON_EXAMPLE_TOKENS = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
    "ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
    "4111111111111111",
    "4242424242424242",
    "5555555555554444",
    "378282246310005",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def character_classes(value: str) -> int:
    classes = 0
    classes += any(char.islower() for char in value)
    classes += any(char.isupper() for char in value)
    classes += any(char.isdigit() for char in value)
    classes += any(not char.isalnum() for char in value)
    return classes


def is_sequential(value: str) -> bool:
    lowered = value.lower()
    sequences = (
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "01234567890123456789",
        "98765432109876543210",
    )
    return any(len(lowered) >= 8 and lowered in seq for seq in sequences)


def is_hex_digest(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value))


def is_uuid(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            value,
        )
    )


def normalize_candidate(value: str) -> str:
    return value.strip().strip("\"'`").rstrip(".,;)]}")


def is_placeholder(value: str) -> bool:
    normalized = normalize_candidate(value)
    return (
        not normalized
        or normalized in COMMON_EXAMPLE_TOKENS
        or bool(ASG_REDACTION_MARKER_RE.fullmatch(normalized))
        or bool(PLACEHOLDER_RE.fullmatch(normalized))
    )


def is_prefixed_placeholder(value: str) -> bool:
    normalized = normalize_candidate(value).lower()
    prefixes = (
        "sk-proj-",
        "sk-admin-",
        "sk-svcacct-",
        "sk-or-",
        "sk-ant-",
        "github_pat_",
        "ghp_",
        "glpat-",
        "gloas-",
        "gldt-",
        "glrt-",
        "glrtr-",
        "glcbt-",
        "glptt-",
        "glft-",
        "glimt-",
        "glagent-",
        "glwt-",
        "glsoat-",
        "glffct-",
        "shpat_",
        "shpca_",
        "shppa_",
        "shpss_",
        "xoxb-",
        "sk_live_",
        "rk_live_",
        "whsec_",
        "sq0atp-",
        "sq0csp-",
        "sg.",
        "re_",
        "npm_",
        "pypi-",
        "dckr_pat_",
        "sb_secret_",
        "sb_publishable_",
        "hf_",
        "vca_",
        "vcp_",
        "cfut_",
        "cfat_",
        "lin_api_",
        "lin_oauth_",
        "ntn_",
        "sntrys_",
        "hvs.",
        "tr_dev_",
        "tr_prod_",
        "glsa_",
        "dp.st.",
        "dp.pt.",
        "dp.ct.",
        "dp.sa.",
        "dp.scim.",
        "dp.audit.",
        "fio-u-",
        "sk.eyj",
        "pmak-",
        "pplx-",
        "r8_",
        "tskey-api-",
        "tskey-auth-",
        "tskey-client-",
        "tskey-scim-",
        "tskey-webhook-",
        "dop_v1_",
        "doo_v1_",
        "dor_v1_",
        "nfp",
        "nfc",
        "nfo",
        "nfu",
        "nfb",
        "bkaa_",
        "bkaj_",
        "bkar_",
        "bkct_",
        "bkpt_",
        "bkpat_",
        "bkps_",
        "bkua_",
        "ccipat_",
        "cciprj_",
        "pul-",
        "atatt3",
        "pscale_tkn_",
        "pscale_oauth_",
        "pscale_pw_",
        "pnu_",
        "pnb_",
        "hrku-aa",
        "dapi",
        "sgp_",
        "duffel_test_",
        "duffel_live_",
        "tvly-",
        "nvapi-",
        "lsv2_pt_",
        "lsv2_sk_",
        "lsv2_",
        "jina_",
        "sk-lf-",
        "pk-lf-",
        "pcsk_",
        "sk_ssemble_",
        "fc-",
        "crsr_",
        "ovsxat_",
        "ovsxat-",
        "ovsxp_",
        "ovsxp-",
        "ek_live_",
        "ek_test_",
        "bitwat_",
        "signkey-",
        "sk-inn-api-",
    )
    marker_words = {"your", "placeholder", "example", "sample", "dummy", "docs", "doc", "here", "replace", "changeme", "invalid", "xxxx"}
    for prefix in prefixes:
        if normalized.startswith(prefix):
            suffix = normalized[len(prefix):]
            words = set(re.sub(r"[^a-z0-9]+", " ", suffix).split())
            return suffix.strip(".-_") == "" or bool(words & marker_words) or "invalid" in suffix
    return False


def is_incomplete_known_provider_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    return bool(
        re.fullmatch(r"github_pat_[A-Za-z0-9_]{1,22}", candidate)
        or re.fullmatch(r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{0,58}", candidate)
    )


def is_public_identifier(value: str) -> bool:
    candidate = normalize_candidate(value)
    public_prefixes = ("prj_", "sb_publishable_", "pk.eyj", "pk-lf-")
    possible_values = [candidate]
    for separator in ("=", ":"):
        if separator in candidate:
            possible_values.append(candidate.split(separator, 1)[1].strip())
    launchdarkly_mobile_key = (
        r"mob-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
    )
    if any(re.fullmatch(launchdarkly_mobile_key, item, re.IGNORECASE) for item in possible_values):
        return True
    return any(item.lower().startswith(public_prefixes) for item in possible_values)


def is_lowercase_slug(value: str) -> bool:
    candidate = normalize_candidate(value)
    return (
        candidate == candidate.lower()
        and bool(re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+){1,12}", candidate))
    )


def is_schema_identifier_candidate(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{7,119}", candidate) or "_" not in candidate:
        return False
    if candidate.lower().startswith(
        (
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "github_pat_",
            "sk_live_",
            "sk_test_",
            "rk_live_",
            "rk_test_",
            "npm_",
            "hf_",
            "sb_secret_",
            "lin_api_",
            "lin_oauth_",
            "cfk_",
            "cfut_",
            "cfat_",
            "vcp_",
            "vci_",
            "vca_",
            "vcr_",
            "vck_",
            "tr_dev_",
            "tr_prod_",
            "dckr_pat_",
            "sntrys_",
            "ntn_",
        )
    ):
        return False
    parts = [part for part in candidate.split("_") if part]
    lower_parts = [part.lower() for part in parts]
    schema_suffixes = (
        "_check",
        "_not_blank",
        "_idx",
        "_index",
        "_fkey",
        "_pkey",
        "_key",
        "_uniq",
        "_unique",
        "_seq",
        "_insert",
        "_update",
        "_delete",
        "_upsert",
        "_trigger",
        "_trg",
    )
    if not candidate.endswith(schema_suffixes):
        action_words = {"allow", "block", "deny", "enforce", "guard", "prevent", "validate"}
        environment_words = {"dev", "local", "prod", "production", "staging", "test"}
        if not (lower_parts and lower_parts[-1] in environment_words and any(part in action_words for part in lower_parts)):
            return False
    if len(parts) < 2 or any(len(part) > 48 for part in parts):
        return False
    return all(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", part) for part in parts)


def is_credential_free_url(value: str) -> bool:
    candidate = normalize_candidate(value)
    if re.match(r"(?i)^(?:sqlite(?:\+[A-Za-z0-9_.-]+)?|file):", candidate):
        return True
    if "://" not in candidate:
        return False
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    return bool(parsed.scheme and parsed.netloc and "@" not in parsed.netloc)


def is_placeholder_credential_url(value: str) -> bool:
    candidate = normalize_candidate(value)
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return False
    if not parsed.username or parsed.password is None:
        return False
    username = unquote(parsed.username).lower()
    password = unquote(parsed.password).lower()
    host = (parsed.hostname or "").lower()
    placeholder_users = {"user", "username", "postgres", "mysql", "redis", "mongo", "mongodb", "root", "admin", "test"}
    placeholder_passwords = {
        "password",
        "pass",
        "postgres",
        "mysql",
        "redis",
        "mongo",
        "mongodb",
        "secret",
        "changeme",
        "changeit",
        "example",
        "placeholder",
        "dummy",
        "test",
    }
    if username not in placeholder_users or password not in placeholder_passwords:
        return False
    if host in {"localhost", "127.0.0.1", "::1", "db", "database", "postgres", "mysql", "redis", "mongo", "mongodb"}:
        return True
    return bool(re.fullmatch(r"[a-z0-9-]+\.(?:localhost|local|test|example|invalid)", host))


def credential_url_placeholder_context(text: str, start: int, end: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    previous_start = text.rfind("\n", 0, max(0, line_start - 1)) + 1
    next_end = text.find("\n", end)
    if next_end == -1:
        next_end = len(text)
    context_start = max(0, previous_start)
    context_end = min(len(text), next_end + 1)
    context = text[context_start:context_end].lower()
    return any(marker in context for marker in (".env.example", ".env.sample", ".env.template", "placeholder", "dummy"))


def is_shell_variable_reference(value: str) -> bool:
    candidate = normalize_candidate(value)
    return bool(re.fullmatch(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})", candidate))


def is_obvious_non_secret_assignment_value(value: str) -> bool:
    candidate = normalize_candidate(value)
    return (
        any(char.isspace() for char in candidate)
        or is_shell_variable_reference(candidate)
        or candidate.startswith(("/", "./", "../", "~/"))
        or is_public_identifier(candidate)
        or is_lowercase_slug(candidate)
        or is_prefixed_placeholder(candidate)
        or is_incomplete_known_provider_token(candidate)
        or is_credential_free_url(candidate)
    )


def is_code_expression_value(value: str) -> bool:
    candidate = normalize_candidate(value)
    return bool(
        re.match(
            r"(?i)^(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*[A-Za-z_$][A-Za-z0-9_$]*\(",
            candidate,
        )
    )


def credible_assignment_value(value: str, *, env_context: bool = False, allow_plain_identifier: bool = False) -> bool:
    candidate = normalize_candidate(value)
    if len(candidate) < (4 if env_context else 8):
        return False
    if is_obvious_non_secret_assignment_value(candidate):
        return False
    if not env_context and is_code_expression_value(candidate):
        return False
    if is_placeholder(candidate) or is_uuid(candidate):
        return False
    if is_incomplete_known_provider_token(candidate):
        return False
    if is_sequential(candidate):
        return False
    if (
        not allow_plain_identifier
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", candidate)
        and not re.fullmatch(r"[A-Fa-f0-9]{32,}", candidate)
    ):
        return False

    entropy = shannon_entropy(candidate)
    classes = character_classes(candidate)

    if env_context and len(candidate) >= 12:
        return entropy >= 2.5 or classes >= 2
    if len(candidate) >= 20 and entropy >= 3.2:
        return True
    return len(candidate) >= 12 and classes >= 2 and entropy >= 2.8


def credible_transport_secret_value(value: str) -> bool:
    candidate = normalize_candidate(value)
    if len(candidate) < 8:
        return False
    if is_shell_variable_reference(candidate):
        return False
    if (
        any(char.isspace() for char in candidate)
        or candidate.startswith(("/", "./", "../", "~/"))
        or is_public_identifier(candidate)
        or is_credential_free_url(candidate)
    ):
        return False
    if is_lowercase_slug(candidate) and not is_uuid(candidate):
        return False
    if is_placeholder(candidate) or is_sequential(candidate) or is_public_identifier(candidate):
        return False
    if (
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", candidate)
        and not (len(candidate) >= 16 and any(char.isdigit() for char in candidate) and character_classes(candidate) >= 2)
    ):
        return False
    if len(candidate) >= 16 and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", candidate):
        return True
    return credible_assignment_value(candidate, env_context=True, allow_plain_identifier=True)


def parse_http_header_argument(header: str) -> tuple[str, str] | None:
    if ":" not in header:
        return None
    name, value = header.split(":", 1)
    normalized_name = name.strip().strip("\"'").lower()
    if not normalized_name:
        return None
    return normalized_name, value.strip().strip("\"'")


def header_secret_value(name: str, value: str) -> str:
    candidate = value.strip()
    if name == "authorization":
        match = re.match(r"(?i)^(?:bearer|basic)\s+(.+)$", candidate)
        if match:
            return match.group(1).strip()
    return candidate


def safe_secret_reference_header(header: str) -> bool:
    parsed = parse_http_header_argument(header)
    if parsed is None:
        return False
    name, value = parsed
    if name not in SENSITIVE_REFERENCE_HEADER_NAMES:
        return False
    return is_shell_variable_reference(header_secret_value(name, value))


def credible_secret_header_value(header: str) -> bool:
    parsed = parse_http_header_argument(header)
    if parsed is None:
        return False
    name, value = parsed
    if name not in SENSITIVE_REFERENCE_HEADER_NAMES or safe_secret_reference_header(header):
        return False
    return credible_transport_secret_value(header_secret_value(name, value))


def valid_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3:
        return False
    for part in parts[:2]:
        padded = part + "=" * (-len(part) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            json.loads(decoded.decode("utf-8"))
        except Exception:
            return False
    return len(parts[2]) >= 8


def valid_qdrant_database_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if is_placeholder(candidate) or is_prefixed_placeholder(candidate):
        return False
    if not candidate.startswith("eyJhb"):
        return False
    if "." in candidate:
        return valid_jwt(candidate)
    return len(candidate) >= 80 and bool(re.fullmatch(r"[A-Za-z0-9_-]+", candidate))


def valid_github_app_installation_token(value: str) -> bool:
    parts = value.split("_", 2)
    if len(parts) != 3 or parts[0] != "ghs" or not parts[1].isdigit():
        return False
    return valid_jwt(parts[2])


def valid_github_fine_grained_pat(value: str) -> bool:
    candidate = normalize_candidate(value)
    if len(candidate) > 255 or is_placeholder(candidate) or is_prefixed_placeholder(candidate):
        return False
    return bool(re.fullmatch(r"github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59,221}", candidate))


def luhn_valid(value: str) -> bool:
    digits = [int(ch) for ch in re.sub(r"\D", "", value)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def valid_provider_token(value: str) -> bool:
    return not is_placeholder(value) and not is_prefixed_placeholder(value)


def valid_launchdarkly_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(
        r"(?i)(?:api|sdk)-([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})",
        candidate,
    )
    if not match:
        return False
    hex_body = match.group(1).replace("-", "").lower()
    return len(set(hex_body)) >= 8 and not is_sequential(hex_body)


def valid_clojars_deploy_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"(?i)CLOJARS_([a-z0-9]{60})", candidate)
    if not match:
        return False
    body = match.group(1).lower()
    return len(set(body)) >= 8 and not is_sequential(body)


def valid_cratesio_api_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"cio([A-Za-z0-9]{32})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_xai_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"xai-([A-Za-z0-9_]{80})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 12 and not is_sequential(body)


def valid_databento_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"db-([A-Za-z0-9]{29})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_azure_openai_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    if not re.fullmatch(r"[A-Za-z0-9]{32}", candidate):
        return False
    return len(set(candidate.lower())) >= 10 and shannon_entropy(candidate) >= 3.5 and not is_sequential(candidate)


def valid_bitrise_workspace_api_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"bitwat_([A-Za-z0-9_-]{20,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 10 and shannon_entropy(body) >= 3.5 and not is_sequential(body)


def valid_inngest_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"(?:signkey-[A-Za-z0-9][A-Za-z0-9_-]{1,31}-|sk-inn-api-)([A-Za-z0-9_-]{20,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 10 and shannon_entropy(body) >= 3.5 and not is_sequential(body)


def valid_unkey_root_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"unkey_([A-Za-z0-9]{20,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_groq_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"gsk_([A-Za-z0-9]{20,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_tavily_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"tvly-([A-Za-z0-9]{20,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_nvidia_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"nvapi-([A-Za-z0-9_-]{64})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_langsmith_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"lsv2_(?:pt|sk)_([A-Za-z0-9_-]{20,160})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_jina_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"jina_([A-Za-z0-9_-]{60})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_langfuse_secret_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"sk-lf-([A-Za-z0-9_-]{16,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_pinecone_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"pcsk_([A-Za-z0-9_-]{24,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_ssemble_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"sk_ssemble_([A-Za-z0-9_-]{16,128})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_firecrawl_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"fc-([A-Fa-f0-9]{32})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_cursor_api_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"crsr_([A-Za-z0-9_-]{16,160})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_openvsx_access_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"(?:ovsxat|ovsxp)[_-]([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", candidate)
    return bool(match and is_uuid(match.group(1)))


def valid_pagarme_encryption_key(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"ek_(?:live|test)_([A-Za-z0-9]{20,64})", candidate)
    if not match:
        return False
    body = match.group(1)
    return len(set(body.lower())) >= 8 and not is_sequential(body)


def valid_terraform_cloud_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if not valid_provider_token(candidate):
        return False
    match = re.fullmatch(r"([A-Za-z0-9]{14})\.atlasv1\.([A-Za-z0-9_=-]{60,70})", candidate)
    if not match:
        return False
    body = match.group(2)
    return len(set(body.lower())) >= 10 and not is_sequential(body)


def split_key_words(key: str) -> list[str]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized).lower()
    return [part for part in normalized.split("_") if part]


def is_sensitive_key(key: str) -> bool:
    clean = key.strip("\"'`")
    if SENSITIVE_KEY_RE.search(clean):
        return True

    words = split_key_words(clean)
    joined = "".join(words)
    word_set = set(words)

    sensitive_pairs = {
        ("api", "key"),
        ("access", "token"),
        ("refresh", "token"),
        ("auth", "token"),
        ("client", "secret"),
        ("secret", "key"),
        ("private", "key"),
        ("session", "secret"),
        ("signing", "key"),
        ("encryption", "key"),
        ("webhook", "secret"),
        ("database", "url"),
        ("db", "url"),
        ("connection", "string"),
    }
    if any(first in word_set and second in word_set for first, second in sensitive_pairs):
        return True
    if joined in {
        "apikey",
        "apitoken",
        "accesstoken",
        "refreshtoken",
        "authtoken",
        "clientsecret",
        "secretkey",
        "privatekey",
        "sessionsecret",
        "signingkey",
        "encryptionkey",
        "webhooksecret",
        "databaseurl",
        "dburl",
    }:
        return True
    return clean.isupper() and bool(SENSITIVE_KEY_WORD_RE.search(clean))


def is_sensitive_identifier_key(key: str) -> bool:
    words = split_key_words(key.strip("\"'`"))
    if len(words) < 2:
        return False
    identifier_suffixes = {"id", "identifier", "name", "fingerprint", "thumbprint"}
    sensitive_words = {"key", "token", "secret", "credential", "password", "private", "public"}
    return words[-1] in identifier_suffixes and any(word in sensitive_words for word in words[:-1])


def env_like_context(path: str = "", surface: str = "") -> bool:
    return bool(
        re.search(r"(?i)(^|/)\.env(\.|$)|\.envrc$|secrets?\.(ya?ml|json|toml|env)$|credentials", path)
        or "dotenv" in surface
        or surface == "env"
    )


def json_path_join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def json_list_path(path: str, index: int) -> str:
    return f"{path}[{index}]" if path else f"[{index}]"


def json_terminal_key(path: str) -> str:
    if not path:
        return ""
    tail = path.rsplit(".", 1)[-1]
    return re.sub(r"\[\d+\]$", "", tail)


def add_json_context_findings(text: str, findings: list[Finding], *, path: str, surface: str) -> None:
    key = json_terminal_key(path)
    if not key or not is_sensitive_key(key):
        return
    if is_sensitive_identifier_key(key):
        return
    if not credible_assignment_value(text, env_context=env_like_context(path, surface)):
        return
    findings.append(
        Finding(
            "SENSITIVE_JSON_VALUE",
            0,
            len(text),
            0.82,
            "sensitive JSON key with credible secret-shaped value",
        )
    )


AWS_ACCESS_KEY_ID_RE = re.compile(r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
AWS_SECRET_ACCESS_KEY_RE = re.compile(r"(?i)\b(?:aws_)?secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")

TOKEN_DETECTORS = [
    RegexDetector(
        "AWS_ACCESS_KEY_ID",
        AWS_ACCESS_KEY_ID_RE,
        0.55,
        "AWS access key identifier without paired secret access key",
        validator=valid_provider_token,
    ),
    RegexDetector("AWS_SECRET_ACCESS_KEY", AWS_SECRET_ACCESS_KEY_RE, 0.95, "AWS secret access key", group=1, validator=valid_provider_token),
    RegexDetector(''.join(('AWS', '_BE', 'DRO', 'CK_', 'API', '_KE', 'Y')), re.compile(''.join(('(?<', '![A', '-Za', '-z0', '-9+', '/])', '(?:', 'ABS', 'KQm', 'Vkc', 'm9j', 'a0F', 'QSU', 'tle', 'S[A', '-Za', '-z0', '-9+', '/]{', '40,', '}={', '0,2', '}|b', 'edr', 'ock', '-ap', 'i-k', 'ey-', 'YmV', 'kcm', '9ja', 'y5h', 'bWF', '6b2', '5hd', '3Mu', 'Y29', 'tLz', '9BY', '3Rp', 'b24', '9Q2', 'Fsb', 'Fdp', 'dGh', 'CZW', 'FyZ', 'XJU', 'b2t', 'lbi', 'ZYL', 'UFt', 'ei1', 'BbG', 'dvc', 'ml0', 'aG0', '9QV', 'dTN', 'C1I', 'TUF', 'DLV', 'NIQ', 'TI1', 'NiZ', 'YLU', 'Fte', 'i1D', 'cmV', 'kZW', '50a', 'WFs', 'P[A', '-Za', '-z0', '-9+', '/\\\\', ']{2', '0,}', '={0', ',2}', ')(?', '![A', '-Za', '-z0', '-9+', '/])'))), 0.96, ''.join(('Ama', 'zon', ' Be', 'dro', 'ck ', 'API', ' ke', 'y')), validator=valid_provider_token),
    RegexDetector("GCP_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"), 0.95, "Google API key", validator=valid_provider_token),
    RegexDetector("GCP_OAUTH_SECRET", re.compile(r"(?<![A-Za-z0-9_-])GOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])"), 0.95, "Google OAuth client secret", validator=valid_provider_token),
    RegexDetector("AZURE_STORAGE_KEY", re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/=]{80,100})"), 0.94, "Azure storage account key", group=1, validator=valid_provider_token),
    RegexDetector("OPENAI_PROJECT_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.96, "OpenAI project key", validator=valid_provider_token),
    RegexDetector("OPENAI_ADMIN_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-admin-[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])"), 0.96, "OpenAI admin key", validator=valid_provider_token),
    RegexDetector("OPENAI_SERVICE_ACCOUNT_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-svcacct-[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])"), 0.96, "OpenAI service account key", validator=valid_provider_token),
    RegexDetector("OPENAI_LEGACY_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}(?![A-Za-z0-9_-])"), 0.96, "OpenAI legacy key", validator=valid_provider_token),
    RegexDetector("OPENROUTER_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-or-v[0-9]+-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.95, "OpenRouter API key", validator=valid_provider_token),
    RegexDetector("PERPLEXITY_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])pplx-[A-Za-z0-9]{48}(?![A-Za-z0-9_-])"), 0.94, "Perplexity API key", validator=valid_provider_token),
    RegexDetector("REPLICATE_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])r8_[A-Za-z0-9_-]{37}(?![A-Za-z0-9_-])"), 0.94, "Replicate API token", validator=valid_provider_token),
    RegexDetector("ANTHROPIC_ADMIN_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-admin[0-9]{2}-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.97, "Anthropic Admin API key", validator=valid_provider_token),
    RegexDetector("ANTHROPIC_COMPLIANCE_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-api01-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.97, "Anthropic Compliance access key", validator=valid_provider_token),
    RegexDetector("ANTHROPIC_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-api03-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.97, "Anthropic Claude API key", validator=valid_provider_token),
    RegexDetector("ANTHROPIC_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.96, "Anthropic API key", validator=valid_provider_token),
    RegexDetector("GITHUB_TOKEN", re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])"), 0.95, "GitHub token", validator=valid_provider_token),
    RegexDetector(
        "GITHUB_APP_INSTALLATION_TOKEN",
        re.compile(r"(?<![A-Za-z0-9_])ghs_[0-9]{1,20}_eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_])"),
        0.96,
        "GitHub App installation token",
        validator=valid_github_app_installation_token,
    ),
    RegexDetector(
        "GITHUB_FINE_GRAINED_PAT",
        re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59,221}(?![A-Za-z0-9_])"),
        0.95,
        "GitHub fine-grained PAT",
        validator=valid_github_fine_grained_pat,
    ),
    RegexDetector(
        "GITLAB_TOKEN",
        re.compile(r"(?<![A-Za-z0-9_-])(?:gl(?:pat|oas|dt|rt|rtr|cbt|ptt|ft|imt|wt|soat|ffct)-|glagent-)[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"),
        0.95,
        "GitLab token",
        validator=valid_provider_token,
    ),
    RegexDetector("SHOPIFY_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_])shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}(?![A-Za-z0-9_])"), 0.95, "Shopify access token", validator=valid_provider_token),
    RegexDetector("PLANETSCALE_TOKEN", re.compile(r"(?<![A-Za-z0-9_.-])pscale_(?:tkn|oauth|pw)_[A-Za-z0-9_.=-]{32,64}(?![A-Za-z0-9_.=-])"), 0.95, "PlanetScale token", validator=valid_provider_token),
    RegexDetector("PREFECT_API_KEY", re.compile(r"(?<![A-Za-z0-9_])pn[ub]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])"), 0.94, "Prefect API key", validator=valid_provider_token),
    RegexDetector("HEROKU_OAUTH_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])HRKU-AA[A-Za-z0-9_-]{58}(?![A-Za-z0-9_-])"), 0.95, "Heroku OAuth token", validator=valid_provider_token),
    RegexDetector("AIRTABLE_PERSONAL_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9])pat[A-Za-z0-9]{14}\.[a-f0-9]{64}(?![A-Za-z0-9])"), 0.95, "Airtable personal access token", validator=valid_provider_token),
    RegexDetector("DATABRICKS_PAT", re.compile(r"(?<![A-Za-z0-9_-])dapi[a-f0-9]{32}(?:-\d)?(?![A-Za-z0-9_-])"), 0.94, "Databricks personal access token", validator=valid_provider_token),
    RegexDetector("SOURCEGRAPH_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_])sgp_(?:[A-Fa-f0-9]{40}|(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40})(?![A-Za-z0-9_])"), 0.95, "Sourcegraph access token", validator=valid_provider_token),
    RegexDetector("DUFFEL_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])duffel_(?:test|live)_[A-Za-z0-9_=-]{43}(?![A-Za-z0-9_=-])"), 0.94, "Duffel API access token", validator=valid_provider_token),
    RegexDetector("FRAMEIO_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_.-])fio-u-[A-Za-z0-9_=-]{64}(?![A-Za-z0-9_=-])"), 0.95, "Frame.io API token", validator=valid_provider_token),
    RegexDetector("LOB_API_KEY", re.compile(r"(?i)\b(?:lob(?:[_\-. ]{0,8}(?:api|secret|auth))?[_\-. ]{0,8}(?:key|token)|lob_api_key)\b[\w .\t'\"`:=><|?,-]{0,80}((?:live|test)_[a-f0-9]{35})(?=[:\s'\"`;]|\\[nr]|$)"), 0.94, "Lob API key", group=1, validator=valid_provider_token),
    RegexDetector("LOB_API_KEY", re.compile(r"(?i)https://api\.lob\.com/[^\n]{0,200}?\s-u\s+((?:live|test)_[a-f0-9]{35})(?=:)"), 0.94, "Lob API key", group=1, validator=valid_provider_token),
    RegexDetector("MAPBOX_SECRET_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"), 0.95, "Mapbox secret access token", validator=valid_provider_token),
    RegexDetector("DROPBOX_SHORT_LIVED_ACCESS_TOKEN", re.compile(r"(?i)\b(?:dropbox(?:[_\-. ]{0,12}(?:api|access|oauth|bearer))?[_\-. ]{0,12}(?:token|key)|dropbox_access_token|dropbox_api_token)\b[\s'\"`]{0,5}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'\"\s=]{0,5}(sl\.[A-Za-z0-9_=-]{130,180})(?=[\s'\"`;]|\\[nr]|$)"), 0.95, "Dropbox short-lived access token", group=1, validator=valid_provider_token),
    RegexDetector("LAUNCHDARKLY_API_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])api-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-4[A-Fa-f0-9]{3}-[89abAB][A-Fa-f0-9]{3}-[A-Fa-f0-9]{12}(?![A-Za-z0-9_-])"), 0.95, "LaunchDarkly API access token", validator=valid_launchdarkly_token),
    RegexDetector("LAUNCHDARKLY_SDK_KEY", re.compile(r"(?<![A-Za-z0-9_-])sdk-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-4[A-Fa-f0-9]{3}-[89abAB][A-Fa-f0-9]{3}-[A-Fa-f0-9]{12}(?![A-Za-z0-9_-])"), 0.95, "LaunchDarkly server-side SDK key", validator=valid_launchdarkly_token),
    RegexDetector("CLOJARS_DEPLOY_TOKEN", re.compile(r"(?i)(?<![A-Za-z0-9_])CLOJARS_[a-z0-9]{60}(?![A-Za-z0-9_])"), 0.95, "Clojars deploy token", validator=valid_clojars_deploy_token),
    RegexDetector("CRATESIO_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])cio[A-Za-z0-9]{32}(?![A-Za-z0-9_-])"), 0.95, "crates.io API token", validator=valid_cratesio_api_token),
    RegexDetector("XAI_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])xai-[A-Za-z0-9_]{80}(?![A-Za-z0-9_])"), 0.95, "xAI API key", validator=valid_xai_api_key),
    RegexDetector("DATABENTO_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])db-[A-Za-z0-9]{29}(?![A-Za-z0-9_-])"), 0.95, "Databento API key", validator=valid_databento_api_key),
    RegexDetector(
        "AZURE_OPENAI_API_KEY",
        re.compile(
            r"(?ix)(?:"
            r"(?=[^\r\n]*(?:\bAZURE_OPENAI_(?:API_)?KEY\b|\bazure\s+openai\b|openai\.azure\.com|cognitiveservices\.azure\.com))"
            r"(?:\bAZURE_OPENAI_(?:API_)?KEY\b[\w .\t'\"`:=><|?,-]{0,80}|\b(?:api[-_ ]?key|subscription[-_ ]?key)\b[\s'\"`:=><|?,-]{0,20})"
            r"|(?:\b(?:azure\s+openai|openai\.azure\.com|cognitiveservices\.azure\.com)\b[^\r\n]{0,200}\b(?:api[-_ ]?key|subscription[-_ ]?key)\b[\s'\"`:=><|?,-]{0,20})"
            r")([A-Za-z0-9]{32})(?![A-Za-z0-9])"
        ),
        0.95,
        "Azure OpenAI API key",
        group=1,
        validator=valid_azure_openai_api_key,
    ),
    RegexDetector("BITRISE_WORKSPACE_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_])bitwat_[A-Za-z0-9_-]{20,128}(?![A-Za-z0-9_-])"), 0.95, "Bitrise workspace API token", validator=valid_bitrise_workspace_api_token),
    RegexDetector("INNGEST_KEY", re.compile(r"(?<![A-Za-z0-9_-])(?:signkey-[A-Za-z0-9][A-Za-z0-9_-]{1,31}-|sk-inn-api-)[A-Za-z0-9_-]{20,128}(?![A-Za-z0-9_-])"), 0.95, "Inngest API or signing key", validator=valid_inngest_key),
    RegexDetector("UNKEY_ROOT_KEY", re.compile(r"(?<![A-Za-z0-9_])unkey_[A-Za-z0-9]{20,128}(?![A-Za-z0-9_])"), 0.95, "Unkey root key", validator=valid_unkey_root_key),
    RegexDetector("GROQ_API_KEY", re.compile(r"(?<![A-Za-z0-9_])gsk_[A-Za-z0-9]{20,128}(?![A-Za-z0-9_])"), 0.95, "Groq API key", validator=valid_groq_api_key),
    RegexDetector("TAVILY_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])tvly-[A-Za-z0-9]{20,128}(?![A-Za-z0-9_-])"), 0.95, "Tavily API key", validator=valid_tavily_api_key),
    RegexDetector("NVIDIA_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])nvapi-[A-Za-z0-9_-]{64}(?![A-Za-z0-9_-])"), 0.95, "NVIDIA API key", validator=valid_nvidia_api_key),
    RegexDetector("LANGSMITH_API_KEY", re.compile(r"(?<![A-Za-z0-9_])lsv2_(?:pt|sk)_[A-Za-z0-9_-]{20,160}(?![A-Za-z0-9_-])"), 0.95, "LangSmith API key", validator=valid_langsmith_api_key),
    RegexDetector("JINA_API_KEY", re.compile(r"(?<![A-Za-z0-9_])jina_[A-Za-z0-9_-]{60}(?![A-Za-z0-9_-])"), 0.95, "Jina API key", validator=valid_jina_api_key),
    RegexDetector("LANGFUSE_SECRET_KEY", re.compile(r"(?<![A-Za-z0-9_-])sk-lf-[A-Za-z0-9_-]{16,128}(?![A-Za-z0-9_-])"), 0.95, "Langfuse secret key", validator=valid_langfuse_secret_key),
    RegexDetector("PINECONE_API_KEY", re.compile(r"(?<![A-Za-z0-9_])pcsk_[A-Za-z0-9_-]{24,128}(?![A-Za-z0-9_-])"), 0.95, "Pinecone API key", validator=valid_pinecone_api_key),
    RegexDetector("SSEMBLE_API_KEY", re.compile(r"(?<![A-Za-z0-9_])sk_ssemble_[A-Za-z0-9_-]{16,128}(?![A-Za-z0-9_-])"), 0.95, "Ssemble API key", validator=valid_ssemble_api_key),
    RegexDetector("FIRECRAWL_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])fc-[A-Fa-f0-9]{32}(?![A-Za-z0-9_-])"), 0.94, "Firecrawl API key", validator=valid_firecrawl_api_key),
    RegexDetector("CURSOR_API_KEY", re.compile(r"(?<![A-Za-z0-9_])crsr_[A-Za-z0-9_-]{16,160}(?![A-Za-z0-9_-])"), 0.94, "Cursor API key", validator=valid_cursor_api_key),
    RegexDetector("OPENVSX_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_])(?:ovsxat|ovsxp)[_-][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![A-Za-z0-9_-])"), 0.95, "Open VSX access token", validator=valid_openvsx_access_token),
    RegexDetector("PAGARME_ENCRYPTION_KEY", re.compile(r"(?<![A-Za-z0-9_])ek_(?:live|test)_[A-Za-z0-9]{20,64}(?![A-Za-z0-9_])"), 0.95, "Pagar.me encryption key", validator=valid_pagarme_encryption_key),
    RegexDetector("TERRAFORM_CLOUD_TOKEN", re.compile(r"(?<![A-Za-z0-9_.-])[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}(?![A-Za-z0-9_=-])"), 0.95, "Terraform Cloud token", validator=valid_terraform_cloud_token),
    RegexDetector(
        "QDRANT_DATABASE_API_KEY",
        re.compile(
            r"(?i)(?:\bqdrant(?:[_\-. ]{0,16}(?:database|db|cloud|api))?[_\-. ]{0,16}(?:api[_\-. ]{0,4}key|key|token)\b[\w .\t'\"`:=><|?,-]{0,80}|\bqdrant\b[^\r\n]{0,200}\b(?:api-key|authorization)\s*:\s*(?:bearer\s+)?)((?:eyJhb[A-Za-z0-9_-]{20,})(?:\.[A-Za-z0-9_-]{8,}){0,2})(?![A-Za-z0-9_-])"
        ),
        0.95,
        "Qdrant granular database API key",
        group=1,
        validator=valid_qdrant_database_api_key,
    ),
    RegexDetector("SLACK_TOKEN", re.compile(r"(?<![A-Za-z0-9-])xox[baprs]-[0-9A-Za-z-]{20,}(?![A-Za-z0-9-])"), 0.95, "Slack token", validator=valid_provider_token),
    RegexDetector("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}"), 0.96, "Slack webhook", validator=valid_provider_token),
    RegexDetector("STRIPE_KEY", re.compile(r"(?<![A-Za-z0-9_])[rs]k_(?:live|test)_[A-Za-z0-9]{24,}(?![A-Za-z0-9_])"), 0.95, "Stripe secret/restricted key", validator=valid_provider_token),
    RegexDetector("STRIPE_WEBHOOK_SECRET", re.compile(r"(?<![A-Za-z0-9_])whsec_[A-Za-z0-9]{24,}(?![A-Za-z0-9_])"), 0.95, "Stripe webhook secret", validator=valid_provider_token),
    RegexDetector("SQUARE_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])(?:EAAA[A-Za-z0-9_-]{22,60}|sq0atp-[A-Za-z0-9_-]{22,60})(?![A-Za-z0-9_-])"), 0.95, "Square access token", validator=valid_provider_token),
    RegexDetector("SQUARE_OAUTH_SECRET", re.compile(r"(?<![A-Za-z0-9_-])sq0csp-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"), 0.95, "Square OAuth secret", validator=valid_provider_token),
    RegexDetector("SENDGRID_KEY", re.compile(r"(?<![A-Za-z0-9_-])SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])"), 0.95, "SendGrid API key", validator=valid_provider_token),
    RegexDetector("RESEND_API_KEY", re.compile(r"(?<![A-Za-z0-9_])re_[A-Za-z0-9]{20,}(?![A-Za-z0-9_])"), 0.94, "Resend API key", validator=valid_provider_token),
    RegexDetector("MAILCHIMP_API_KEY", re.compile(r"(?i)\b(?:MailchimpSDK\.initialize|mailchimp)[A-Za-z0-9_. -]{0,32}[:=]\s*([a-f0-9]{32}-us\d{1,2})(?![A-Za-z0-9-])"), 0.94, "Mailchimp API key", group=1, validator=valid_provider_token),
    RegexDetector("NPM_TOKEN", re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])"), 0.93, "npm token", validator=valid_provider_token),
    RegexDetector("NPM_AUTH_TOKEN", re.compile(r"(?i)(?://[A-Za-z0-9_.:/-]+)?[:/]_authToken\s*=\s*([A-Fa-f0-9]{32,}|npm_[A-Za-z0-9]{36})"), 0.94, "npm registry auth token", group=1, validator=valid_provider_token),
    RegexDetector("PYPI_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])pypi-[A-Za-z0-9_-]{85,}(?![A-Za-z0-9_-])"), 0.94, "PyPI token", validator=valid_provider_token),
    RegexDetector("DOCKER_PAT", re.compile(r"(?<![A-Za-z0-9_-])dckr_pat_[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"), 0.93, "Docker Hub PAT", validator=valid_provider_token),
    RegexDetector("SUPABASE_SECRET_KEY", re.compile(r"(?<![A-Za-z0-9_])sb_secret_[A-Za-z0-9]{22}_[A-Za-z0-9]{8}(?![A-Za-z0-9_])"), 0.95, "Supabase secret API key", validator=valid_provider_token),
    RegexDetector("HUGGINGFACE_TOKEN", re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{20,}(?![A-Za-z0-9_])"), 0.94, "Hugging Face user access token", validator=valid_provider_token),
    RegexDetector("VERCEL_TOKEN", re.compile(r"(?<![A-Za-z0-9_])vc[piarck]_[A-Za-z0-9]{24,}(?![A-Za-z0-9_])"), 0.94, "Vercel token or API key", validator=valid_provider_token),
    RegexDetector("CLOUDFLARE_TOKEN", re.compile(r"(?<![A-Za-z0-9_])cf(?:k|ut|at)_[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_])"), 0.95, "Cloudflare API credential", validator=valid_provider_token),
    RegexDetector("LINEAR_TOKEN", re.compile(r"(?<![A-Za-z0-9_])lin_(?:api|oauth)_[A-Za-z0-9]{20,}(?![A-Za-z0-9_])"), 0.94, "Linear API key or OAuth token", validator=valid_provider_token),
    RegexDetector("NOTION_TOKEN", re.compile(r"(?<![A-Za-z0-9_])ntn_[A-Za-z0-9]{20,}(?![A-Za-z0-9_])"), 0.92, "Notion API token", validator=valid_provider_token),
    RegexDetector("SENTRY_TOKEN", re.compile(r"(?<![A-Za-z0-9_])sntrys_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_])"), 0.93, "Sentry auth token", validator=valid_provider_token),
    RegexDetector("GRAFANA_SERVICE_ACCOUNT_TOKEN", re.compile(r"(?<![A-Za-z0-9_])glsa_[A-Za-z0-9_-]{20,}_[A-Fa-f0-9]{8}(?![A-Za-z0-9_])"), 0.95, "Grafana service account token", validator=valid_provider_token),
    RegexDetector("VAULT_TOKEN", re.compile(r"(?<![A-Za-z0-9_.-])hvs\.[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])"), 0.93, "HashiCorp Vault token", validator=valid_provider_token),
    RegexDetector("ONEPASSWORD_SERVICE_ACCOUNT_TOKEN", re.compile(r"(?<![A-Za-z0-9_])ops_eyJ[A-Za-z0-9+/_-]{200,}={0,3}(?![A-Za-z0-9+/_=-])"), 0.97, "1Password service account token", validator=valid_provider_token),
    RegexDetector("AGE_SECRET_KEY", re.compile(r"(?<![A-Za-z0-9_-])AGE-SECRET-KEY-(?:PQ-)?1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{40,}(?![A-Za-z0-9_-])"), 0.96, "age identity secret key", validator=valid_provider_token),
    RegexDetector("DOPPLER_SERVICE_TOKEN", re.compile(r"(?<![A-Za-z0-9_.-])dp\.st(?:\.[a-z0-9_-]{2,35})?\.[A-Za-z0-9]{40,44}(?![A-Za-z0-9_-])"), 0.95, "Doppler service token", validator=valid_provider_token),
    RegexDetector("DOPPLER_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_.-])dp\.(?:ct|pt|sa|scim|audit)\.[A-Za-z0-9]{40,44}(?![A-Za-z0-9_-])"), 0.95, "Doppler API token", validator=valid_provider_token),
    RegexDetector("TRIGGER_KEY", re.compile(r"(?<![A-Za-z0-9_-])tr_(?:dev|prod)_[A-Za-z0-9]{20,}(?![A-Za-z0-9_-])"), 0.92, "Trigger.dev API key", validator=valid_provider_token),
    RegexDetector("SONARQUBE_SCOPED_ORG_TOKEN", re.compile(r"(?<![A-Za-z0-9_])sqco_[A-Za-z0-9=_-]{40,}(?![A-Za-z0-9=_-])"), 0.94, "SonarQube Cloud scoped organization token", validator=valid_provider_token),
    RegexDetector("FLY_IO_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9+/=_-])(?:FlyV1[ \t]+)?(?:fo1_[A-Za-z0-9_-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3})(?![A-Za-z0-9+/=_-])"), 0.95, "Fly.io access token", validator=valid_provider_token),
    RegexDetector("TAILSCALE_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])tskey-api-(?:[A-Za-z0-9]{32,}|[A-Za-z0-9]{8,}-[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])"), 0.95, "Tailscale API key", validator=valid_provider_token),
    RegexDetector("TAILSCALE_AUTH_KEY", re.compile(r"(?<![A-Za-z0-9_-])tskey-auth-(?:[A-Za-z0-9]{32,}|[A-Za-z0-9]{8,}-[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])"), 0.95, "Tailscale auth key", validator=valid_provider_token),
    RegexDetector("TAILSCALE_OAUTH_CLIENT_SECRET", re.compile(r"(?<![A-Za-z0-9_-])tskey-client-(?:[A-Za-z0-9]{32,}|[A-Za-z0-9]{8,}-[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])"), 0.95, "Tailscale OAuth client secret", validator=valid_provider_token),
    RegexDetector("TAILSCALE_SCIM_KEY", re.compile(r"(?<![A-Za-z0-9_-])tskey-scim-(?:[A-Za-z0-9]{32,}|[A-Za-z0-9]{8,}-[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])"), 0.95, "Tailscale SCIM key", validator=valid_provider_token),
    RegexDetector("TAILSCALE_WEBHOOK_KEY", re.compile(r"(?<![A-Za-z0-9_-])tskey-webhook-(?:[A-Za-z0-9]{32,}|[A-Za-z0-9]{8,}-[A-Za-z0-9]{16,})(?![A-Za-z0-9_-])"), 0.95, "Tailscale webhook key", validator=valid_provider_token),
    RegexDetector("DIGITALOCEAN_PERSONAL_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_])dop_v1_[A-Fa-f0-9]{64}(?![A-Za-z0-9_])"), 0.95, "DigitalOcean personal access token", validator=valid_provider_token),
    RegexDetector("DIGITALOCEAN_OAUTH_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9_])doo_v1_[A-Fa-f0-9]{64}(?![A-Za-z0-9_])"), 0.95, "DigitalOcean OAuth access token", validator=valid_provider_token),
    RegexDetector("DIGITALOCEAN_OAUTH_REFRESH_TOKEN", re.compile(r"(?<![A-Za-z0-9_])dor_v1_[A-Fa-f0-9]{64}(?![A-Za-z0-9_])"), 0.95, "DigitalOcean OAuth refresh token", validator=valid_provider_token),
    RegexDetector("NETLIFY_AUTH_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])nf[pcoub][A-Za-z0-9_-]{37}(?![A-Za-z0-9_-])"), 0.94, "Netlify authentication token", validator=valid_provider_token),
    RegexDetector("BUILDKITE_TOKEN", re.compile(r"(?<![A-Za-z0-9_-])(?:bkaa_|bkaj_|bkar_|bkct_|bkpt_|bkpat_|bkps_|bkua_)[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])"), 0.95, "Buildkite token", validator=valid_provider_token),
    RegexDetector("CIRCLECI_TOKEN", re.compile(r"(?<![A-Za-z0-9_])CCI(?:PAT|PRJ)_[1-9A-HJ-NP-Za-km-z]{20,24}_[A-Fa-f0-9]{40}(?![A-Za-z0-9_])"), 0.95, "CircleCI API token", validator=valid_provider_token),
    RegexDetector("PULUMI_ACCESS_TOKEN", re.compile(r"(?<![A-Za-z0-9-])pul-[a-f0-9]{40}(?![A-Za-z0-9-])"), 0.94, "Pulumi access token", validator=valid_provider_token),
    RegexDetector("ATLASSIAN_API_TOKEN", re.compile(r"(?<![A-Za-z0-9_=-])ATATT3[A-Za-z0-9_=-]{186}(?![A-Za-z0-9_=-])"), 0.95, "Atlassian API token", validator=valid_provider_token),
    RegexDetector("POSTMAN_API_KEY", re.compile(r"(?<![A-Za-z0-9_-])PMAK-[A-Za-z0-9]{50,}(?![A-Za-z0-9_-])"), 0.94, "Postman API key", validator=valid_provider_token),
    RegexDetector("DATADOG_API_KEY", re.compile(r"(?i)\b(?:datadog|dd)[_\-.]?(?:api|app(?:lication)?)[_\-.]?key\s*[:=]\s*([A-Fa-f0-9]{32,40})(?![A-Fa-f0-9])"), 0.94, "Datadog API or application key", group=1, validator=valid_provider_token),
    RegexDetector("COHERE_API_KEY", re.compile(r"(?i)\b(?:cohere|co_api_key)[A-Za-z0-9_. -]{0,32}[:=]\s*([A-Za-z0-9]{40})(?![A-Za-z0-9])"), 0.94, "Cohere API key", group=1, validator=valid_provider_token),
    RegexDetector("TWILIO_AUTH_TOKEN", re.compile(r"(?i)\b(?:twilio[_\-.]?)?auth[_\-.]?token\s*[:=]\s*([A-Fa-f0-9]{32})(?![A-Fa-f0-9])"), 0.94, "Twilio auth token", group=1, validator=valid_provider_token),
    RegexDetector("TELEGRAM_BOT_TOKEN", re.compile(r"(?<![A-Za-z0-9_:-])\d{5,16}:[A-Za-z0-9_-]{32,45}(?![A-Za-z0-9_-])"), 0.94, "Telegram bot token", validator=valid_provider_token),
    RegexDetector("DISCORD_WEBHOOK", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"), 0.94, "Discord webhook", validator=valid_provider_token),
    RegexDetector("JWT", re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])"), 0.88, "JSON Web Token", validator=valid_jwt),
]

TOKEN_DETECTOR_HINTS = {
    "AWS_ACCESS_KEY_ID": ("a3t", "akia", "agpa", "aida", "aroa", "aipa", "anpa", "anva", "asia"),
    "AWS_SECRET_ACCESS_KEY": ("secret_access_key",),
    "AWS_BEDROCK_API_KEY": ("abskqmvkcm9ja0fqsutles", "bedrock-api-key-"),
    "GCP_API_KEY": ("aiza",),
    "GCP_OAUTH_SECRET": ("gocspx-",),
    "AZURE_STORAGE_KEY": ("accountkey=",),
    "OPENAI_PROJECT_KEY": ("sk-proj-",),
    "OPENAI_ADMIN_KEY": ("sk-admin-",),
    "OPENAI_SERVICE_ACCOUNT_KEY": ("sk-svcacct-",),
    "OPENAI_LEGACY_KEY": ("sk-", "t3blbkfj"),
    "OPENROUTER_KEY": ("sk-or-v",),
    "PERPLEXITY_API_KEY": ("pplx-",),
    "REPLICATE_API_TOKEN": ("r8_",),
    "ANTHROPIC_ADMIN_KEY": ("sk-ant-admin",),
    "ANTHROPIC_COMPLIANCE_KEY": ("sk-ant-api01-",),
    "ANTHROPIC_API_KEY": ("sk-ant-api03-",),
    "ANTHROPIC_KEY": ("sk-ant-",),
    "GITHUB_TOKEN": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "GITHUB_APP_INSTALLATION_TOKEN": ("ghs_", ".eyj"),
    "GITHUB_FINE_GRAINED_PAT": ("github_pat_",),
    "GITLAB_TOKEN": ("glpat-", "gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "glwt-", "glsoat-", "glffct-"),
    "SHOPIFY_ACCESS_TOKEN": ("shpat_", "shpca_", "shppa_", "shpss_"),
    "PLANETSCALE_TOKEN": ("pscale_tkn_", "pscale_oauth_", "pscale_pw_"),
    "PREFECT_API_KEY": ("pnu_", "pnb_"),
    "HEROKU_OAUTH_TOKEN": ("hrku-aa",),
    "AIRTABLE_PERSONAL_ACCESS_TOKEN": ("pat",),
    "DATABRICKS_PAT": ("dapi",),
    "SOURCEGRAPH_ACCESS_TOKEN": ("sgp_",),
    "DUFFEL_API_TOKEN": ("duffel_test_", "duffel_live_"),
    "FRAMEIO_API_TOKEN": ("fio-u-",),
    "LOB_API_KEY": ("lob", "api.lob.com"),
    "MAPBOX_SECRET_TOKEN": ("sk.eyj",),
    "DROPBOX_SHORT_LIVED_ACCESS_TOKEN": ("dropbox", "sl."),
    "LAUNCHDARKLY_API_ACCESS_TOKEN": ("api-",),
    "LAUNCHDARKLY_SDK_KEY": ("sdk-",),
    "CLOJARS_DEPLOY_TOKEN": ("clojars_",),
    "CRATESIO_API_TOKEN": ("cio",),
    "XAI_API_KEY": ("xai-",),
    "DATABENTO_API_KEY": ("db-",),
    "AZURE_OPENAI_API_KEY": ("azure_openai", "openai.azure.com", "cognitiveservices.azure.com"),
    "BITRISE_WORKSPACE_API_TOKEN": ("bitwat_",),
    "INNGEST_KEY": ("signkey-", "sk-inn-api-"),
    "UNKEY_ROOT_KEY": ("unkey_",),
    "GROQ_API_KEY": ("gsk_",),
    "TAVILY_API_KEY": ("tvly-",),
    "NVIDIA_API_KEY": ("nvapi-",),
    "LANGSMITH_API_KEY": ("lsv2_",),
    "JINA_API_KEY": ("jina_",),
    "LANGFUSE_SECRET_KEY": ("sk-lf-",),
    "PINECONE_API_KEY": ("pcsk_",),
    "SSEMBLE_API_KEY": ("sk_ssemble_",),
    "FIRECRAWL_API_KEY": ("fc-",),
    "CURSOR_API_KEY": ("crsr_",),
    "OPENVSX_ACCESS_TOKEN": ("ovsxat_", "ovsxat-", "ovsxp_", "ovsxp-"),
    "PAGARME_ENCRYPTION_KEY": ("ek_live_", "ek_test_"),
    "TERRAFORM_CLOUD_TOKEN": ("atlasv1.",),
    "QDRANT_DATABASE_API_KEY": ("qdrant", "eyjhb"),
    "SLACK_TOKEN": ("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"),
    "SLACK_WEBHOOK": ("hooks.slack.com/services/",),
    "STRIPE_KEY": ("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
    "STRIPE_WEBHOOK_SECRET": ("whsec_",),
    "SQUARE_ACCESS_TOKEN": ("sq0atp-", "eaaa"),
    "SQUARE_OAUTH_SECRET": ("sq0csp-",),
    "SENDGRID_KEY": ("sg.",),
    "RESEND_API_KEY": ("re_",),
    "MAILCHIMP_API_KEY": ("mailchimp",),
    "NPM_TOKEN": ("npm_",),
    "NPM_AUTH_TOKEN": ("_authtoken",),
    "PYPI_TOKEN": ("pypi-",),
    "DOCKER_PAT": ("dckr_pat_",),
    "SUPABASE_SECRET_KEY": ("sb_secret_",),
    "HUGGINGFACE_TOKEN": ("hf_",),
    "VERCEL_TOKEN": ("vcp_", "vci_", "vca_", "vcr_", "vck_"),
    "CLOUDFLARE_TOKEN": ("cfk_", "cfut_", "cfat_"),
    "LINEAR_TOKEN": ("lin_api_", "lin_oauth_"),
    "NOTION_TOKEN": ("ntn_",),
    "SENTRY_TOKEN": ("sntrys_",),
    "GRAFANA_SERVICE_ACCOUNT_TOKEN": ("glsa_",),
    "VAULT_TOKEN": ("hvs.",),
    "ONEPASSWORD_SERVICE_ACCOUNT_TOKEN": ("ops_eyj",),
    "AGE_SECRET_KEY": ("age-secret-key-1", "age-secret-key-pq-1"),
    "DOPPLER_SERVICE_TOKEN": ("dp.st.",),
    "DOPPLER_API_TOKEN": ("dp.ct.", "dp.pt.", "dp.sa.", "dp.scim.", "dp.audit."),
    "TRIGGER_KEY": ("tr_dev_", "tr_prod_"),
    "SONARQUBE_SCOPED_ORG_TOKEN": ("sqco_",),
    "FLY_IO_ACCESS_TOKEN": ("flyv1", "fm2_", "fm1a_", "fm1r_", "fo1_"),
    "TAILSCALE_API_KEY": ("tskey-api-",),
    "TAILSCALE_AUTH_KEY": ("tskey-auth-",),
    "TAILSCALE_OAUTH_CLIENT_SECRET": ("tskey-client-",),
    "TAILSCALE_SCIM_KEY": ("tskey-scim-",),
    "TAILSCALE_WEBHOOK_KEY": ("tskey-webhook-",),
    "DIGITALOCEAN_PERSONAL_ACCESS_TOKEN": ("dop_v1_",),
    "DIGITALOCEAN_OAUTH_ACCESS_TOKEN": ("doo_v1_",),
    "DIGITALOCEAN_OAUTH_REFRESH_TOKEN": ("dor_v1_",),
    "NETLIFY_AUTH_TOKEN": ("nfp", "nfc", "nfo", "nfu", "nfb"),
    "BUILDKITE_TOKEN": ("bkaa_", "bkaj_", "bkar_", "bkct_", "bkpt_", "bkpat_", "bkps_", "bkua_"),
    "CIRCLECI_TOKEN": ("ccipat_", "cciprj_"),
    "PULUMI_ACCESS_TOKEN": ("pul-",),
    "ATLASSIAN_API_TOKEN": ("atatt3",),
    "POSTMAN_API_KEY": ("pmak-",),
    "DATADOG_API_KEY": ("datadog_api_key", "datadog_app_key", "dd_api_key", "dd_app_key"),
    "COHERE_API_KEY": ("cohere", "co_api_key"),
    "TWILIO_AUTH_TOKEN": ("twilio_auth_token", "auth_token"),
    "DISCORD_WEBHOOK": ("discord.com/api/webhooks/", "discordapp.com/api/webhooks/"),
    "JWT": ("eyj", ".eyj"),
}
TOKEN_DETECTOR_HINT_PATTERNS = {
    "TELEGRAM_BOT_TOKEN": re.compile(r"(?<![A-Za-z0-9_:-])\d{5,16}:"),
}
SENSITIVE_TEXT_HINTS = (
    "api",
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "credential",
    "private",
    "auth",
    "bearer",
    "access",
    "refresh",
    "session",
    "signing",
    "encryption",
    "client",
    "webhook",
    "database",
    "db",
    "connection",
    "accountkey",
)
PROVIDER_TOKEN_HINTS = tuple(
    sorted(
        {hint for hints in TOKEN_DETECTOR_HINTS.values() for hint in hints if len(hint) >= 3},
        key=len,
        reverse=True,
    )
)

AUTH_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?Authorization[\"']?\s*(?::|=)\s*[\"']?\s*(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{10,})"
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^\s*(?:"
    r"x-api-key|api-key|apikey|circle-token|circleci-token|x-auth-token|x-access-token|x-refresh-token|"
    r"x-session-token|x-csrf-token|x-xsrf-token|csrf-token|xsrf-token"
    r")\s*:\s*([^\r\n;, ]{8,})"
)
SENSITIVE_REFERENCE_HEADER_NAMES = {
    "authorization",
    "circle-token",
    "circleci-token",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-refresh-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
}
COOKIE_HEADER_RE = re.compile(r"(?im)^\s*(Cookie|Set-Cookie)\s*:\s*([^\r\n]+)")
COOKIE_ATTRIBUTE_NAMES = {
    "domain",
    "expires",
    "httponly",
    "max-age",
    "partitioned",
    "path",
    "priority",
    "samesite",
    "secure",
}
SENSITIVE_COOKIE_NAME_RE = re.compile(
    r"(?i)(?:^|[_.-])("
    r"session|sessionid|sid|sess|auth|token|jwt|csrf|xsrf|remember|"
    r"access|refresh|id_token|connect\.sid"
    r")(?:$|[_.-])"
)
URL_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|https?|ssh)://[^\s'\"<>/@:]+:[^\s'\"<>/@]+@[^\s'\"<>]+"
)
QUERY_SECRET_RE = re.compile(
    r"(?i)([?&][A-Za-z0-9_.-]*(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|key|secret|password|pwd|bearer|authorization)=)([^&#\s'\"<>]+)"
)
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
PEM_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
PGP_PRIVATE_KEY_BLOCK_RE = re.compile(
    ''.join(('---', '--B', 'EGI', 'N P', 'GP ', 'PRI', 'VAT', 'E K', 'EY ', 'BLO', 'CK-', '---', '-[\\', 's\\S', ']*?', '---', '--E', 'ND ', 'PGP', ' PR', 'IVA', 'TE ', 'KEY', ' BL', 'OCK', '---', '--'))
)
PGP_PRIVATE_KEY_HEADER_RE = re.compile(''.join(('---', '--B', 'EGI', 'N P', 'GP ', 'PRI', 'VAT', 'E K', 'EY ', 'BLO', 'CK-', '---', '-')))
URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>]+")

COMMAND_BOUNDARY = r"(?:^|[\s|;&]|\$\()"
SENSITIVE_PATH_PATTERN = (
    r"(?:"
    r"\.env(?:\.[A-Za-z0-9_-]+)?|\.envrc|\.npmrc|\.pypirc|\.netrc|\.pgpass|"
    r"\.git-credentials|\.claude/settings(?:\.local)?\.json|\.claude\.json|"
    r"\.local/share/agent-secret-guard/fingerprint\.key|"
    r"credentials(?:\.[A-Za-z0-9_-]+)?|secrets?\.(?:ya?ml|json|toml|env)|"
    r"/\.aws/credentials|/\.ssh/id_[A-Za-z0-9_-]+|/\.kube/config|"
    r"/\.config/gcloud/(?:application_default_credentials(?:\.json)?|legacy_credentials)|/\.azure/(?:accessTokens(?:\.json)?|msal)|"
    r"\.vault-token|"
    r"\.(?:pem|key|p12|pfx|jks)\b"
    r")"
)
READ_TOOL_PATTERN = r"(?:cat|less|more|bat|head|tail|grep|egrep|fgrep|rg|sed|awk|jq|python[0-9.]*|node|perl|ruby|xxd|strings|base64|openssl)"
SENSITIVE_ENV_NAME_PATTERN = r"(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|API|PRIVATE|BEARER|ACCESS|REFRESH|SESSION|SIGNING|ENCRYPTION|MASTER|ROOT|ADMIN)"

ENV_TEMPLATE_PATH_RE = re.compile(r"(^|/)\.env\.(?:example|sample|template|dist)$", re.IGNORECASE)

PATH_RULES = [
    PathRule("SENSITIVE_FILE_PATH", "dotenv", re.compile(r"(^|/)\.env(?:\.[A-Za-z0-9_-]+)?$", re.IGNORECASE), "dotenv files commonly contain secret values"),
    PathRule("SENSITIVE_FILE_PATH", "envrc", re.compile(r"(^|/)\.envrc$", re.IGNORECASE), "direnv files commonly export secret values"),
    PathRule("SENSITIVE_FILE_PATH", "claude-settings", re.compile(r"(^|/)\.claude/settings(?:\.local)?\.json$", re.IGNORECASE), "Claude settings may contain MCP credentials"),
    PathRule("SENSITIVE_FILE_PATH", "claude-json", re.compile(r"(^|/)\.claude\.json$", re.IGNORECASE), "Claude JSON config may contain auth tokens"),
    PathRule("SENSITIVE_FILE_PATH", "credentials-file", re.compile(r"(^|/)credentials(?:\.[A-Za-z0-9_-]+)?$", re.IGNORECASE), "generic credentials files commonly contain secret values"),
    PathRule("SENSITIVE_FILE_PATH", "aws-credentials", re.compile(r"(^|/)\.aws/credentials$", re.IGNORECASE), "AWS credentials file contains access keys"),
    PathRule("SENSITIVE_FILE_PATH", "netrc", re.compile(r"(^|/)\.netrc$", re.IGNORECASE), "netrc files contain login/password pairs"),
    PathRule("SENSITIVE_FILE_PATH", "git-credentials", re.compile(r"(^|/)\.git-credentials$", re.IGNORECASE), "git credential storage contains auth material"),
    PathRule("SENSITIVE_FILE_PATH", "npm-rc", re.compile(r"(^|/)\.npmrc$", re.IGNORECASE), "npm config may contain registry tokens"),
    PathRule("SENSITIVE_FILE_PATH", "pypi-rc", re.compile(r"(^|/)\.pypirc$", re.IGNORECASE), "PyPI config may contain package tokens"),
    PathRule("SENSITIVE_FILE_PATH", "pgpass", re.compile(r"(^|/)\.pgpass$", re.IGNORECASE), "PostgreSQL password file contains database passwords"),
    PathRule("SENSITIVE_FILE_PATH", "private-key", re.compile(r"\.(?:pem|key|p12|pfx|jks)$", re.IGNORECASE), "private key material must not be read by agents"),
    PathRule("SENSITIVE_FILE_PATH", "asg-fingerprint-key", re.compile(r"(^|/)\.local/share/agent-secret-guard/fingerprint\.key$", re.IGNORECASE), "ASG fingerprint key protects reviewed baselines"),
    PathRule("SENSITIVE_FILE_PATH", "ssh-key", re.compile(r"(^|/)\.ssh/(?:id_[A-Za-z0-9_-]+|.*_key)$", re.IGNORECASE), "SSH private keys must not be read by agents"),
    PathRule("SENSITIVE_FILE_PATH", "kubeconfig", re.compile(r"(^|/)\.kube/config$", re.IGNORECASE), "kubeconfig may contain cluster credentials"),
    PathRule("SENSITIVE_FILE_PATH", "gcloud-creds", re.compile(r"(^|/)\.config/gcloud/(?:application_default_credentials(?:\.json)?|legacy_credentials)(?:/|$)", re.IGNORECASE), "GCP credential stores must not be read by agents"),
    PathRule("SENSITIVE_FILE_PATH", "azure-token", re.compile(r"(^|/)\.azure/(?:accessTokens(?:\.json)?|msal)(?:/|$)", re.IGNORECASE), "Azure auth token stores must not be read by agents"),
    PathRule("SENSITIVE_FILE_PATH", "secrets-config", re.compile(r"(^|/)secrets?(?:\.[A-Za-z0-9_-]+)?\.(?:ya?ml|json|toml|env)$", re.IGNORECASE), "secret-named config files commonly contain values"),
    PathRule("SENSITIVE_FILE_PATH", "vault-token", re.compile(r"(^|/)\.vault-token$", re.IGNORECASE), "Vault token file contains plaintext auth material"),
]

COMMAND_RULES = [
    CommandRule("LEAKY_COMMAND", "process-args", re.compile(COMMAND_BOUNDARY + r"ps\s+(?:aux|axu|-ef|-eaf|-A|-eo)\b"), "process listing can expose argv secrets"),
    CommandRule("LEAKY_COMMAND", "ps-args-column", re.compile(COMMAND_BOUNDARY + r"ps\s+[^|;&]*-o\s+[^|;&]*(?:args|command|cmd)\b"), "process args column can expose argv secrets"),
    CommandRule("LEAKY_COMMAND", "pgrep-full", re.compile(COMMAND_BOUNDARY + r"pgrep\s+-[A-Za-z]*[afF][A-Za-z]*\b"), "pgrep full output can expose argv secrets"),
    CommandRule("LEAKY_COMMAND", "proc-cmdline-environ", re.compile(r"/proc/(?:self|[0-9]+)/(?:cmdline|environ)\b"), "procfs cmdline/environ exposes process secrets"),
    CommandRule("LEAKY_COMMAND", "env-dump", re.compile(COMMAND_BOUNDARY + r"(?:/usr/bin/|/bin/)?env(?:\s+(?:-0|-i))*\s*(?:$|[|;&])"), "environment dump exposes secret values"),
    CommandRule("LEAKY_COMMAND", "printenv", re.compile(COMMAND_BOUNDARY + r"(?:/usr/bin/|/bin/)?printenv(?:\s|$|[|;&])"), "printenv exposes secret values"),
    CommandRule("LEAKY_COMMAND", "set-dump", re.compile(r"(?:^|[|;&]|\$\()\s*set\s*(?:$|[|;&])"), "bare set dumps shell variables"),
    CommandRule("LEAKY_COMMAND", "export-dump", re.compile(COMMAND_BOUNDARY + r"export\s+(?:-p|--print-export)(?:\s|$|[|;&])"), "export dump exposes variable values"),
    CommandRule("LEAKY_COMMAND", "declare-dump", re.compile(COMMAND_BOUNDARY + r"(?:declare|typeset)\s+-[A-Za-z0-9-]*p(?:\s|$|[|;&])"), "declare/typeset dump exposes variable values"),
    CommandRule("LEAKY_COMMAND", "echo-secret-env", re.compile(COMMAND_BOUNDARY + r"(?:echo|printf)\s+[^|;&\r\n]*\$\{?[A-Za-z0-9_]*" + SENSITIVE_ENV_NAME_PATTERN + r"[A-Za-z0-9_]*"), "printing secret-named env vars exposes values"),
    CommandRule("LEAKY_COMMAND", "python-env-dump", re.compile(COMMAND_BOUNDARY + r"python[0-9.]*\s+.*(?:os\.environ|os\.getenv|environ\[)"), "Python env access can expose secret values"),
    CommandRule("LEAKY_COMMAND", "node-env-dump", re.compile(COMMAND_BOUNDARY + r"(?:node|bun)\s+[^|;&]*process\.env"), "Node process.env access can expose secret values"),
    CommandRule("LEAKY_COMMAND", "ruby-env-dump", re.compile(COMMAND_BOUNDARY + r"ruby\s+[^|;&]*\bENV\b"), "Ruby ENV access can expose secret values"),
    CommandRule("LEAKY_COMMAND", "deno-env-dump", re.compile(COMMAND_BOUNDARY + r"deno\s+(?:eval|run)[^|;&]*Deno\.env"), "Deno env access can expose secret values"),
    CommandRule("LEAKY_COMMAND", "curl-verbose", re.compile(COMMAND_BOUNDARY + r"curl\s+[^|;&]*(?:-v\b|--verbose\b|--trace(?:-ascii)?\b)"), "curl verbose/trace output can expose credentials"),
    CommandRule("LEAKY_COMMAND", "curl-user-credential", re.compile(COMMAND_BOUNDARY + r"curl\s+[^|;&]*(?:-u\s|--user(?:\s|=)|--proxy-user(?:\s|=))"), "curl user/password options expose credentials through argv"),
    CommandRule("LEAKY_COMMAND", "wget-debug", re.compile(COMMAND_BOUNDARY + r"wget\s+[^|;&]*(?:-d\b|--debug\b)"), "wget debug output can expose credentials"),
    CommandRule("LEAKY_COMMAND", "wget-password-argv", re.compile(COMMAND_BOUNDARY + r"wget\s+[^|;&]*(?:--password(?:\s|=)|--http-password(?:\s|=)|--ftp-password(?:\s|=)|--proxy-password(?:\s|=))"), "wget password arguments expose credentials through argv"),
    CommandRule("LEAKY_COMMAND", "tracing", re.compile(COMMAND_BOUNDARY + r"(?:strace|dtrace|ltrace)(?:\s|$)"), "process tracing can capture secret syscall/library arguments"),
    CommandRule("LEAKY_COMMAND", "read-secret-path", re.compile(COMMAND_BOUNDARY + READ_TOOL_PATTERN + r"\s+[^|;&]*" + SENSITIVE_PATH_PATTERN), "reading known secret-bearing files is unsafe"),
    CommandRule("LEAKY_COMMAND", "source-secret-path", re.compile(COMMAND_BOUNDARY + r"(?:source|\.)\s+[^|;&]*" + SENSITIVE_PATH_PATTERN), "sourcing known secret-bearing files is unsafe"),
    CommandRule("LEAKY_COMMAND", "supabase-status", re.compile(COMMAND_BOUNDARY + r"supabase\s+status(?:\s|$|[|;&])"), "supabase status prints local credentials"),
    CommandRule("LEAKY_COMMAND", "gcloud-print-token", re.compile(COMMAND_BOUNDARY + r"gcloud\s+[^|;&]*\bauth\s+(?:application-default\s+)?print-(?:access|identity)-token\b"), "gcloud auth print-token commands emit bearer tokens"),
    CommandRule("LEAKY_COMMAND", "gcloud-secret-access", re.compile(COMMAND_BOUNDARY + r"gcloud\s+[^|;&]*secrets\s+versions\s+access\b"), "GCP Secret Manager access prints secret payloads"),
    CommandRule("LEAKY_COMMAND", "gcloud-service-account-key-create", re.compile(COMMAND_BOUNDARY + r"gcloud\s+[^|;&]*\biam\s+service-accounts\s+keys\s+create\b"), "gcloud service account key creation writes a private key file"),
    CommandRule("LEAKY_COMMAND", "aws-secret-value", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*(?:secretsmanager\s+get-secret-value|ssm\s+get-parameter\b[^|;&]*--with-decryption|configure\s+get\s+(?:aws_secret_access_key|aws_session_token))"), "AWS CLI command prints decrypted secret material"),
    CommandRule("LEAKY_COMMAND", "aws-iam-access-key-create", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*iam\s+create-access-key\b"), "AWS IAM create-access-key emits a one-time secret access key"),
    CommandRule("LEAKY_COMMAND", "aws-iam-service-specific-credential", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*iam\s+(?:create|reset)-service-specific-credential\b"), "AWS IAM service-specific credential commands emit generated passwords or secrets"),
    CommandRule("LEAKY_COMMAND", "aws-ecr-login-password", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*ecr\s+get-login-password\b"), "AWS ECR get-login-password emits a registry login password"),
    CommandRule("LEAKY_COMMAND", "aws-ecr-authorization-token", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*ecr\s+get-authorization-token\b"), "AWS ECR get-authorization-token emits registry authorization data"),
    CommandRule("LEAKY_COMMAND", "aws-codeartifact-token", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*codeartifact\s+get-authorization-token\b"), "AWS CodeArtifact get-authorization-token emits repository authorization tokens"),
    CommandRule("LEAKY_COMMAND", "aws-sts-credentials", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*sts\s+(?:assume-role(?:-with-(?:saml|web-identity))?|get-session-token|get-federation-token)\b"), "AWS STS credential commands emit temporary access key, secret key, and session token material"),
    CommandRule("LEAKY_COMMAND", "aws-sso-role-credentials", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*sso\s+get-role-credentials\b"), "AWS SSO get-role-credentials emits temporary role credentials"),
    CommandRule("LEAKY_COMMAND", "aws-configure-export-credentials", re.compile(COMMAND_BOUNDARY + r"aws\s+[^|;&]*configure\s+export-credentials\b"), "AWS configure export-credentials prints resolved AWS credentials"),
    CommandRule("LEAKY_COMMAND", "az-access-token", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*account\s+get-access-token\b"), "Azure CLI get-access-token prints bearer access tokens"),
    CommandRule("LEAKY_COMMAND", "az-keyvault-secret-show", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*keyvault\s+secret\s+show(?:-deleted)?\b"), "Azure Key Vault secret show returns secret values"),
    CommandRule("LEAKY_COMMAND", "az-ad-service-principal-credential", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*ad\s+sp\s+(?:create-for-rbac|credential\s+reset)\b"), "Azure service principal create/reset commands emit passwords or credential locations"),
    CommandRule("LEAKY_COMMAND", "az-ad-app-credential-reset", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*ad\s+app\s+credential\s+reset\b"), "Azure app credential reset emits credentials that must be protected"),
    CommandRule("LEAKY_COMMAND", "az-acr-expose-token", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*acr\s+login\b(?=[^|;&]*--expose-token\b)"), "Azure Container Registry expose-token prints an access token"),
    CommandRule("LEAKY_COMMAND", "az-storage-account-keys", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*storage\s+account\s+keys\s+list\b"), "Azure Storage account keys list emits storage access keys"),
    CommandRule("LEAKY_COMMAND", "az-storage-connection-string", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*storage\s+account\s+show-connection-string\b"), "Azure Storage account show-connection-string emits account-key connection strings"),
    CommandRule("LEAKY_COMMAND", "az-acr-credential-show", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*acr\s+credential\s+show\b"), "Azure Container Registry credential show emits registry passwords"),
    CommandRule("LEAKY_COMMAND", "az-acr-token-credential-generate", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*acr\s+token\s+credential\s+generate\b"), "Azure Container Registry token credential generate emits token passwords"),
    CommandRule("LEAKY_COMMAND", "az-appservice-publishing-credentials", re.compile(COMMAND_BOUNDARY + r"az\s+[^|;&]*(?:webapp|functionapp)\s+deployment\s+list-publishing-(?:credentials|profiles)\b"), "Azure App Service publishing credential/profile commands emit deployment credentials"),
    CommandRule("LEAKY_COMMAND", "kubectl-raw-config", re.compile(COMMAND_BOUNDARY + r"kubectl\s+config\s+view\b[^|;&]*--raw\b"), "kubectl config view --raw displays sensitive data"),
    CommandRule("LEAKY_COMMAND", "kubectl-secret-output", re.compile(COMMAND_BOUNDARY + r"kubectl\s+(?:get|describe)\s+secrets?\b(?=[^|;&]*(?:-o\s*(?:json|yaml|go-template|jsonpath)|--output[=\s](?:json|yaml|go-template|jsonpath)|describe\s+secrets?))"), "kubectl secret output exposes secret data"),
    CommandRule("LEAKY_COMMAND", "vercel-env-pull", re.compile(COMMAND_BOUNDARY + r"vercel\s+env\s+pull\b"), "vercel env pull writes secrets into dotenv files"),
    CommandRule("LEAKY_COMMAND", "gh-auth-token", re.compile(COMMAND_BOUNDARY + r"gh\s+auth\s+(?:token|status[^|;&]*--show-token)\b"), "GitHub auth token output is a secret"),
    CommandRule("LEAKY_COMMAND", "git-config-dump", re.compile(COMMAND_BOUNDARY + r"git\s+config\s+(?:--list|--get-regexp)(?:\s|$|[|;&])"), "git config dumps can contain credentials"),
    CommandRule("LEAKY_COMMAND", "npm-auth-config", re.compile(COMMAND_BOUNDARY + r"npm\s+(?:token|whoami|config\s+(?:list|ls|get))\b"), "npm auth/config output may contain registry tokens"),
    CommandRule("LEAKY_COMMAND", "docker-login-password-argv", re.compile(COMMAND_BOUNDARY + r"docker\s+login\b(?=[^|;&]*(?:\s-p(?:\s|=)|\s--password(?!-stdin)\b))"), "docker login password arguments expose credentials through argv"),
    CommandRule("LEAKY_COMMAND", "twine-password-argv", re.compile(COMMAND_BOUNDARY + r"twine\s+upload\b(?=[^|;&]*(?:\s-p(?:\s|=)|\s--password\b))"), "twine password arguments expose package tokens through argv"),
    CommandRule("LEAKY_COMMAND", "secret-manager-read", re.compile(COMMAND_BOUNDARY + r"(?:op|pass|gopass|bw|lpass|doppler|vault)\s+[^|;&]*(?:read|show|get|download|password)\b"), "secret-manager read commands return plaintext secrets"),
    CommandRule("LEAKY_COMMAND", "macos-keychain-read", re.compile(COMMAND_BOUNDARY + r"security\s+find-[^|;&]*-password\b"), "macOS keychain password reads can print secrets"),
]


def contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def detector_possible(detector: RegexDetector, text: str, text_lower: str, special_present: dict[str, bool] | None = None) -> bool:
    hint_pattern = TOKEN_DETECTOR_HINT_PATTERNS.get(detector.kind)
    if hint_pattern is not None:
        return bool(hint_pattern.search(text))

    hints = TOKEN_DETECTOR_HINTS.get(detector.kind)
    if hints is None:
        return True
    if special_present is not None:
        hints = tuple(
            hint
            for hint in hints
            if all(present or char not in hint for char, present in special_present.items())
        )
        if not hints:
            return False
    return contains_any(text_lower, hints)


def has_sensitive_text_hint(text_lower: str) -> bool:
    return contains_any(text_lower, SENSITIVE_TEXT_HINTS)


def add_regex_findings(text: str, findings: list[Finding]) -> None:
    text_lower = text.lower()
    special_present = {char: char in text_lower for char in "_-.:"}
    for detector in TOKEN_DETECTORS:
        if not detector_possible(detector, text, text_lower, special_present):
            continue
        for match in detector.pattern.finditer(text):
            token = match.group(detector.group)
            if detector.validator and not detector.validator(token):
                continue
            start, end = match.span(detector.group)
            findings.append(Finding(detector.kind, start, end, detector.confidence, detector.reason))


def add_composite_findings(text: str, findings: list[Finding]) -> None:
    if not any(prefix in text for prefix in ("A3T", "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA")):
        return

    secret_matches = [match for match in AWS_SECRET_ACCESS_KEY_RE.finditer(text) if valid_provider_token(match.group(1))]
    if not secret_matches:
        return

    for key_match in AWS_ACCESS_KEY_ID_RE.finditer(text):
        value = key_match.group(0)
        if not valid_provider_token(value):
            continue
        if any(abs(key_match.start() - secret.start(1)) <= 4096 for secret in secret_matches):
            findings.append(
                Finding(
                    "AWS_ACCESS_KEY_ID",
                    key_match.start(),
                    key_match.end(),
                    0.93,
                    "AWS access key identifier paired with secret access key",
                )
            )


def infisical_secret_command_allowed(command: str) -> bool:
    if not re.search(r"\binfisical\s+secrets\b", command):
        return True
    if re.search(r"(?:--help\b|\s-h(?:\s|$))", command):
        return True
    if re.search(r"\binfisical\s+secrets\s+set\b", command):
        return bool(re.search(r"(?:^|\s)--file(?:\s|=)", command) or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*=@", command))
    if re.search(r"\bjq\b", command) and re.search(r"\.secretKey\b", command):
        return True
    if re.search(r"\binfisical\s+secrets\s+get\b", command) and "--plain" in command:
        if safe_infisical_plain_assignment(command):
            return True
        return any(
            re.search(pattern, command)
            for pattern in (
                r"\|\s*wc\b",
                r"\|\s*sha256sum\b",
                r"\|\s*sha1sum\b",
                r"\|\s*md5sum\b",
                r"\|\s*shasum\b",
                r"\|\s*grep\s+-q\b",
                r"\|\s*grep\s+-qc\b",
                r"\|\s*grep\s+-c\b",
                r">\s*\S",
                r">>\s*\S",
            )
        )
    return False


def shell_variable_reference_regex(variable_name: str) -> str:
    name = re.escape(variable_name)
    return rf"\$(?:{name}\b|\{{{name}\}})"


def split_unquoted_shell_statements(command: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        char = command[index]
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            index += 1
            continue
        if char in ("'", '"'):
            current.append(char)
            quote = char
            index += 1
            continue
        if char == "\n" or char == ";":
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            index += 1
            continue
        if char == "&" and index + 1 < len(command) and command[index + 1] == "&":
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            index += 2
            continue
        current.append(char)
        index += 1

    statement = "".join(current).strip()
    if statement:
        statements.append(statement)
    return statements


def is_curl_word(word: str) -> bool:
    candidate = word.rsplit("$(", 1)[-1].rsplit("/", 1)[-1]
    return candidate == "curl"


def iter_curl_header_arguments(command: str) -> Iterable[str]:
    for statement in split_unquoted_shell_statements(command):
        try:
            words = shlex.split(statement, posix=True)
        except ValueError:
            continue
        for index, word in enumerate(words):
            if not is_curl_word(word):
                continue
            cursor = index + 1
            while cursor < len(words):
                arg = words[cursor]
                if arg in {"-H", "--header"} and cursor + 1 < len(words):
                    yield words[cursor + 1]
                    cursor += 2
                    continue
                if arg.startswith("--header="):
                    yield arg.split("=", 1)[1]
                cursor += 1


def secret_reference_is_exfiltrated(command: str, variable_name: str | None = None) -> bool:
    ref = shell_variable_reference_regex(variable_name) if variable_name else r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})"
    for statement in split_unquoted_shell_statements(command):
        if not re.search(ref, statement):
            continue
        if re.search(COMMAND_BOUNDARY + r"(?:echo|printf)\s+[^|;&\r\n]*" + ref, statement):
            return True
        if re.search(COMMAND_BOUNDARY + r"(?:cat|tee)\b[^|;&\r\n]*" + ref, statement):
            return True
        safe_header_reference = any(re.search(ref, header) and safe_secret_reference_header(header) for header in iter_curl_header_arguments(statement))
        if not safe_header_reference and re.search(ref + r"[^|;&\r\n]*(?:>\s*\S|>>\s*\S)", statement):
            return True
    return False


def safe_infisical_plain_assignment(command: str) -> bool:
    assignments = list(
        re.finditer(
            r"(?m)(?:^|[\s;&])([A-Za-z_][A-Za-z0-9_]*)=\$\((?=[^)]*\binfisical\s+secrets\s+get\b)(?=[^)]*--plain\b)[^)]*\)",
            command,
        )
    )
    if not assignments:
        return False
    plain_gets = len(re.findall(r"\binfisical\s+secrets\s+get\b[^|;&\n)]*--plain\b", command))
    if plain_gets > len(assignments):
        return False
    safe_sink_seen = False
    for match in assignments:
        name = match.group(1)
        ref = shell_variable_reference_regex(name)
        if secret_reference_is_exfiltrated(command, name):
            return False
        if any(re.search(ref, header) and safe_secret_reference_header(header) for header in iter_curl_header_arguments(command)):
            safe_sink_seen = True
    return safe_sink_seen


def safe_infisical_plain_assignment_command(command: str) -> bool:
    return safe_infisical_plain_assignment(command)


def is_known_non_secret_literal(value: str) -> bool:
    candidate = normalize_candidate(value).lower()
    if candidate in {"", "true", "false", "yes", "no", "on", "off", "null", "none"}:
        return True
    if re.fullmatch(r"\d{1,5}", candidate):
        return True
    if candidate in {"localhost", "0.0.0.0", "127.0.0.1", "::1"}:
        return True
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", candidate):
        return True
    return is_credential_free_url(candidate)


def safe_dotenv_write_command(command: str) -> bool:
    if not re.search(r">\s*['\"]?[^|;&\s]*\.env(?:\.[A-Za-z0-9_-]+)?['\"]?", command):
        return False
    if "<<" not in command or "\n" not in command:
        return False
    body = command.split("\n", 1)[1]
    saw_assignment = False
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", stripped)
        if not match:
            continue
        saw_assignment = True
        key = match.group(1)
        value = match.group(2).strip().strip("\"'")
        if is_known_non_secret_literal(value):
            continue
        if is_sensitive_key(key) or credible_assignment_value(value, env_context=True, allow_plain_identifier=True):
            return False
    return saw_assignment


def safe_env_projection_command(command: str) -> bool:
    normalized = " ".join(command.strip().split())
    grep_stage = r"(?:\|\s*(?:grep|rg)\s+[-A-Za-z0-9_ '\".^$]+)?"
    cut_stage = r"cut\s+-d=?['\"]?=['\"]?\s+-f1"
    sed_stage = r"sed\s+['\"]s/=.*//['\"]"
    awk_stage = r"awk\s+-F=?['\"]?=['\"]?\s+['\"]?\{print \$1\}['\"]?"
    env_stage = r"(?:/usr/bin/|/bin/)?env"
    patterns = (
        rf"{env_stage}\s*\|\s*{cut_stage}\s*{grep_stage}",
        rf"{env_stage}\s*\|\s*(?:grep|rg)\s+[-A-Za-z0-9_ '\".^$]+\s*\|\s*{cut_stage}\s*{grep_stage}",
        rf"{env_stage}\s*\|\s*{sed_stage}\s*{grep_stage}",
        rf"{env_stage}\s*\|\s*{awk_stage}\s*{grep_stage}",
    )
    return any(re.fullmatch(pattern, normalized) for pattern in patterns)


def normalize_file_path_value(value: str) -> str:
    return value.strip().strip("\"'").replace("\\", "/")


def file_path_policy_applies(surface: str, path: str) -> bool:
    if surface == "file-path":
        return True
    pre_tool_surfaces = {"tool-input", "codex:PreToolUse", "codex:PermissionRequest"}
    if surface not in pre_tool_surfaces:
        return False
    terminal = json_terminal_key(path).lower().replace("-", "_")
    return terminal in {"file", "file_path", "filepath", "filename", "path"}


def add_file_path_findings(text: str, findings: list[Finding], *, surface: str, path: str) -> None:
    if not file_path_policy_applies(surface, path):
        return
    candidate = normalize_file_path_value(text)
    if not candidate or ENV_TEMPLATE_PATH_RE.search(candidate):
        return
    for rule in PATH_RULES:
        if rule.pattern.search(candidate):
            findings.append(Finding(rule.kind, 0, len(text), rule.confidence, f"{rule.reason}; rule={rule.name}"))
            return


def split_single_unquoted_pipe(command: str) -> tuple[str, str] | None:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in command:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char in ("'", '"'):
            current.append(char)
            quote = char
            continue
        if char == "|":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    parts.append("".join(current).strip())
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def has_unquoted_shell_metachar(command: str, chars: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in command:
        if quote:
            if char == quote:
                quote = None
            continue
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char in chars:
            return True
    return False


def has_unquoted_shell_control(command: str) -> bool:
    return has_unquoted_shell_metachar(command, ";&")


def has_unquoted_pipe(command: str) -> bool:
    return has_unquoted_shell_metachar(command, "|")


def safe_template_file_read_command(command: str) -> bool:
    if has_unquoted_shell_control(command) or has_unquoted_pipe(command):
        return False
    normalized = " ".join(command.strip().split())
    return re.fullmatch(
        rf"{READ_TOOL_PATTERN}\s+[^|;&]*\.env\.(?:example|sample|template|dist)['\"]?",
        normalized,
        flags=re.IGNORECASE,
    ) is not None


def safe_redacted_process_listing_command(command: str) -> bool:
    parts = split_single_unquoted_pipe(command)
    if parts is None:
        return False
    process_stage, redactor_stage = (" ".join(part.strip().split()) for part in parts)
    if has_unquoted_shell_control(process_stage) or has_unquoted_shell_control(redactor_stage):
        return False
    process_patterns = (
        r"ps\s+(?:aux|axu|-ef|-eaf|-A|-eo)\b.*",
        r"ps\s+.*-o\s+.*(?:args|command|cmd)\b.*",
        r"pgrep\s+-[A-Za-z]*[afF][A-Za-z]*\b.*",
    )
    redactor_pattern = (
        r"(?:\S*/)?(?:"
        r"asg-stream-redact|secret-filter|"
        r"asg-fast\s+redact(?:\s+--surface\s+(?:tool-output|stream|text))?|"
        r"agent-secret-guard\s+redact(?:\s+--surface\s+(?:tool-output|stream|text))?"
        r")"
    )
    return (
        any(re.fullmatch(pattern, process_stage) for pattern in process_patterns)
        and re.fullmatch(redactor_pattern, redactor_stage) is not None
    )


def add_curl_header_policy_findings(text: str, findings: list[Finding]) -> None:
    for header in iter_curl_header_arguments(text):
        if not credible_secret_header_value(header):
            continue
        findings.append(
            Finding(
                "LEAKY_COMMAND",
                0,
                len(text),
                0.93,
                "curl header contains a literal credential value; rule=curl-auth-header",
            )
        )
        return


def add_command_policy_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    if surface != "bash-command":
        return
    if safe_bash_command_allowed(text):
        return

    for rule in COMMAND_RULES:
        if rule.pattern.search(text):
            findings.append(Finding(rule.kind, 0, len(text), rule.confidence, f"{rule.reason}; rule={rule.name}"))
    add_curl_header_policy_findings(text, findings)

    if not infisical_secret_command_allowed(text):
        findings.append(
            Finding(
                "SECRET_MANAGER_COMMAND",
                0,
                len(text),
                0.93,
                "Infisical secrets command can emit or log plaintext secret values",
            )
        )


def safe_bash_command_allowed(command: str) -> bool:
    normalized = " ".join(command.strip().split())
    if (
        safe_env_projection_command(command)
        or safe_dotenv_write_command(command)
        or safe_template_file_read_command(command)
        or safe_redacted_process_listing_command(command)
    ):
        return True
    safe_patterns = (
        r"infisical\s+run\b.*",
        r"infisical\s+secrets\b.*\|\s*jq\b.*\.secretKey.*",
    )
    return any(re.fullmatch(pattern, normalized) for pattern in safe_patterns)


def add_structural_findings(text: str, findings: list[Finding]) -> None:
    if "PRIVATE KEY" in text:
        for match in PGP_PRIVATE_KEY_BLOCK_RE.finditer(text):
            findings.append(Finding("PRIVATE_KEY_BLOCK", match.start(), match.end(), 0.99, "complete OpenPGP private key block"))

        for match in PEM_BLOCK_RE.finditer(text):
            findings.append(Finding("PRIVATE_KEY_BLOCK", match.start(), match.end(), 0.99, "complete private key block"))

        for match in PGP_PRIVATE_KEY_HEADER_RE.finditer(text):
            if not any(existing.start <= match.start() < existing.end for existing in findings):
                block_end = text.find("\n\n", match.end())
                end = len(text) if block_end == -1 else block_end
                findings.append(Finding("PRIVATE_KEY_BLOCK", match.start(), end, 0.94, "OpenPGP private key header without matching footer"))

        for match in PEM_HEADER_RE.finditer(text):
            if not any(existing.start <= match.start() < existing.end for existing in findings):
                block_end = text.find("\n\n", match.end())
                end = len(text) if block_end == -1 else block_end
                findings.append(Finding("PRIVATE_KEY_BLOCK", match.start(), end, 0.94, "private key header without matching footer"))

    if "SECRET VALUE" not in text:
        return

    lines = text.splitlines(keepends=True)
    offset = 0
    in_infisical = False
    table_start = 0
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("\u250c"):
            in_infisical = True
            table_start = offset
        if in_infisical and stripped.startswith("\u2514"):
            findings.append(Finding("INFISICAL_TABLE", table_start, offset + len(line), 0.99, "Infisical table with secret value column"))
            in_infisical = False
        offset += len(line)
    if in_infisical:
        findings.append(Finding("INFISICAL_TABLE", table_start, len(text), 0.99, "unterminated Infisical secret table"))


def add_auth_and_url_findings(text: str, findings: list[Finding]) -> None:
    text_lower = text.lower()
    if "authorization" in text_lower:
        for match in AUTH_HEADER_RE.finditer(text):
            if credible_transport_secret_value(match.group(1)):
                findings.append(Finding("AUTH_HEADER", match.start(1), match.end(1), 0.92, "Authorization header credential"))

    if any(header in text_lower for header in ("x-api-key", "api-key", "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token", "x-session-token")):
        for match in SENSITIVE_HEADER_RE.finditer(text):
            value = normalize_candidate(match.group(1))
            if credible_assignment_value(value, env_context=True, allow_plain_identifier=True):
                findings.append(Finding("SENSITIVE_HTTP_HEADER", match.start(1), match.end(1), 0.9, "sensitive HTTP header value"))

    if "cookie" in text_lower:
        for match in COOKIE_HEADER_RE.finditer(text):
            header_name = match.group(1).lower()
            header_value = match.group(2)
            value_offset = match.start(2)
            segments = header_value.split(";")
            if header_name == "set-cookie":
                segments = segments[:1]
            cursor = 0
            for segment in segments:
                segment_start = header_value.find(segment, cursor)
                cursor = segment_start + len(segment) + 1 if segment_start >= 0 else cursor
                if "=" not in segment:
                    continue
                name, raw_value = segment.split("=", 1)
                cookie_name = name.strip()
                cookie_value = normalize_candidate(raw_value.strip())
                if not cookie_name or cookie_name.lower() in COOKIE_ATTRIBUTE_NAMES:
                    continue
                if not (
                    SENSITIVE_COOKIE_NAME_RE.search(cookie_name)
                    or cookie_name.startswith(("__Host-", "__Secure-", "__Http-"))
                ):
                    continue
                if not credible_assignment_value(cookie_value, env_context=True, allow_plain_identifier=True):
                    continue
                relative_start = segment.find(raw_value)
                start = value_offset + segment_start + relative_start if segment_start >= 0 and relative_start >= 0 else value_offset
                findings.append(Finding("HTTP_COOKIE_SECRET", start, start + len(raw_value.strip()), 0.9, "sensitive cookie value"))

    has_url = "://" in text
    if has_url and "@" in text:
        for match in URL_CREDENTIAL_RE.finditer(text):
            end = match.end()
            while end > match.start() and text[end - 1] in ".,;)]}":
                end -= 1
            value = text[match.start():end]
            if is_placeholder_credential_url(value) and credential_url_placeholder_context(text, match.start(), end):
                continue
            findings.append(Finding("CREDENTIAL_URL", match.start(), end, 0.94, "URL contains username/password credentials"))

    if ("?" in text or "&" in text) and has_sensitive_text_hint(text_lower):
        for match in QUERY_SECRET_RE.finditer(text):
            value = normalize_candidate(match.group(2))
            if credible_transport_secret_value(value):
                findings.append(Finding("URL_QUERY_SECRET", match.start(2), match.end(2), 0.88, "sensitive query parameter value"))

    if has_url and "%" in text:
        for match in URL_RE.finditer(text):
            url = match.group(0)
            if "%" not in url:
                continue
            decoded = unquote(url)
            if decoded == url:
                continue
            decoded_findings = scan_text(decoded, surface="decoded-url", threshold=0.65)
            if decoded_findings:
                findings.append(Finding("ENCODED_SECRET_URL", match.start(), match.end(), 0.9, "URL-decoded content contains a secret"))


ASSIGNMENT_RE = re.compile(
    r"(?P<key>[\"']?[A-Za-z_][A-Za-z0-9_.-]*[\"']?)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>[\"']?)"
    r"(?P<value>[^\"'\s,#}\]]{4,})"
)
ASSIGNMENT_KEY_HINT_RE = re.compile(
    r"(?i)(?:^|[\s,{[(])"
    r"[\"']?[A-Za-z_][A-Za-z0-9_.-]*"
    r"(?:api|key|secret|token|password|passwd|pwd|credential|private|auth|"
    r"bearer|access|refresh|session|signing|encryption|client|webhook|"
    r"database|db|connection|string)"
    r"[A-Za-z0-9_.-]*[\"']?\s*[:=]"
)
SOURCE_LISTING_PREFIX_RE = re.compile(
    r"^(?P<path>(?:[A-Za-z]:)?(?=[^:\r\n]{1,1000}(?:[/.\\]))[^:\r\n]{1,1000}):\d+(?::\d+)?:"
)


def strip_source_listing_prefix(line: str) -> tuple[str, int]:
    match = SOURCE_LISTING_PREFIX_RE.match(line)
    if not match:
        return line, 0
    return line[match.end():], match.end()


def env_template_source_listing_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    line_start = 0
    for line in text.splitlines(keepends=True):
        match = SOURCE_LISTING_PREFIX_RE.match(line)
        if match and ENV_TEMPLATE_PATH_RE.search(match.group("path").replace("\\", "/")):
            spans.append((line_start, line_start + len(line)))
        line_start += len(line)
    return spans


def finding_in_span(finding: Finding, spans: list[tuple[int, int]]) -> bool:
    return any(start <= finding.start and finding.end <= end for start, end in spans)


def add_assignment_findings(text: str, findings: list[Finding], *, path: str = "", surface: str = "") -> None:
    env_context = env_like_context(path, surface)
    text_lower = text.lower()
    if (":" not in text and "=" not in text) or not has_sensitive_text_hint(text_lower) or not ASSIGNMENT_KEY_HINT_RE.search(text):
        return

    line_start = 0
    for line in text.splitlines(keepends=True):
        scan_line, prefix_len = strip_source_listing_prefix(line)
        stripped = scan_line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            line_start += len(line)
            continue

        for match in ASSIGNMENT_RE.finditer(scan_line):
            key = match.group("key").strip("\"'")
            if not is_sensitive_key(key):
                continue
            if is_sensitive_identifier_key(key):
                continue
            value = match.group("value")
            if not credible_assignment_value(value, env_context=env_context):
                continue
            confidence = 0.88 if env_context else 0.82
            findings.append(
                Finding(
                    "SENSITIVE_ASSIGNMENT",
                    line_start + prefix_len + match.start("value"),
                    line_start + prefix_len + match.end("value"),
                    confidence,
                    "sensitive key assignment with credible secret-shaped value",
                )
            )
        line_start += len(line)


HIGH_ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9_/-])([A-Za-z0-9_+/=-]{32,})(?![A-Za-z0-9_/-])")
BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9_+/-])([A-Za-z0-9_+/-]{24,}={0,2})(?![A-Za-z0-9_+/-])")
STRING_LITERAL_RE = re.compile(
    r"(?P<prefix>[rRuUbB]{0,2})"
    r"(?P<quote>['\"`])"
    r"(?P<body>(?:\\.|(?! (?P=quote)).)*?)"
    r"(?P=quote)",
    re.VERBOSE | re.DOTALL,
)
LITERAL_JOINER_RE = re.compile(r"^(?:\s*\+\s*|\s*\\\s*|\s*)$")
IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
CONST_STRING_ASSIGNMENT_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:export|declare|public|private|protected|static|final|readonly|const|let|var)\s+)*"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=\n;]+)?=\s*(?P<expr>[^\n#;]+)"
)
LINE_CONTINUATION_RE = re.compile(r"(?:[^\r\n]*\\\r?\n[ \t]*)+[^\r\n]*")
YAML_BLOCK_HEADER_RE = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*:\s*(?P<style>[|>])[-+]?\s*(?:#[^\r\n]*)?\r?\n"
)
TOKEN_FRAGMENT_RE = re.compile(r"[A-Za-z0-9._~:/@+%?&=-]{1,256}")
SPLIT_LITERAL_HINTS = (
    "sk-",
    "proj",
    "api0",
    "admin",
    "ghp_",
    "github_pat_",
    "glpat-",
    "xox",
    "secret",
    "token",
    "key",
    "hf_",
    "vca_",
    "vcp_",
    "cfut_",
    "cfat_",
    "lin_api_",
    "ntn_",
    "sntrys_",
)


def is_path_like_candidate(value: str) -> bool:
    candidate = normalize_candidate(value)
    if "://" in candidate or ("/" not in candidate and "\\" not in candidate):
        return False

    parts = [part for part in re.split(r"[\\/]+", candidate) if part]
    if len(parts) < 2:
        return False

    path_words = {
        ".claude-home",
        ".codex",
        "agents",
        "bin",
        "cache",
        "configs",
        "docs",
        "e2e",
        "lib",
        "node_modules",
        "plugins",
        "scripts",
        "skills",
        "src",
        "test",
        "tests",
    }
    lowered_parts = [part.lower() for part in parts]
    if any(part in path_words for part in lowered_parts):
        return True
    if len(parts) >= 3 and sum(bool(re.fullmatch(r"[a-z0-9_.-]{1,40}", part)) for part in lowered_parts) >= 2:
        return True
    return bool(re.search(r"(?i)(?:^|[\\/])[^\\/]+\.(?:md|mjs|js|ts|tsx|json|ya?ml|toml|py|rs|go|txt)$", candidate))


def is_ref_or_path_slug(value: str) -> bool:
    """Suppress VCS refs and file paths that split into short word-runs.

    Covers owner/branch slugs, jj/git bookmark names, "Merge pull request from
    owner/branch" sources, and slash-prefixed doc paths like
    ``../../Some_File_Name``. A packed secret instead carries one long opaque
    run, so we only suppress when every alphanumeric run is short.

    Safety: a candidate is only suppressed when it contains a path separator
    (``/`` or ``\\``) *and* a ``-`` or ``_``, with no base64 fill (``+``/``=``).
    Standard base64 uses ``+``/``/`` but never ``-``/``_``; url-safe base64 uses
    ``-``/``_`` but never ``/`` -- so this shape matches neither encoding, nor a
    bare random API key (which has no separators).
    """
    candidate = normalize_candidate(value)
    if ("/" not in candidate and "\\" not in candidate) or "://" in candidate:
        return False
    if "+" in candidate or "=" in candidate:
        return False
    if "-" not in candidate and "_" not in candidate:
        return False
    if not re.fullmatch(r"[A-Za-z0-9._/\\-]+", candidate):
        return False
    runs = [run for run in re.split(r"[^A-Za-z0-9]+", candidate) if run]
    if len(runs) < 3:
        return False
    return all(len(run) <= 16 for run in runs)


def is_short_known_provider_token(value: str) -> bool:
    candidate = normalize_candidate(value)
    if candidate.startswith("pypi-"):
        return not bool(re.fullmatch(r"pypi-[A-Za-z0-9_-]{85,}", candidate))
    return False


def decode_string_literal(match: re.Match[str]) -> str | None:
    quote = match.group("quote")
    body = match.group("body")
    prefix = match.group("prefix").lower()
    if quote == "`":
        if "${" in body:
            return None
        return re.sub(r"\\([\\`$])", r"\1", body)
    if "b" in prefix:
        return None
    if "r" in prefix:
        return body
    try:
        return ast.literal_eval(quote + body + quote)
    except Exception:
        return None


def joined_literal_runs(text: str) -> Iterable[tuple[int, int, str]]:
    if len(text) > 2_000_000 or not any(quote in text for quote in ("'", '"', "`")):
        return
    text_lower = text.lower()
    if not ("+" in text or "\\\n" in text or ".join" in text_lower or contains_any(text_lower, SPLIT_LITERAL_HINTS)):
        return

    matches = list(STRING_LITERAL_RE.finditer(text))
    if len(matches) < 2:
        return

    index = 0
    while index < len(matches) - 1:
        first = matches[index]
        decoded = decode_string_literal(first)
        if decoded is None:
            index += 1
            continue

        pieces = [decoded]
        run_start = first.start()
        run_end = first.end()
        cursor = index
        while cursor + 1 < len(matches):
            separator = text[matches[cursor].end(): matches[cursor + 1].start()]
            if len(separator) > 32 or not LITERAL_JOINER_RE.fullmatch(separator):
                break
            next_decoded = decode_string_literal(matches[cursor + 1])
            if next_decoded is None:
                break
            pieces.append(next_decoded)
            run_end = matches[cursor + 1].end()
            cursor += 1

        if len(pieces) >= 2:
            if any(is_shell_variable_reference(piece) or "$" in piece for piece in pieces):
                index = max(cursor, index + 1)
                continue
            joined = "".join(pieces)
            if 16 <= len(joined) <= 1024:
                yield run_start, run_end, joined
            index = max(cursor, index + 1)
        else:
            index += 1


def bracket_literal_list_runs(text: str) -> Iterable[tuple[int, int, str]]:
    if len(text) > 2_000_000 or "[" not in text or "]" not in text or "join" not in text.lower():
        return
    opener = 0
    while True:
        start = text.find("[", opener)
        if start < 0:
            return
        end = text.find("]", start + 1)
        if end < 0:
            return
        opener = start + 1
        if end - start > 2048:
            continue

        before = text[max(0, start - 32):start]
        after = text[end + 1:end + 40]
        joined_after = bool(re.match(r"\s*\.\s*join\s*\(\s*(?:\"\"|''|``)?\s*\)", after))
        joined_before = bool(re.search(r"(?:\"\"|''|``)\s*\.\s*join\s*\(\s*$", before))
        if not (joined_after or joined_before):
            continue

        body = text[start + 1:end]
        matches = list(STRING_LITERAL_RE.finditer(body))
        if len(matches) < 2:
            continue
        remainder = STRING_LITERAL_RE.sub("", body)
        if not re.fullmatch(r"[\s,]*", remainder):
            continue
        pieces = []
        for match in matches:
            decoded = decode_string_literal(match)
            if decoded is None:
                pieces = []
                break
            pieces.append(decoded)
        if not pieces:
            continue
        joined = "".join(pieces)
        if 16 <= len(joined) <= 1024:
            yield start, end + 1, joined


def dedupe_static_spans(spans: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    seen: set[tuple[int, int]] = set()
    result: list[tuple[int, int]] = []
    for start, end in spans:
        if end <= start or (start, end) in seen:
            continue
        seen.add((start, end))
        result.append((start, end))
        if len(result) >= 32:
            break
    return tuple(result)


def split_top_level(text: str, separator: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for idx, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in ("'", '"', "`"):
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            depth = max(0, depth - 1)
            continue
        if char == separator and depth == 0:
            spans.append((start, idx))
            start = idx + 1
    spans.append((start, len(text)))
    return spans


def matching_bracket_index(text: str, start: int) -> int:
    if start >= len(text) or text[start] not in "([{":
        return -1
    opener = text[start]
    closer = {"(": ")", "[": "]", "{": "}"}[opener]
    depth = 0
    quote = ""
    escaped = False
    for idx in range(start, len(text)):
        char = text[idx]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in ("'", '"', "`"):
            quote = char
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def trim_expression(expr: str, base_offset: int) -> tuple[str, int]:
    stripped_left = len(expr) - len(expr.lstrip())
    stripped = expr.strip()
    return stripped, base_offset + stripped_left


def strip_outer_parens(expr: str, base_offset: int) -> tuple[str, int]:
    expr, base_offset = trim_expression(expr, base_offset)
    while expr.startswith("("):
        end = matching_bracket_index(expr, 0)
        if end != len(expr) - 1:
            break
        expr, base_offset = trim_expression(expr[1:-1], base_offset + 1)
    return expr, base_offset


def eval_static_string_term(expr: str, base_offset: int, constants: dict[str, StaticString]) -> StaticString | None:
    expr, base_offset = strip_outer_parens(expr, base_offset)
    if not expr:
        return None

    literal = STRING_LITERAL_RE.match(expr)
    if literal and literal.end() == len(expr):
        decoded = decode_string_literal(literal)
        if decoded is None:
            return None
        return StaticString(decoded, ((base_offset + literal.start(), base_offset + literal.end()),))

    if IDENTIFIER_RE.fullmatch(expr):
        return constants.get(expr)

    return eval_static_join_expression(expr, base_offset, constants)


def eval_static_join_expression(expr: str, base_offset: int, constants: dict[str, StaticString]) -> StaticString | None:
    if "join" not in expr:
        return None
    list_start = expr.find("[")
    if list_start < 0:
        return None
    list_end = matching_bracket_index(expr, list_start)
    if list_end < 0:
        return None

    before = expr[:list_start]
    after = expr[list_end + 1:]
    joined_after = bool(re.fullmatch(r"\s*\.\s*join\s*\(\s*(?:\"\"|''|``)?\s*\)\s*", after))
    joined_before = bool(
        re.fullmatch(r"\s*(?:\"\"|''|``)\s*\.\s*join\s*\(\s*", before)
        and re.fullmatch(r"\s*\)\s*", after)
    )
    if not (joined_after or joined_before):
        return None

    body = expr[list_start + 1:list_end]
    parts = split_top_level(body, ",")
    if len(parts) < 2 or len(parts) > 16:
        return None

    values: list[str] = []
    spans: list[tuple[int, int]] = []
    for start, end in parts:
        part = eval_static_string_expr(body[start:end], base_offset + list_start + 1 + start, constants)
        if part is None:
            return None
        values.append(part.value)
        spans.extend(part.spans)

    value = "".join(values)
    if len(value) > 1024:
        return None
    return StaticString(value, dedupe_static_spans(spans))


def eval_static_string_expr(expr: str, base_offset: int, constants: dict[str, StaticString]) -> StaticString | None:
    expr, base_offset = strip_outer_parens(expr, base_offset)
    if not expr:
        return None

    joined = eval_static_join_expression(expr, base_offset, constants)
    if joined is not None:
        return joined

    parts = split_top_level(expr, "+")
    if len(parts) == 1:
        return eval_static_string_term(expr, base_offset, constants)
    if len(parts) > 16:
        return None

    values: list[str] = []
    spans: list[tuple[int, int]] = []
    for start, end in parts:
        part = eval_static_string_term(expr[start:end], base_offset + start, constants)
        if part is None:
            return None
        values.append(part.value)
        spans.extend(part.spans)

    value = "".join(values)
    if len(value) > 1024:
        return None
    return StaticString(value, dedupe_static_spans(spans))


def static_string_dataflow_runs(text: str) -> Iterable[tuple[tuple[tuple[int, int], ...], str]]:
    if (
        len(text) > 2_000_000
        or "=" not in text
        or not any(quote in text for quote in ("'", '"', "`"))
        or not contains_any(text.lower(), SPLIT_LITERAL_HINTS)
    ):
        return

    constants: dict[str, StaticString] = {}
    for match in CONST_STRING_ASSIGNMENT_RE.finditer(text):
        value = eval_static_string_expr(match.group("expr"), match.start("expr"), constants)
        if value is None or len(value.value) > 1024:
            continue

        expr_span = (match.start("expr"), match.end("expr"))
        stored = StaticString(value.value, dedupe_static_spans((*value.spans, expr_span)))
        if len(constants) >= 200:
            constants.pop(next(iter(constants)))
        constants[match.group("name")] = stored

        if 16 <= len(stored.value) <= 1024:
            yield stored.spans, stored.value


def line_continuation_runs(text: str) -> Iterable[tuple[int, int, str]]:
    if len(text) > 2_000_000 or "\\\n" not in text and "\\\r\n" not in text:
        return
    for match in LINE_CONTINUATION_RE.finditer(text):
        raw = match.group(0)
        if len(raw) > 4096:
            continue
        lowered = raw.lower()
        if not (has_sensitive_text_hint(lowered) or contains_any(lowered, PROVIDER_TOKEN_HINTS)):
            continue
        reconstructed = re.sub(r"\\\r?\n[ \t]*", "", raw).strip()
        if 16 <= len(reconstructed) <= 2048:
            yield match.start(), match.end(), reconstructed


def yaml_block_scalar_runs(text: str) -> Iterable[tuple[int, int, str]]:
    if len(text) > 2_000_000 or not any(marker in text for marker in ("|\n", "|\r\n", ">\n", ">\r\n")):
        return
    for match in YAML_BLOCK_HEADER_RE.finditer(text):
        key = match.group("key")
        base_indent = len(match.group("indent").expandtabs(2))
        cursor = match.end()
        block_end = cursor
        fragments: list[str] = []

        while cursor < len(text):
            next_newline = text.find("\n", cursor)
            line_end = len(text) if next_newline < 0 else next_newline + 1
            line = text[cursor:line_end]
            content = line.rstrip("\r\n")
            stripped = content.strip()
            indent = len(content) - len(content.lstrip(" \t"))

            if stripped and indent <= base_indent:
                break
            block_end = line_end
            if stripped:
                fragments.append(stripped)
            cursor = line_end

        if not fragments or block_end <= match.end() or block_end - match.start() > 4096:
            continue
        if not is_sensitive_key(key) and not contains_any(" ".join(fragments).lower(), PROVIDER_TOKEN_HINTS):
            continue
        if not all(TOKEN_FRAGMENT_RE.fullmatch(fragment) for fragment in fragments):
            continue

        compact = "".join(fragments)
        folded = " ".join(fragments)
        for reconstructed in (compact, folded):
            if 16 <= len(reconstructed) <= 2048:
                yield match.start(), block_end, reconstructed


def add_joined_literal_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    if surface.startswith(("decoded-", "joined-literal")):
        return
    literal_runs = list(joined_literal_runs(text) or ())
    literal_runs.extend(bracket_literal_list_runs(text) or ())
    for start, end, joined in literal_runs:
        joined_findings = scan_text(joined, surface="joined-literal", threshold=0.8)
        if joined_findings:
            findings.append(
                Finding(
                    "OBFUSCATED_SECRET_LITERAL",
                    start,
                    end,
                    0.9,
                    "concatenated string literals reconstruct secret material",
                )
            )
    for spans, joined in static_string_dataflow_runs(text) or ():
        joined_findings = scan_text(joined, surface="joined-literal", threshold=0.8)
        if not joined_findings:
            continue
        for start, end in spans:
            findings.append(
                Finding(
                    "OBFUSCATED_SECRET_LITERAL",
                    start,
                    end,
                    0.9,
                    "string constants reconstruct secret material",
                )
            )
    for start, end, reconstructed in line_continuation_runs(text) or ():
        reconstructed_findings = scan_text(reconstructed, surface="joined-literal", threshold=0.8)
        if reconstructed_findings:
            findings.append(
                Finding(
                    "OBFUSCATED_SECRET_LITERAL",
                    start,
                    end,
                    0.9,
                    "line continuation reconstructs secret material",
                )
            )
    for start, end, reconstructed in yaml_block_scalar_runs(text) or ():
        reconstructed_findings = scan_text(reconstructed, surface="joined-literal", threshold=0.8)
        if reconstructed_findings:
            findings.append(
                Finding(
                    "OBFUSCATED_SECRET_LITERAL",
                    start,
                    end,
                    0.9,
                    "multiline scalar reconstructs secret material",
                )
            )


def is_vercel_deployment_metadata_identifier(value: str, line: str) -> bool:
    candidate = normalize_candidate(value)
    if not re.fullmatch(r"dpl_[A-Za-z0-9_-]{24,96}", candidate):
        return False
    if re.search(r"(?i)[\"']?id[\"']?\s*[:=]\s*[\"']?" + re.escape(candidate), line):
        return True
    return bool(re.search(r"https://vercel\.com/[^\s\"']+/" + re.escape(candidate) + r"(?:[\"'\s,}]|$)", line))


def is_public_platform_identifier(value: str, line: str) -> bool:
    candidate = normalize_candidate(value)
    possible_values = [candidate]
    for separator in ("=", ":"):
        if separator in candidate:
            possible_values.append(candidate.split(separator, 1)[1].strip())

    contexts = (
        ("VERCEL_ORG_ID", r"team_[A-Za-z0-9]{12,96}"),
        ("VERCEL_PROJECT_ID", r"prj_[A-Za-z0-9]{12,96}"),
        ("SUPABASE_PROJECT_ID", r"[a-z0-9]{20}"),
    )
    for key, pattern in contexts:
        if not re.search(rf"\b{re.escape(key)}\b", line):
            continue
        if any(re.fullmatch(pattern, item) for item in possible_values):
            return True
    return False


def add_high_entropy_findings(text: str, findings: list[Finding]) -> None:
    if not HIGH_ENTROPY_RE.search(text):
        return
    line_start = 0
    for line in text.splitlines(keepends=True):
        scan_line, prefix_len = strip_source_listing_prefix(line)
        for match in HIGH_ENTROPY_RE.finditer(scan_line):
            value = normalize_candidate(match.group(1))
            rhs_values = [value.split(separator, 1)[1] for separator in ("=", ":") if separator in value]
            if (
                is_placeholder(value)
                or is_uuid(value)
                or is_hex_digest(value)
                or is_sequential(value)
                or is_prefixed_placeholder(value)
                or is_incomplete_known_provider_token(value)
                or is_public_identifier(value)
                or (value.startswith("eyJ") and scan_line[max(0, match.start(1) - 3) : match.start(1)].lower() == "pk.")
                or is_lowercase_slug(value)
                or is_schema_identifier_candidate(value)
                or is_vercel_deployment_metadata_identifier(value, scan_line)
                or is_public_platform_identifier(value, scan_line)
                or any(char.isspace() for char in value)
                or is_path_like_candidate(value)
                or is_ref_or_path_slug(value)
                or is_short_known_provider_token(value)
                or AWS_ACCESS_KEY_ID_RE.fullmatch(value)
                or any(AWS_ACCESS_KEY_ID_RE.fullmatch(normalize_candidate(rhs)) for rhs in rhs_values)
                or any(is_ref_or_path_slug(rhs) for rhs in rhs_values)
                or any(is_obvious_non_secret_assignment_value(rhs) for rhs in rhs_values)
            ):
                continue
            decoded = maybe_decode_base64(value)
            if decoded:
                if not decoded_text_worth_scanning(decoded):
                    continue
                if not scan_text(decoded, surface="decoded-base64:1", threshold=0.8):
                    continue
            if len(value) > 120:
                continue
            entropy = shannon_entropy(value)
            if entropy >= 4.2 and character_classes(value) >= 3:
                findings.append(
                    Finding(
                        "HIGH_ENTROPY_TOKEN",
                        line_start + prefix_len + match.start(1),
                        line_start + prefix_len + match.end(1),
                        0.66,
                        "bare high-entropy token",
                    )
                )
        line_start += len(line)


def maybe_decode_base64(value: str) -> str | None:
    candidate = normalize_candidate(value)
    if len(candidate) < 24 or len(candidate) > 512:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        return None
    if not decoded:
        return None

    decode_attempts: list[tuple[str, bool]] = [("utf-8", False)]
    if len(decoded) % 2 == 0 and b"\x00" in decoded:
        decode_attempts.extend((("utf-16le", True), ("utf-16be", True)))

    for codec, allow_nul in decode_attempts:
        if not allow_nul and b"\x00" in decoded:
            continue
        try:
            text = decoded.decode(codec)
        except UnicodeDecodeError:
            continue
        if not text or "\x00" in text:
            continue
        printable = sum(char.isprintable() or char.isspace() for char in text) / max(len(text), 1)
        if printable >= 0.9:
            return text
    return None


def decoded_surface_depth(surface: str, encoding: str) -> int:
    if surface == f"decoded-{encoding}":
        return 1
    match = re.fullmatch(rf"decoded-{re.escape(encoding)}:(\d+)", surface)
    return int(match.group(1)) if match else 0


def decoded_text_worth_scanning(text: str) -> bool:
    candidate = text.strip()
    if not candidate:
        return False
    lowered = candidate.lower()
    if has_sensitive_text_hint(lowered) or contains_any(lowered, PROVIDER_TOKEN_HINTS):
        return True
    if BASE64_BLOB_RE.search(candidate):
        return True

    token = normalize_candidate(candidate)
    if (
        len(token) < 20
        or len(token) > 512
        or any(char.isspace() for char in token)
        or is_placeholder(token)
        or is_uuid(token)
        or is_hex_digest(token)
        or is_sequential(token)
        or is_public_identifier(token)
        or is_lowercase_slug(token)
        or is_path_like_candidate(token)
    ):
        return False
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
        return False
    return shannon_entropy(token) >= 3.5 and character_classes(token) >= 2


def has_unicode_format_characters(text: str) -> bool:
    return not text.isascii() and any(unicodedata.category(char) == "Cf" for char in text)


def display_normalized_text(text: str) -> tuple[str, list[tuple[int, int]], bool]:
    normalized: list[str] = []
    spans: list[tuple[int, int]] = []
    changed = False
    position = 0
    while position < len(text):
        match = ANSI_ESCAPE_RE.match(text, position)
        if match:
            changed = True
            position = match.end()
            continue
        char = text[position]
        if unicodedata.category(char) == "Cf":
            changed = True
            position += 1
            continue
        normalized.append(char)
        spans.append((position, position + 1))
        position += 1
    return "".join(normalized), spans, changed


def add_display_normalized_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    depth = decoded_surface_depth(surface, "display")
    if surface.startswith("decoded-") and depth == 0:
        return
    if depth >= 1:
        return
    if "\x1b" not in text and "\x9b" not in text and not has_unicode_format_characters(text):
        return
    normalized, spans, changed = display_normalized_text(text)
    if not changed or not spans or normalized == text:
        return
    if not decoded_text_worth_scanning(normalized):
        lowered = normalized.lower()
        if not has_sensitive_text_hint(lowered) and not contains_any(lowered, PROVIDER_TOKEN_HINTS):
            return
    normalized_findings = scan_text(normalized, surface="decoded-display:1", threshold=0.8)
    for finding in normalized_findings:
        if finding.start < 0 or finding.start >= len(spans):
            continue
        end_index = min(max(finding.end, finding.start + 1), len(spans)) - 1
        start = spans[finding.start][0]
        end = spans[end_index][1]
        findings.append(Finding("DISPLAY_NORMALIZED_SECRET", start, end, 0.9, "display-normalized content contains a secret"))


def is_softwrap_token_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char in "_-.~+/=")


def softwrap_normalized_text(text: str) -> tuple[str, list[tuple[int, int]], bool]:
    normalized: list[str] = []
    spans: list[tuple[int, int]] = []
    changed = False
    position = 0
    while position < len(text):
        char = text[position]
        if char not in "\r\n":
            normalized.append(char)
            spans.append((position, position + 1))
            position += 1
            continue

        next_position = position + 1
        if char == "\r" and next_position < len(text) and text[next_position] == "\n":
            next_position += 1
        while next_position < len(text) and text[next_position] in " \t":
            next_position += 1

        previous_char = normalized[-1] if normalized else ""
        next_char = text[next_position] if next_position < len(text) else ""
        if is_softwrap_token_char(previous_char) and is_softwrap_token_char(next_char):
            changed = True
            position = next_position
            continue

        normalized.append(char)
        spans.append((position, position + 1))
        position += 1
    return "".join(normalized), spans, changed


def add_softwrap_findings(text: str, findings: list[Finding], *, surface: str, reconstruction_hint: bool) -> None:
    depth = decoded_surface_depth(surface, "softwrap")
    if surface.startswith("decoded-") and depth == 0:
        return
    if surface in {"bash-command", "vcs-diff"}:
        return
    if depth >= 1 or ("\n" not in text and "\r" not in text):
        return
    if HEREDOC_RE.search(text):
        return
    if not reconstruction_hint:
        return
    normalized, spans, changed = softwrap_normalized_text(text)
    if not changed or not spans or normalized == text:
        return
    normalized_findings = scan_text(normalized, surface="decoded-softwrap:1", threshold=0.8)
    for finding in normalized_findings:
        if finding.start < 0 or finding.start >= len(spans):
            continue
        end_index = min(max(finding.end, finding.start + 1), len(spans)) - 1
        start = spans[finding.start][0]
        end = spans[end_index][1]
        original_segment = text[start:end]
        if "\n" not in original_segment and "\r" not in original_segment:
            continue
        if finding.kind in {"SENSITIVE_ASSIGNMENT", "SENSITIVE_JSON_VALUE", "LEAKY_COMMAND", "SENSITIVE_FILE_PATH"}:
            continue
        findings.append(Finding("SOFT_WRAPPED_SECRET", start, end, 0.9, "soft-wrapped content contains a secret"))


def add_chunked_token_findings(text: str, findings: list[Finding], *, surface: str, reconstruction_hint: bool) -> None:
    depth = decoded_surface_depth(surface, "chunked")
    if surface.startswith("decoded-") and depth == 0:
        return
    if surface in {"bash-command", "vcs-diff"}:
        return
    if depth >= 1 or (" " not in text and "\t" not in text and ":" not in text):
        return
    if not reconstruction_hint:
        return
    for match in CHUNKED_TOKEN_RE.finditer(text):
        raw = match.group(1)
        raw_lower = raw.lower()
        if "infisical" in raw_lower and "--plain" in raw_lower:
            continue
        if raw.count(" ") + raw.count("\t") + raw.count(":") < 2:
            continue
        reconstructed = re.sub(r"[ \t:]+", "", raw)
        if reconstructed == raw or not decoded_text_worth_scanning(reconstructed):
            continue
        reconstructed_findings = scan_text(reconstructed, surface="decoded-chunked:1", threshold=0.8)
        if reconstructed_findings:
            findings.append(Finding("CHUNKED_SECRET_TOKEN", match.start(1), match.end(1), 0.9, "separator-chunked content contains a secret"))


def decode_escape_sequence_run(value: str) -> str | None:
    if len(value) < 32 or len(value) > 4096:
        return None
    pieces: list[str] = []
    position = 0
    while position < len(value):
        match = ESCAPE_SEQUENCE_RE.match(value, position)
        if not match:
            return None
        token = match.group(0)
        body = token.lstrip("\\")
        try:
            if body.startswith("x"):
                codepoint = int(body[1:], 16)
            elif body.startswith("u"):
                codepoint = int(body[1:], 16)
            elif body.startswith("U"):
                codepoint = int(body[1:], 16)
            else:
                codepoint = int(body, 8)
            pieces.append(chr(codepoint))
        except (ValueError, OverflowError):
            return None
        position = match.end()
    decoded = "".join(pieces)
    if not decoded_text_worth_scanning(decoded):
        return None
    return decoded


def add_escaped_sequence_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    depth = decoded_surface_depth(surface, "escape")
    if surface.startswith("decoded-") and depth == 0:
        return
    if depth >= MAX_DECODE_DEPTH:
        return
    if "\\" not in text:
        return
    for match in ESCAPED_SEQUENCE_RUN_RE.finditer(text):
        decoded = decode_escape_sequence_run(match.group(0))
        if not decoded:
            continue
        decoded_findings = scan_text(decoded, surface=f"decoded-escape:{depth + 1}", threshold=0.8)
        if decoded_findings:
            findings.append(Finding("ENCODED_SECRET_ESCAPE", match.start(), match.end(), 0.9, "escaped content contains a secret"))


def add_html_entity_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    depth = decoded_surface_depth(surface, "html-entity")
    if surface.startswith("decoded-") and depth == 0:
        return
    if depth >= MAX_DECODE_DEPTH or "&" not in text:
        return
    for match in HTML_ENTITY_CANDIDATE_RE.finditer(text):
        raw = match.group(0)
        if "&" not in raw or ";" not in raw:
            continue
        decoded = html.unescape(raw)
        if decoded == raw or not decoded_text_worth_scanning(decoded):
            continue
        decoded_findings = scan_text(decoded, surface=f"decoded-html-entity:{depth + 1}", threshold=0.8)
        if decoded_findings:
            findings.append(Finding("ENCODED_SECRET_HTML_ENTITY", match.start(), match.end(), 0.9, "HTML entity decoded content contains a secret"))


def add_percent_encoded_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    depth = decoded_surface_depth(surface, "percent")
    if surface.startswith("decoded-") and depth == 0:
        return
    if depth >= MAX_DECODE_DEPTH or "%" not in text:
        return
    for match in PERCENT_ENCODED_RUN_RE.finditer(text):
        raw = match.group(0)
        decoded = unquote(raw)
        if decoded == raw or not decoded_text_worth_scanning(decoded):
            continue
        decoded_findings = scan_text(decoded, surface=f"decoded-percent:{depth + 1}", threshold=0.8)
        if decoded_findings:
            findings.append(Finding("ENCODED_SECRET_PERCENT", match.start(), match.end(), 0.9, "percent-decoded content contains a secret"))


def add_hex_encoded_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    depth = decoded_surface_depth(surface, "hex")
    if surface.startswith("decoded-") and depth == 0:
        return
    if depth >= MAX_DECODE_DEPTH:
        return
    for match in HEX_ENCODED_RUN_RE.finditer(text):
        raw = match.group(0)
        if len(raw) > 4096:
            continue
        try:
            decoded_bytes = bytes.fromhex(raw)
        except ValueError:
            continue
        if not decoded_bytes or b"\x00" in decoded_bytes:
            continue
        try:
            decoded = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(char.isprintable() or char.isspace() for char in decoded) / max(len(decoded), 1)
        if printable < 0.9 or not decoded_text_worth_scanning(decoded):
            continue
        decoded_findings = scan_text(decoded, surface=f"decoded-hex:{depth + 1}", threshold=0.8)
        if decoded_findings:
            findings.append(Finding("ENCODED_SECRET_HEX", match.start(), match.end(), 0.9, "hex-decoded content contains a secret"))


def add_encoded_blob_findings(text: str, findings: list[Finding], *, surface: str) -> None:
    depth = decoded_surface_depth(surface, "base64")
    if surface.startswith("decoded-") and depth == 0:
        return
    if depth >= MAX_DECODE_DEPTH:
        return
    for match in BASE64_BLOB_RE.finditer(text):
        decoded = maybe_decode_base64(match.group(1))
        if not decoded:
            continue
        if not decoded_text_worth_scanning(decoded):
            continue
        decoded_findings = scan_text(decoded, surface=f"decoded-base64:{depth + 1}", threshold=0.8)
        if decoded_findings:
            findings.append(Finding("ENCODED_SECRET_BLOB", match.start(1), match.end(1), 0.9, "base64-decoded content contains a secret"))


def add_pii_findings(text: str, findings: list[Finding], *, include_pii: bool) -> None:
    if not include_pii:
        return
    for match in re.finditer(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text):
        candidate = match.group(0)
        normalized = re.sub(r"\D", "", candidate)
        if normalized in COMMON_EXAMPLE_TOKENS:
            continue
        if luhn_valid(candidate):
            findings.append(Finding("PAYMENT_CARD", match.start(), match.end(), 0.7, "Luhn-valid payment card number"))
    for match in re.finditer(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", text):
        context = text[max(0, match.start() - 24): match.end() + 24].lower()
        if "ssn" in context or "social security" in context:
            findings.append(Finding("SSN", match.start(), match.end(), 0.68, "SSN-shaped value in SSN context"))


def dedupe_findings(findings: Iterable[Finding], *, threshold: float) -> list[Finding]:
    candidates = [finding for finding in findings if finding.end > finding.start and finding.confidence >= threshold]
    candidates.sort(key=lambda item: (-item.confidence, -(item.end - item.start), item.start))
    selected: list[Finding] = []
    for finding in candidates:
        if any(not (finding.end <= kept.start or kept.end <= finding.start) for kept in selected):
            continue
        selected.append(finding)
    selected.sort(key=lambda item: item.start)
    return selected


def load_fingerprint_key(*, create: bool) -> bytes:
    env_key = os.environ.get("ASG_FINGERPRINT_KEY")
    if env_key:
        return env_key.encode("utf-8")

    path = DEFAULT_FINGERPRINT_KEY
    if path.exists():
        return path.read_bytes().strip()
    if not create:
        raise FileNotFoundError(str(path))

    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode("ascii")
    old_umask = os.umask(0o177)
    try:
        try:
            with path.open("xb") as handle:
                handle.write(key + b"\n")
        except FileExistsError:
            return path.read_bytes().strip()
    finally:
        os.umask(old_umask)
    path.chmod(0o600)
    return key


def read_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON") from exc


def corpus_case_requirements(case: dict[str, Any]) -> list[str]:
    raw = case.get("requirements", case.get("requirement"))
    values: list[str] = []
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list):
        values = [str(item) for item in raw if str(item).strip()]
    values = sorted({value.strip() for value in values if value.strip()})
    if values:
        return values

    expected_kinds = [str(kind) for kind in case.get("expected_kinds", []) if str(kind).strip()]
    if expected_kinds:
        return [f"kind:{kind}" for kind in sorted(set(expected_kinds))]

    surface = str(case.get("surface") or "text")
    return [f"surface:{surface}"]


def materialize_corpus_value(value: Any) -> Any:
    if isinstance(value, dict):
        parts = value.get("__asg_join__")
        if set(value) == {"__asg_join__"} and isinstance(parts, list):
            return "".join(str(materialize_corpus_value(part)) for part in parts)
        entries = value.get("__asg_object__")
        if set(value) == {"__asg_object__"} and isinstance(entries, list):
            output = {}
            for entry in entries:
                if isinstance(entry, list) and len(entry) == 2:
                    output[str(materialize_corpus_value(entry[0]))] = materialize_corpus_value(entry[1])
            return materialize_corpus_value(output)
        return {key: materialize_corpus_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [materialize_corpus_value(item) for item in value]
    return value


def corpus_case_input(case: dict[str, Any]) -> str:
    if "input_parts" in case:
        parts = case.get("input_parts")
        if isinstance(parts, list):
            return "".join(str(materialize_corpus_value(part)) for part in parts)
    return str(case.get("input") or "")


def corpus_case_json(case: dict[str, Any]) -> Any:
    return materialize_corpus_value(case.get("json"))


def requirement_description(catalog: Any, requirement: str) -> str:
    if isinstance(catalog, dict):
        entry = catalog.get(requirement)
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            return str(entry.get("description") or "")
    return ""


def evaluate_corpus_quality(
    requirement_catalog: Any,
    coverage: dict[str, dict[str, Any]],
    *,
    min_cases_per_requirement: int = 2,
    positive_kinds: set[str] | None = None,
    required_positive_kinds: set[str] | None = None,
    detector_hints: dict[str, tuple[str, ...]] | None = None,
    detector_hint_patterns: dict[str, re.Pattern[str]] | None = None,
    positive_kind_inputs: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    catalog_keys: set[str] = set()
    blank_descriptions: list[str] = []
    if isinstance(requirement_catalog, dict):
        for key, entry in requirement_catalog.items():
            requirement = str(key).strip()
            if not requirement:
                continue
            catalog_keys.add(requirement)
            description = entry if isinstance(entry, str) else entry.get("description", "") if isinstance(entry, dict) else ""
            if not str(description).strip():
                blank_descriptions.append(requirement)

    covered_keys = set(coverage)
    thin_requirements = {
        requirement: int(bucket.get("cases", 0))
        for requirement, bucket in sorted(coverage.items())
        if int(bucket.get("cases", 0)) < min_cases_per_requirement
    }
    positive_without_negative = {
        requirement: {
            "positive": int(bucket.get("positive", 0)),
            "negative": int(bucket.get("negative", 0)),
        }
        for requirement, bucket in sorted(coverage.items())
        if int(bucket.get("positive", 0)) > 0 and int(bucket.get("negative", 0)) == 0
    }
    missing_catalog_entries = sorted(covered_keys - catalog_keys)
    unused_catalog_entries = sorted(catalog_keys - covered_keys)
    required_kinds = required_positive_kinds or set()
    known_positive_kinds = positive_kinds or set()
    hints_by_kind = detector_hints or {}
    pattern_by_kind = detector_hint_patterns or {}
    inputs_by_kind = positive_kind_inputs or {}
    missing_positive_kinds = sorted(required_kinds - known_positive_kinds)
    missing_detector_hints = sorted(kind for kind in required_kinds if not hints_by_kind.get(kind) and kind not in pattern_by_kind)
    short_detector_hints = {
        kind: [hint for hint in hints_by_kind.get(kind, ()) if len(hint) < 3]
        for kind in sorted(required_kinds)
        if any(len(hint) < 3 for hint in hints_by_kind.get(kind, ()))
    }

    def sample_matches_detector_hint(kind: str, sample: str) -> bool:
        if any(hint.lower() in sample.lower() for hint in hints_by_kind.get(kind, ())):
            return True
        hint_pattern = pattern_by_kind.get(kind)
        return bool(hint_pattern and hint_pattern.search(sample))

    positive_without_detector_hint = sorted(
        kind
        for kind in required_kinds & known_positive_kinds
        if not any(sample_matches_detector_hint(kind, sample) for sample in inputs_by_kind.get(kind, []))
    )
    status = "pass"
    if (
        missing_catalog_entries
        or unused_catalog_entries
        or blank_descriptions
        or thin_requirements
        or positive_without_negative
        or missing_positive_kinds
        or missing_detector_hints
        or short_detector_hints
        or positive_without_detector_hint
    ):
        status = "fail"
    return {
        "status": status,
        "catalog_requirements": len(catalog_keys),
        "covered_requirements": len(covered_keys),
        "min_cases_per_requirement": min_cases_per_requirement,
        "missing_catalog_entries": missing_catalog_entries,
        "unused_catalog_entries": unused_catalog_entries,
        "blank_descriptions": sorted(blank_descriptions),
        "thin_requirements": thin_requirements,
        "positive_without_negative": positive_without_negative,
        "missing_positive_kinds": missing_positive_kinds,
        "missing_detector_hints": missing_detector_hints,
        "short_detector_hints": short_detector_hints,
        "positive_without_detector_hint": positive_without_detector_hint,
    }


def finding_fingerprint(text: str, finding: Finding, *, path: str, surface: str, key: bytes) -> str:
    value = text[finding.start:finding.end]
    payload = json.dumps(
        {
            "kind": finding.kind,
            "path": path,
            "surface": surface,
            "value": value,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return f"asg1:{digest}"


def load_baseline(path: str) -> set[str]:
    payload = read_json_file(Path(path).expanduser())
    fingerprints: set[str] = set()
    if isinstance(payload, dict):
        for item in payload.get("fingerprints", []):
            if isinstance(item, str):
                fingerprints.add(item)
        for item in payload.get("findings", []):
            if isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
                fingerprints.add(item["fingerprint"])
    return fingerprints


def filter_baselined_findings(
    text: str,
    findings: list[Finding],
    *,
    path: str,
    surface: str,
    baseline: set[str],
    key: bytes,
) -> list[Finding]:
    return [
        finding
        for finding in findings
        if finding_fingerprint(text, finding, path=path, surface=surface, key=key) not in baseline
    ]


def scan_text(
    text: str,
    *,
    surface: str = "text",
    path: str = "",
    include_pii: bool = False,
    threshold: float = DEFAULT_REDACT_THRESHOLD,
) -> list[Finding]:
    findings: list[Finding] = []
    add_command_policy_findings(text, findings, surface=surface)
    add_file_path_findings(text, findings, surface=surface, path=path)
    if not text or len(text) < 4:
        return dedupe_findings(findings, threshold=threshold)
    add_structural_findings(text, findings)
    add_regex_findings(text, findings)
    add_composite_findings(text, findings)
    add_auth_and_url_findings(text, findings)
    add_assignment_findings(text, findings, path=path, surface=surface)
    add_joined_literal_findings(text, findings, surface=surface)
    add_display_normalized_findings(text, findings, surface=surface)
    reconstruction_hint = RECONSTRUCTION_HINT_RE.search(text) is not None
    add_softwrap_findings(text, findings, surface=surface, reconstruction_hint=reconstruction_hint)
    add_chunked_token_findings(text, findings, surface=surface, reconstruction_hint=reconstruction_hint)
    add_high_entropy_findings(text, findings)
    add_pii_findings(text, findings, include_pii=include_pii)
    add_escaped_sequence_findings(text, findings, surface=surface)
    add_html_entity_findings(text, findings, surface=surface)
    add_percent_encoded_findings(text, findings, surface=surface)
    add_hex_encoded_findings(text, findings, surface=surface)
    add_encoded_blob_findings(text, findings, surface=surface)
    env_template_spans = env_template_source_listing_spans(text)
    if env_template_spans:
        findings = [finding for finding in findings if not finding_in_span(finding, env_template_spans)]
    return dedupe_findings(findings, threshold=threshold)


def scan_json_value(text: str, *, surface: str, path: str, threshold: float) -> list[Finding]:
    findings = scan_text(text, surface=surface, path=path, threshold=threshold)
    add_json_context_findings(text, findings, path=path, surface=surface)
    return dedupe_findings(findings, threshold=threshold)


def apply_redactions(text: str, findings: list[Finding]) -> str:
    if not findings:
        return text
    chunks: list[str] = []
    cursor = 0
    for finding in findings:
        chunks.append(text[cursor:finding.start])
        chunks.append(f"[REDACTED:{finding.kind}]")
        cursor = finding.end
    chunks.append(text[cursor:])
    return "".join(chunks)


def redact_text(
    text: str,
    *,
    surface: str = "text",
    path: str = "",
    include_pii: bool = False,
    threshold: float = DEFAULT_REDACT_THRESHOLD,
) -> tuple[str, list[Finding]]:
    findings = scan_text(text, surface=surface, path=path, include_pii=include_pii, threshold=threshold)
    if not findings:
        return text, []
    return apply_redactions(text, findings), findings


def read_stdin() -> str:
    daemon_stdin = getattr(DAEMON_STATE, "stdin", None)
    if daemon_stdin is not None:
        return daemon_stdin
    return sys.stdin.read()


def public_summary(
    findings: list[Finding],
    *,
    text: str = "",
    path: str = "",
    surface: str = "",
    include_fingerprints: bool = False,
    fingerprint_key: bytes | None = None,
) -> dict[str, Any]:
    kinds = sorted({finding.kind for finding in findings})
    public_findings = []
    for finding in findings:
        item = finding.public()
        if include_fingerprints and fingerprint_key is not None:
            item["fingerprint"] = finding_fingerprint(text, finding, path=path, surface=surface, key=fingerprint_key)
        public_findings.append(item)
    return {"count": len(findings), "kinds": kinds, "findings": public_findings}


def reason_for(findings: list[Finding], *, prefix: str = "Potential secret material detected") -> str:
    kinds = ", ".join(sorted({finding.kind for finding in findings}))
    remediation = remediation_for_findings(findings)
    return f"{prefix} ({kinds}). Content omitted to avoid logging secrets. {remediation}"


def remediation_for_findings(findings: list[Finding]) -> str:
    reasons = " ".join(finding.reason.lower() for finding in findings)
    hints: list[str] = []
    if "process listing" in reasons or "argv" in reasons or "procfs" in reasons:
        hints.append(
            "For process status, avoid full argument columns; use `pgrep -x NAME`, "
            "`pgrep -l NAME`, or `ps -ax -o pid=,stat=,etime=,comm= | rg PATTERN`. "
            "If full arguments are required, pipe the process listing directly to ASG "
            "redaction as the only pipe stage before inspecting output."
        )
    if "environment dump" in reasons or "printenv" in reasons or "shell variables" in reasons or "variable values" in reasons:
        hints.append(
            "For runtime variable checks, emit names only with a key projection such as "
            "`cut -d= -f1`, `sed 's/=.*//'`, or `awk -F= '{print $1}'`; do not print values."
        )
    if "secret-bearing files" in reasons or "known secret-bearing files" in reasons or "sourcing known" in reasons:
        hints.append(
            "For secret files, read checked-in example/template files or metadata only; "
            "use operator-managed secret injection for real values."
        )
    if "token" in reasons or "credentials" in reasons or "secret values" in reasons or "secret payload" in reasons:
        hints.append(
            "For cloud and secret-manager workflows, prefer list/show-metadata commands "
            "or runtime injection; do not print bearer tokens, decrypted values, passwords, "
            "or generated credentials."
        )
    if "curl" in reasons or "wget" in reasons or "password arguments" in reasons:
        hints.append(
            "For HTTP calls, remove verbose/trace modes and keep credentials in referenced "
            "variables or stdin-specific safe flags rather than literal argv values."
        )
    if not hints:
        hints.append(
            "Retry with metadata-only output, key-only projections, operator-managed "
            "secret injection, or ASG-redacted output where supported."
        )
    return " ".join(dict.fromkeys(hints))


def insert_json_item(target: dict[Any, Any], key: Any, value: Any) -> None:
    if key not in target:
        target[key] = value
        return
    suffix = 2
    while True:
        candidate = f"{key}#{suffix}"
        if candidate not in target:
            target[candidate] = value
            return
        suffix += 1


def redact_json_strings(obj: Any, *, surface: str, path: str, threshold: float) -> tuple[Any, list[Finding]]:
    all_findings: list[Finding] = []
    if isinstance(obj, str):
        findings = scan_json_value(obj, surface=surface, path=path, threshold=threshold)
        return apply_redactions(obj, findings), findings
    if isinstance(obj, list):
        new_items = []
        for index, item in enumerate(obj):
            redacted, findings = redact_json_strings(item, surface=surface, path=json_list_path(path, index), threshold=threshold)
            new_items.append(redacted)
            all_findings.extend(findings)
        return new_items, all_findings
    if isinstance(obj, dict):
        new_obj = {}
        for key, value in obj.items():
            output_key = key
            value_path_key = str(key)
            if isinstance(key, str):
                key_path = json_path_join(path, "$key")
                key_findings = scan_json_value(key, surface=surface, path=key_path, threshold=threshold)
                if key_findings:
                    output_key = apply_redactions(key, key_findings)
                    value_path_key = output_key
                    all_findings.extend(key_findings)
            redacted, value_findings = redact_json_strings(value, surface=surface, path=json_path_join(path, value_path_key), threshold=threshold)
            insert_json_item(new_obj, output_key, redacted)
            all_findings.extend(value_findings)
        return new_obj, all_findings
    return obj, []


def scan_json_strings(obj: Any, *, surface: str, path: str, threshold: float) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(obj, str):
        return scan_json_value(obj, surface=surface, path=path, threshold=threshold)
    if isinstance(obj, list):
        for index, item in enumerate(obj):
            findings.extend(scan_json_strings(item, surface=surface, path=json_list_path(path, index), threshold=threshold))
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                findings.extend(scan_json_value(key, surface=surface, path=json_path_join(path, "$key"), threshold=threshold))
            findings.extend(scan_json_strings(value, surface=surface, path=json_path_join(path, str(key)), threshold=threshold))
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    text = read_stdin()
    path = args.path or ""
    threshold = args.threshold
    if threshold is None:
        threshold = DEFAULT_BLOCK_THRESHOLD if args.fail_on_detect else DEFAULT_REDACT_THRESHOLD
    findings = scan_text(text, surface=args.surface, path=path, include_pii=args.include_pii, threshold=threshold)
    fingerprint_key = None
    if args.baseline:
        try:
            fingerprint_key = load_fingerprint_key(create=False)
            findings = filter_baselined_findings(
                text,
                findings,
                path=path,
                surface=args.surface,
                baseline=load_baseline(args.baseline),
                key=fingerprint_key,
            )
        except Exception as exc:
            emit(json.dumps({"ok": False, "error": f"baseline unavailable: {exc.__class__.__name__}"}, sort_keys=True))
            return 1
    if args.fingerprints:
        try:
            fingerprint_key = fingerprint_key or load_fingerprint_key(create=True)
        except Exception as exc:
            emit(json.dumps({"ok": False, "error": f"fingerprint unavailable: {exc.__class__.__name__}"}, sort_keys=True))
            return 1
    if not args.quiet:
        emit(
            json.dumps(
                {
                    "ok": not findings,
                    **public_summary(
                        findings,
                        text=text,
                        path=path,
                        surface=args.surface,
                        include_fingerprints=args.fingerprints,
                        fingerprint_key=fingerprint_key,
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
    if args.fail_on_detect and findings:
        return 2
    return 0


def cmd_redact(args: argparse.Namespace) -> int:
    text = read_stdin()
    redacted, findings = redact_text(text, surface=args.surface, path=args.path or "", include_pii=args.include_pii, threshold=args.threshold)
    if args.json:
        emit(json.dumps({"redacted": redacted, **public_summary(findings)}, indent=2, sort_keys=True))
    else:
        sys.stdout.write(redacted)
    return 0


def load_json_stdin() -> dict[str, Any]:
    try:
        value = json.loads(read_stdin())
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def load_any_json_stdin() -> Any:
    try:
        return json.loads(read_stdin())
    except Exception:
        return None


def cmd_json_block(args: argparse.Namespace) -> int:
    payload = load_any_json_stdin()
    if payload is None:
        if not args.quiet:
            emit(json.dumps({"ok": True, "count": 0, "kinds": [], "findings": []}, sort_keys=True))
        return 0

    findings = scan_json_strings(payload, surface=args.surface, path=args.path or "", threshold=args.threshold)
    if findings:
        if not args.quiet:
            emit(json.dumps({"ok": False, **public_summary(findings)}, sort_keys=True))
        return 2

    if not args.quiet:
        emit(json.dumps({"ok": True, "count": 0, "kinds": [], "findings": []}, sort_keys=True))
    return 0


def cmd_json_redact(args: argparse.Namespace) -> int:
    payload = load_any_json_stdin()
    if payload is None:
        emit(json.dumps({"ok": True, "count": 0, "kinds": [], "findings": [], "redacted": None}, sort_keys=True))
        return 0

    redacted, findings = redact_json_strings(payload, surface=args.surface, path=args.path or "", threshold=args.threshold)
    emit(json.dumps({"ok": not findings, "redacted": redacted, **public_summary(findings)}, sort_keys=True))
    return 0


def cmd_baseline_create(args: argparse.Namespace) -> int:
    text = read_stdin()
    path = args.path or ""
    findings = scan_text(text, surface=args.surface, path=path, include_pii=args.include_pii, threshold=args.threshold)
    try:
        key = load_fingerprint_key(create=True)
    except Exception as exc:
        emit(json.dumps({"ok": False, "error": f"fingerprint unavailable: {exc.__class__.__name__}"}, sort_keys=True))
        return 1

    entries = []
    fingerprints = []
    for finding in findings:
        fingerprint = finding_fingerprint(text, finding, path=path, surface=args.surface, key=key)
        fingerprints.append(fingerprint)
        entries.append(
            {
                "fingerprint": fingerprint,
                "kind": finding.kind,
                "confidence": round(finding.confidence, 3),
                "reason": finding.reason,
                "surface": args.surface,
                "path": path,
            }
        )
    emit(
        json.dumps(
            {
                "version": 1,
                "kind": "agent-secret-guard-baseline",
                "count": len(entries),
                "fingerprints": fingerprints,
                "findings": entries,
                "review_required": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def evaluate_corpus(path: Path, *, threshold: float) -> dict[str, Any]:
    corpus = read_json_file(path)
    cases = corpus.get("cases", []) if isinstance(corpus, dict) else []
    requirement_catalog = corpus.get("requirements", {}) if isinstance(corpus, dict) else {}
    results: list[dict[str, Any]] = []
    coverage: dict[str, dict[str, Any]] = {}
    positive_kinds: set[str] = set()
    positive_kind_inputs: dict[str, list[str]] = {}
    tp = fp = fn = tn = wrong_kind = 0

    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("id") or f"case-{len(results) + 1}")
        label = str(case.get("label") or "").lower()
        positive = label in {"positive", "true_positive", "secret"}
        surface = str(case.get("surface") or "text")
        case_path = str(case.get("path") or "")
        expected_kinds = sorted(str(kind) for kind in case.get("expected_kinds", []))
        requirements = corpus_case_requirements(case)
        if positive:
            positive_kinds.update(expected_kinds)
            sample_text = (
                json.dumps(corpus_case_json(case), ensure_ascii=False, sort_keys=True)
                if "json" in case
                else corpus_case_input(case)
            )
            for kind in expected_kinds:
                positive_kind_inputs.setdefault(kind, []).append(sample_text)

        if "json" in case:
            findings = scan_json_strings(corpus_case_json(case), surface=surface, path=case_path, threshold=threshold)
        else:
            findings = scan_text(corpus_case_input(case), surface=surface, path=case_path, threshold=threshold)

        kinds = sorted({finding.kind for finding in findings})
        detected = bool(findings)
        expected_kind_ok = not expected_kinds or set(expected_kinds).issubset(kinds)
        ok = (detected and expected_kind_ok) if positive else not detected

        if positive and detected:
            tp += 1
            if not expected_kind_ok:
                wrong_kind += 1
        elif positive:
            fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1

        for requirement in requirements:
            bucket = coverage.setdefault(
                requirement,
                {
                    "description": requirement_description(requirement_catalog, requirement),
                    "cases": 0,
                    "positive": 0,
                    "negative": 0,
                    "passed": 0,
                    "failed": 0,
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "tn": 0,
                    "wrong_kind": 0,
                },
            )
            bucket["cases"] += 1
            bucket["positive" if positive else "negative"] += 1
            bucket["passed" if ok else "failed"] += 1
            if positive and detected:
                bucket["tp"] += 1
                if not expected_kind_ok:
                    bucket["wrong_kind"] += 1
            elif positive:
                bucket["fn"] += 1
            elif detected:
                bucket["fp"] += 1
            else:
                bucket["tn"] += 1

        results.append(
            {
                "id": case_id,
                "label": "positive" if positive else "negative",
                "requirements": requirements,
                "detected": detected,
                "ok": ok,
                "kinds": kinds,
                "expected_kinds": expected_kinds,
                "count": len(findings),
            }
        )

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    ok = all(item["ok"] for item in results)
    for bucket in coverage.values():
        bucket_tp = int(bucket["tp"])
        bucket_fp = int(bucket["fp"])
        bucket_fn = int(bucket["fn"])
        bucket_tn = int(bucket["tn"])
        bucket["precision"] = round(bucket_tp / (bucket_tp + bucket_fp), 6) if bucket_tp + bucket_fp else 1.0
        bucket["recall"] = round(bucket_tp / (bucket_tp + bucket_fn), 6) if bucket_tp + bucket_fn else 1.0
        bucket["fpr"] = round(bucket_fp / (bucket_fp + bucket_tn), 6) if bucket_fp + bucket_tn else 0.0
        bucket["status"] = "pass" if bucket["failed"] == 0 else "fail"

    coverage_summary = {
        "requirements": len(coverage),
        "cases": sum(int(bucket["cases"]) for bucket in coverage.values()),
        "passed": sum(int(bucket["passed"]) for bucket in coverage.values()),
        "failed": sum(int(bucket["failed"]) for bucket in coverage.values()),
    }
    coverage_quality = evaluate_corpus_quality(
        requirement_catalog,
        coverage,
        positive_kinds=positive_kinds,
        required_positive_kinds={detector.kind for detector in TOKEN_DETECTORS},
        detector_hints=TOKEN_DETECTOR_HINTS,
        detector_hint_patterns=TOKEN_DETECTOR_HINT_PATTERNS,
        positive_kind_inputs=positive_kind_inputs,
    )
    ok = ok and coverage_quality["status"] == "pass"
    return {
        "ok": ok,
        "corpus": str(path),
        "version": corpus.get("version") if isinstance(corpus, dict) else None,
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "wrong_kind": wrong_kind,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "fpr": round(fpr, 6),
        },
        "coverage": {
            "summary": coverage_summary,
            "quality": coverage_quality,
            "requirements": dict(sorted(coverage.items())),
        },
        "cases": results,
    }


def cmd_eval(args: argparse.Namespace) -> int:
    path = Path(args.corpus).expanduser()
    try:
        result = evaluate_corpus(path, threshold=args.threshold)
    except Exception as exc:
        emit(json.dumps({"ok": False, "error": f"eval failed: {exc.__class__.__name__}"}, sort_keys=True))
        return 1
    if not args.quiet:
        emit(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def first_nested_value(obj: Any, keys: set[str]) -> Any:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).lower() in keys:
                return value
            found = first_nested_value(value, keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = first_nested_value(item, keys)
            if found is not None:
                return found
    return None


def external_finding(scanner: str, *, kind: str, file: Any = None, line: Any = None, verified: Any = None, fingerprint: Any = None) -> dict[str, Any]:
    item: dict[str, Any] = {"scanner": scanner, "kind": str(kind or "unknown")}
    if file:
        item["file"] = str(file)
    parsed_line = safe_int(line)
    if parsed_line is not None:
        item["line"] = parsed_line
    if verified is not None:
        item["verified"] = bool(verified)
    if fingerprint:
        item["fingerprint"] = str(fingerprint)
    return item


def normalize_external_file_ref(value: str) -> Path:
    if value.startswith("file://"):
        value = value[7:]
    return Path(value)


def normalize_external_locations(findings: list[dict[str, Any]], *, root: Path) -> list[dict[str, Any]]:
    normalized = []
    for finding in findings:
        item = dict(finding)
        file_value = item.get("file")
        if isinstance(file_value, str):
            try:
                item["file"] = str(normalize_external_file_ref(file_value).resolve().relative_to(root.resolve()))
            except Exception:
                item["file"] = normalize_external_file_ref(file_value).name
        fingerprint = item.get("fingerprint")
        if isinstance(fingerprint, str):
            item["fingerprint"] = fingerprint.replace(str(root), "<scan-root>")
        normalized.append(item)
    return normalized


def parse_gitleaks_report(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text or "[]")
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [
        external_finding(
            "gitleaks",
            kind=item.get("RuleID") or item.get("Description"),
            file=item.get("File"),
            line=item.get("StartLine"),
            fingerprint=item.get("Fingerprint"),
        )
        for item in payload
        if isinstance(item, dict)
    ]


def parse_trufflehog_report(text: str) -> list[dict[str, Any]]:
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            item = None
        if not isinstance(item, dict):
            continue
        metadata = item.get("SourceMetadata") or item.get("source_metadata") or {}
        findings.append(
            external_finding(
                "trufflehog",
                kind=item.get("DetectorName") or item.get("DetectorType") or item.get("detector_name"),
                file=first_nested_value(metadata, {"file", "path"}),
                line=first_nested_value(metadata, {"line", "line_number"}),
                verified=item.get("Verified") if "Verified" in item else item.get("verified"),
                fingerprint=item.get("Fingerprint") or item.get("fingerprint") or first_nested_value(item.get("ExtraData") or {}, {"fingerprint"}),
            )
        )
    return findings


def parse_detect_secrets_report(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text or "{}")
    except Exception:
        return []
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, dict):
        return []
    findings = []
    for file, entries in results.items():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict):
                continue
            findings.append(
                external_finding(
                    "detect-secrets",
                    kind=item.get("type"),
                    file=file,
                    line=item.get("line_number"),
                    verified=item.get("is_verified"),
                    fingerprint=item.get("hashed_secret"),
                )
            )
    return findings


def run_external_scanners_on_path(root: Path, *, scanners: list[str], timeout: int) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    errors: list[dict[str, Any]] = []
    invocations: dict[str, int] = {scanner: 0 for scanner in scanners}

    if "gitleaks" in scanners:
        exe = shutil.which("gitleaks")
        if not exe:
            skipped.append({"scanner": "gitleaks", "reason": "not-installed"})
        else:
            invocations["gitleaks"] += 1
            with tempfile.TemporaryDirectory(prefix="asg-gitleaks-report-") as report_dir:
                report = Path(report_dir) / "gitleaks.json"
                proc = subprocess.run(  # nosec B603 - executable path comes from shutil.which; shell is never used.
                    [exe, "dir", str(root), "--no-banner", "--no-color", "--report-format", "json", "--report-path", str(report), "--exit-code", "0", "--redact"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                if report.exists():
                    results.extend(normalize_external_locations(parse_gitleaks_report(report.read_text()), root=root))
                elif proc.returncode != 0:
                    errors.append({"scanner": "gitleaks", "exit_code": proc.returncode})

    if "trufflehog" in scanners:
        exe = shutil.which("trufflehog")
        if not exe:
            skipped.append({"scanner": "trufflehog", "reason": "not-installed"})
        else:
            invocations["trufflehog"] += 1
            proc = subprocess.run(  # nosec B603 - executable path comes from shutil.which; shell is never used.
                [exe, "filesystem", "--json", "--no-update", "--no-verification", str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode in (0, 183):
                results.extend(normalize_external_locations(parse_trufflehog_report(proc.stdout), root=root))
            else:
                errors.append({"scanner": "trufflehog", "exit_code": proc.returncode})

    if "detect-secrets" in scanners:
        exe = shutil.which("detect-secrets")
        if not exe:
            skipped.append({"scanner": "detect-secrets", "reason": "not-installed"})
        else:
            invocations["detect-secrets"] += 1
            proc = subprocess.run(  # nosec B603 - executable path comes from shutil.which; shell is never used.
                [exe, "scan", "--all-files", str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.stdout:
                results.extend(normalize_external_locations(parse_detect_secrets_report(proc.stdout), root=root))
            elif proc.returncode != 0:
                errors.append({"scanner": "detect-secrets", "exit_code": proc.returncode})

    return {"findings": results, "skipped": skipped, "errors": errors, "invocations": invocations}


def run_external_scanners(text: str, *, scanners: list[str], timeout: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="asg-scan-") as temp_dir:
        root = Path(temp_dir)
        sample = root / "input.txt"
        sample.write_text(text)
        sample.chmod(0o600)
        return run_external_scanners_on_path(root, scanners=scanners, timeout=timeout)



def cmd_external_scan(args: argparse.Namespace) -> int:
    scanner_names = scanner_names_from_args(args.scanner)
    try:
        result = run_external_scanners(read_stdin(), scanners=scanner_names, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        emit(json.dumps({"ok": False, "error": "external scanner timed out"}, sort_keys=True))
        return 1
    findings = result["findings"]
    emit(
        json.dumps(
            {
                "ok": not findings,
                "count": len(findings),
                "findings": findings,
                "skipped": result["skipped"],
                "errors": result["errors"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 2 if args.fail_on_detect and findings else 0


def scanner_names_from_args(values: list[str]) -> list[str]:
    return ["gitleaks", "trufflehog", "detect-secrets"] if "all" in values else values


def corpus_case_material(case: dict[str, Any]) -> tuple[str, str]:
    if "json" in case:
        return json.dumps(corpus_case_json(case), sort_keys=True, separators=(",", ":")), "json"
    return corpus_case_input(case), "text"


def external_eval_case_filename(index: int, case_id: str, material_type: str) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", case_id).strip(".-") or "case"
    extension = "json" if material_type == "json" else "txt"
    return f"{index:04d}-{safe_id[:80]}.{extension}"


def external_case_id_for_finding(finding: dict[str, Any], file_to_case: dict[str, str]) -> str | None:
    file_value = finding.get("file")
    if not isinstance(file_value, str) or not file_value:
        return None
    normalized = file_value.replace("\\", "/").lstrip("./")
    if normalized in file_to_case:
        return file_to_case[normalized]

    basename = Path(normalized).name
    matches = {case_id for path, case_id in file_to_case.items() if Path(path).name == basename}
    if len(matches) == 1:
        return next(iter(matches))

    suffix_matches = {case_id for path, case_id in file_to_case.items() if path.endswith(normalized)}
    if len(suffix_matches) == 1:
        return next(iter(suffix_matches))
    return None


def evaluate_external_corpus(path: Path, *, scanners: list[str], timeout: int, threshold: float) -> dict[str, Any]:
    corpus = read_json_file(path)
    cases = corpus.get("cases", []) if isinstance(corpus, dict) else []
    rows: list[dict[str, Any]] = []
    rows_by_id: dict[str, dict[str, Any]] = {}
    case_meta: dict[str, dict[str, Any]] = {}
    scanner_stats: dict[str, dict[str, int]] = {
        name: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "skipped": 0}
        for name in scanners
    }
    requirement_stats: dict[str, dict[str, dict[str, int]]] = {name: {} for name in scanners}
    errors: list[dict[str, Any]] = []
    external_invocations: dict[str, int] = {scanner: 0 for scanner in scanners}

    def mark_skipped(scanner: str, requirements: list[str]) -> None:
        scanner_stats[scanner]["skipped"] += 1
        for requirement in requirements:
            bucket = requirement_stats[scanner].setdefault(
                requirement,
                {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "skipped": 0},
            )
            bucket["skipped"] += 1

    def mark_verdict(scanner: str, requirements: list[str], verdict: str) -> None:
        scanner_stats[scanner][verdict] += 1
        for requirement in requirements:
            bucket = requirement_stats[scanner].setdefault(
                requirement,
                {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "skipped": 0},
            )
            bucket[verdict] += 1

    for case in cases:
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("id") or f"case-{len(rows) + 1}")
        surface = str(case.get("surface") or "text")
        positive = str(case.get("label") or "").lower() in {"positive", "true_positive", "secret"}
        requirements = corpus_case_requirements(case)
        material, material_type = corpus_case_material(case)
        if "json" in case:
            internal_findings = scan_json_strings(corpus_case_json(case), surface=surface, path=str(case.get("path") or ""), threshold=threshold)
        else:
            internal_findings = scan_text(material, surface=surface, path=str(case.get("path") or ""), threshold=threshold)

        row: dict[str, Any] = {
            "id": case_id,
            "label": "positive" if positive else "negative",
            "requirements": requirements,
            "surface": surface,
            "material_type": material_type,
            "asg_detected": bool(internal_findings),
            "asg_kinds": sorted({finding.kind for finding in internal_findings}),
            "external_applicable": surface != "bash-command",
            "external_detected_by": [],
            "external_kinds": {},
        }
        rows_by_id[case_id] = row

        if surface == "bash-command":
            for scanner in scanners:
                mark_skipped(scanner, requirements)
            row["skip_reason"] = "external file scanners do not model shell-command intent"
            rows.append(row)
            continue
        case_meta[case_id] = {
            "positive": positive,
            "requirements": requirements,
            "material": material,
            "material_type": material_type,
        }
        rows.append(row)

    scanner_case_kinds: dict[str, dict[str, list[str]]] = {scanner: {} for scanner in scanners}
    skipped_scanners: set[str] = set()
    if case_meta:
        with tempfile.TemporaryDirectory(prefix="asg-corpus-external-") as temp_dir:
            root = Path(temp_dir)
            file_to_case: dict[str, str] = {}
            for index, (case_id, meta) in enumerate(case_meta.items(), start=1):
                filename = external_eval_case_filename(index, case_id, str(meta["material_type"]))
                case_path = root / filename
                case_path.write_text(str(meta["material"]))
                case_path.chmod(0o600)
                file_to_case[str(case_path.relative_to(root))] = case_id

            external = run_external_scanners_on_path(root, scanners=scanners, timeout=timeout)
            errors.extend(external["errors"])
            external_invocations.update({scanner: int(count) for scanner, count in external.get("invocations", {}).items()})
            skipped_scanners = {str(item["scanner"]) for item in external["skipped"]}

            for finding in external["findings"]:
                scanner = str(finding.get("scanner") or "unknown")
                if scanner not in scanner_case_kinds:
                    continue
                case_id = external_case_id_for_finding(finding, file_to_case)
                if not case_id:
                    errors.append({"scanner": scanner, "reason": "unmapped-finding"})
                    continue
                kind = str(finding.get("kind") or "unknown")
                scanner_case_kinds[scanner].setdefault(case_id, [])
                if kind not in scanner_case_kinds[scanner][case_id]:
                    scanner_case_kinds[scanner][case_id].append(kind)

    for case_id, meta in case_meta.items():
        row = rows_by_id[case_id]
        positive = bool(meta["positive"])
        requirements = list(meta["requirements"])
        for scanner in scanners:
            if scanner in skipped_scanners:
                mark_skipped(scanner, requirements)
                continue
            kinds = sorted(scanner_case_kinds.get(scanner, {}).get(case_id, []))
            detected = bool(kinds)
            if detected:
                row["external_kinds"][scanner] = kinds
            if positive and detected:
                verdict = "tp"
            elif positive:
                verdict = "fn"
            elif detected:
                verdict = "fp"
            else:
                verdict = "tn"
            mark_verdict(scanner, requirements, verdict)

        row["external_detected_by"] = sorted(row["external_kinds"])
        row["external_kinds"] = dict(sorted(row["external_kinds"].items()))
        row["disagreement"] = bool(row["asg_detected"]) != bool(row["external_detected_by"])

    for stats in scanner_stats.values():
        tp = stats["tp"]
        fp = stats["fp"]
        fn = stats["fn"]
        tn = stats["tn"]
        stats["precision_ppm"] = round((tp / (tp + fp)) * 1_000_000) if tp + fp else 1_000_000
        stats["recall_ppm"] = round((tp / (tp + fn)) * 1_000_000) if tp + fn else 1_000_000
        stats["fpr_ppm"] = round((fp / (fp + tn)) * 1_000_000) if fp + tn else 0

    for scanner, scanner_requirements in requirement_stats.items():
        for requirement, stats in scanner_requirements.items():
            tp = stats["tp"]
            fp = stats["fp"]
            fn = stats["fn"]
            tn = stats["tn"]
            stats["precision_ppm"] = round((tp / (tp + fp)) * 1_000_000) if tp + fp else 1_000_000
            stats["recall_ppm"] = round((tp / (tp + fn)) * 1_000_000) if tp + fn else 1_000_000
            stats["fpr_ppm"] = round((fp / (fp + tn)) * 1_000_000) if fp + tn else 0
        requirement_stats[scanner] = dict(sorted(scanner_requirements.items()))

    return {
        "ok": not errors,
        "corpus": str(path),
        "version": corpus.get("version") if isinstance(corpus, dict) else None,
        "scanners": scanner_stats,
        "scanner_requirements": requirement_stats,
        "external_invocations": external_invocations,
        "errors": errors,
        "cases": rows,
        "disagreements": [row for row in rows if row.get("disagreement")],
    }


def add_confusion_rates(stats: dict[str, int]) -> dict[str, int]:
    tp = stats["tp"]
    fp = stats["fp"]
    fn = stats["fn"]
    tn = stats["tn"]
    return {
        **stats,
        "precision_ppm": round((tp / (tp + fp)) * 1_000_000) if tp + fp else 1_000_000,
        "recall_ppm": round((tp / (tp + fn)) * 1_000_000) if tp + fn else 1_000_000,
        "fpr_ppm": round((fp / (fp + tn)) * 1_000_000) if fp + tn else 0,
    }


def asg_external_eval_stats(rows: list[dict[str, Any]]) -> dict[str, int]:
    stats = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in rows:
        positive = row.get("label") == "positive"
        detected = bool(row.get("asg_detected"))
        if positive and detected:
            stats["tp"] += 1
        elif positive:
            stats["fn"] += 1
        elif detected:
            stats["fp"] += 1
        else:
            stats["tn"] += 1
    return add_confusion_rates(stats)


def scanner_requirement_gaps(
    scanner_requirements: dict[str, dict[str, dict[str, int]]],
    *,
    limit: int,
) -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = {}
    for scanner, requirements in scanner_requirements.items():
        gaps: list[dict[str, Any]] = []
        for requirement, stats in requirements.items():
            if stats.get("fn", 0) or stats.get("fp", 0):
                gaps.append(
                    {
                        "requirement": requirement,
                        "fn": int(stats.get("fn", 0)),
                        "fp": int(stats.get("fp", 0)),
                        "tp": int(stats.get("tp", 0)),
                        "tn": int(stats.get("tn", 0)),
                        "skipped": int(stats.get("skipped", 0)),
                    }
                )
        gaps.sort(key=lambda item: (-(item["fn"] + item["fp"]), item["requirement"]))
        output[scanner] = gaps[:limit]
    return output


def summarize_external_eval_result(
    result: dict[str, Any],
    *,
    case_limit: int = 20,
    requirement_limit: int = 12,
) -> dict[str, Any]:
    cases = result.get("cases", [])
    rows = cases if isinstance(cases, list) else []
    disagreements = result.get("disagreements", [])
    disagreement_rows = disagreements if isinstance(disagreements, list) else []
    case_limit = max(0, case_limit)
    requirement_limit = max(0, requirement_limit)
    return {
        "ok": bool(result.get("ok")),
        "output": "summary",
        "corpus": result.get("corpus"),
        "version": result.get("version"),
        "case_count": len(rows),
        "asg": asg_external_eval_stats(rows),
        "scanners": result.get("scanners", {}),
        "external_invocations": result.get("external_invocations", {}),
        "errors": result.get("errors", []),
        "disagreement_count": len(disagreement_rows),
        "disagreements_sample": [
            {
                "id": row.get("id"),
                "label": row.get("label"),
                "surface": row.get("surface"),
                "requirements": row.get("requirements", []),
                "asg_detected": row.get("asg_detected"),
                "asg_kinds": row.get("asg_kinds", []),
                "external_detected_by": row.get("external_detected_by", []),
            }
            for row in disagreement_rows[:case_limit]
        ],
        "scanner_requirement_gaps": scanner_requirement_gaps(
            result.get("scanner_requirements", {}),
            limit=requirement_limit,
        ),
    }


def cmd_external_eval(args: argparse.Namespace) -> int:
    path = Path(args.corpus).expanduser()
    scanners = scanner_names_from_args(args.scanner)
    try:
        result = evaluate_external_corpus(path, scanners=scanners, timeout=args.timeout, threshold=args.threshold)
    except subprocess.TimeoutExpired:
        emit(json.dumps({"ok": False, "error": "external scanner timed out"}, sort_keys=True))
        return 1
    except Exception as exc:
        emit(json.dumps({"ok": False, "error": f"external eval failed: {exc.__class__.__name__}"}, sort_keys=True))
        return 1
    output = result if args.format == "full" else summarize_external_eval_result(
        result,
        case_limit=args.case_limit,
        requirement_limit=args.requirement_limit,
    )
    if not args.quiet:
        emit(json.dumps(output, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def daemon_socket_path(value: str = "") -> Path:
    configured = value or os.environ.get("ASG_DAEMON_SOCKET") or str(DEFAULT_SOCKET)
    return Path(configured).expanduser()


def daemon_pid_path(value: str = "") -> Path:
    configured = value or os.environ.get("ASG_DAEMON_PID") or str(DEFAULT_PID)
    return Path(configured).expanduser()


def socket_is_alive(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            sock.connect(str(path))
        return True
    except OSError:
        return False


def prepare_socket_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    if path.exists():
        if socket_is_alive(path):
            raise RuntimeError("daemon socket already in use")
        path.unlink()


def probe_socket_bind(path: Path) -> None:
    prepare_socket_path(path)
    old_umask = os.umask(0o177)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(str(path))
    finally:
        os.umask(old_umask)
        with contextlib.suppress(OSError):
            path.unlink()


def read_pid_file(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
        return int(text) if text else None
    except Exception:
        return None


def process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def read_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(min(remaining, 64 * 1024))
        if not chunk:
            raise EOFError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_daemon_request(sock: socket.socket) -> tuple[list[str], str, dict[str, str]]:
    prefix = read_exact(sock, DAEMON_HEADER_STRUCT.size)
    header_len, body_len = DAEMON_HEADER_STRUCT.unpack(prefix)
    if header_len > DAEMON_HEADER_LIMIT or body_len > DAEMON_BODY_LIMIT:
        raise ValueError("request too large")
    try:
        header = json.loads(read_exact(sock, header_len).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid daemon header") from exc
    body = read_exact(sock, body_len).decode("utf-8", errors="replace")
    argv = header.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise ValueError("invalid argv")
    raw_env = header.get("env", {})
    if raw_env is None:
        raw_env = {}
    if not isinstance(raw_env, dict):
        raise ValueError("invalid env")
    env = {
        str(key): str(value)
        for key, value in raw_env.items()
        if key in DAEMON_ENV_OVERRIDES and isinstance(value, str) and len(value) <= 4096
    }
    return argv, body, env


def write_daemon_response(sock: socket.socket, exit_code: int, stdout_text: str, stderr_text: str = "") -> None:
    stdout_bytes = stdout_text.encode("utf-8", errors="replace")
    stderr_bytes = stderr_text.encode("utf-8", errors="replace")
    sock.sendall(DAEMON_RESPONSE_STRUCT.pack(max(0, exit_code), len(stderr_bytes), len(stdout_bytes)))
    if stderr_bytes:
        sock.sendall(stderr_bytes)
    if stdout_bytes:
        sock.sendall(stdout_bytes)


def send_daemon_request(path: Path, argv: list[str], body: str = "", *, timeout: float = 1.0) -> tuple[int, str, str]:
    header = json.dumps({"argv": argv}, separators=(",", ":")).encode("utf-8")
    body_bytes = body.encode("utf-8", errors="replace")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(DAEMON_HEADER_STRUCT.pack(len(header), len(body_bytes)))
        sock.sendall(header)
        if body_bytes:
            sock.sendall(body_bytes)
        prefix = read_exact(sock, DAEMON_RESPONSE_STRUCT.size)
        exit_code, stderr_len, stdout_len = DAEMON_RESPONSE_STRUCT.unpack(prefix)
        stderr_text = read_exact(sock, stderr_len).decode("utf-8", errors="replace") if stderr_len else ""
        stdout_text = read_exact(sock, stdout_len).decode("utf-8", errors="replace") if stdout_len else ""
        return exit_code, stdout_text, stderr_text


def daemon_worker_timeout() -> float:
    raw = os.environ.get("ASG_DAEMON_WORKER_TIMEOUT", "")
    try:
        value = float(raw) if raw else DEFAULT_DAEMON_WORKER_TIMEOUT
    except ValueError:
        value = DEFAULT_DAEMON_WORKER_TIMEOUT
    return min(max(value, 0.1), 30.0)


def daemon_command_supported(argv: list[str]) -> bool:
    return bool(
        argv
        and argv[0]
        in {
            "scan",
            "redact",
            "json-block",
            "json-redact",
            "codex-hook",
            "cursor-hook",
            "claude-pre",
            "claude-post",
        }
    )


def execute_daemon_argv(argv: list[str], stdin_text: str, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    if not argv:
        return 2, "", "agent-secret-guard daemon: missing command\n"
    if not daemon_command_supported(argv):
        return 2, "", "agent-secret-guard daemon: unsupported command\n"

    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 2
        return code, "", "agent-secret-guard daemon: unsupported arguments\n"

    child_env = os.environ.copy()
    child_env.update(env or {})
    try:
        proc = subprocess.run(  # nosec B603 - daemon executes the fixed local ASG engine without shell=True.
            [sys.executable, str(Path(__file__).resolve()), *argv],
            input=stdin_text.encode("utf-8", errors="replace"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_env,
            timeout=daemon_worker_timeout(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 1, "", "agent-secret-guard daemon: worker timed out\n"
    except Exception as exc:
        return 1, "", f"agent-secret-guard daemon: command failed: {exc.__class__.__name__}\n"
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def spawn_daemon_process(command: list[str]) -> int:
    return os.posix_spawn(
        command[0],
        command,
        os.environ.copy(),
        file_actions=[
            (os.POSIX_SPAWN_OPEN, 0, os.devnull, os.O_RDONLY, 0),
            (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
        ],
        setsid=True,
    )


class AgentSecretGuardServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 64

    def handle_error(self, request: Any, client_address: Any) -> None:
        return


class AgentSecretGuardHandler(socketserver.BaseRequestHandler):
    request: socket.socket

    def handle(self) -> None:
        try:
            argv, body, env = read_daemon_request(self.request)
            if argv == ["__shutdown__"]:
                write_daemon_response(self.request, 0, json.dumps({"ok": True}) + "\n")
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            exit_code, stdout_text, stderr_text = execute_daemon_argv(argv, body, env)
            write_daemon_response(self.request, exit_code, stdout_text, stderr_text)
        except Exception:
            with contextlib.suppress(Exception):
                write_daemon_response(self.request, 1, "", "agent-secret-guard daemon: request failed\n")


def cmd_serve(args: argparse.Namespace) -> int:
    path = daemon_socket_path(args.socket)
    pid_path = daemon_pid_path(args.pid_file)
    try:
        prepare_socket_path(path)
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.parent.chmod(0o700)
        old_umask = os.umask(0o177)
        try:
            server = AgentSecretGuardServer(str(path), AgentSecretGuardHandler)
        finally:
            os.umask(old_umask)
    except Exception as exc:
        with contextlib.suppress(OSError):
            if path.exists() and not socket_is_alive(path):
                path.unlink()
        emit(json.dumps({"ok": False, "error": f"daemon unavailable: {exc.__class__.__name__}"}, sort_keys=True))
        return 1

    path.chmod(0o600)
    pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")
    pid_path.chmod(0o600)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
        with contextlib.suppress(OSError):
            if path.exists():
                path.unlink()
        with contextlib.suppress(OSError):
            if pid_path.exists() and read_pid_file(pid_path) == os.getpid():
                pid_path.unlink()
    return 0


def cmd_daemon_start(args: argparse.Namespace) -> int:
    path = daemon_socket_path(args.socket)
    pid_path = daemon_pid_path(args.pid_file)
    if socket_is_alive(path):
        emit(json.dumps({"ok": True, "pid": read_pid_file(pid_path), "running": True, "socket": str(path)}, sort_keys=True))
        return 0

    try:
        probe_socket_bind(path)
    except Exception as exc:
        emit(
            json.dumps(
                {"ok": False, "error": f"daemon unavailable: {exc.__class__.__name__}", "running": False, "socket": str(path)},
                sort_keys=True,
            )
        )
        return 1

    command = [sys.executable, str(Path(__file__).resolve()), "serve", "--socket", str(path), "--pid-file", str(pid_path)]
    try:
        spawn_daemon_process(command)
    except Exception as exc:
        emit(json.dumps({"ok": False, "error": f"daemon start failed: {exc.__class__.__name__}"}, sort_keys=True))
        return 1

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        if socket_is_alive(path):
            emit(json.dumps({"ok": True, "pid": read_pid_file(pid_path), "running": True, "socket": str(path)}, sort_keys=True))
            return 0
        time.sleep(0.03)
    emit(json.dumps({"ok": False, "pid": read_pid_file(pid_path), "running": False, "socket": str(path)}, sort_keys=True))
    return 1


def cmd_daemon_status(args: argparse.Namespace) -> int:
    path = daemon_socket_path(args.socket)
    pid_path = daemon_pid_path(args.pid_file)
    running = socket_is_alive(path)
    pid = read_pid_file(pid_path)
    emit(json.dumps({"ok": running, "pid": pid, "process_alive": process_is_alive(pid) if pid else False, "running": running, "socket": str(path)}, sort_keys=True))
    return 0 if running else 1


def cmd_daemon_stop(args: argparse.Namespace) -> int:
    path = daemon_socket_path(args.socket)
    pid_path = daemon_pid_path(args.pid_file)
    pid = read_pid_file(pid_path)
    requested = False
    if socket_is_alive(path):
        with contextlib.suppress(Exception):
            send_daemon_request(path, ["__shutdown__"], timeout=args.timeout)
            requested = True

    if not pid:
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline and socket_is_alive(path):
            time.sleep(0.03)
        stopped = not socket_is_alive(path)
        if stopped:
            with contextlib.suppress(OSError):
                if path.exists():
                    path.unlink()
        emit(json.dumps({"ok": stopped, "requested": requested, "running": not stopped, "socket": str(path)}, sort_keys=True))
        return 0 if stopped else 1

    if not requested:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, 15)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        if not process_is_alive(pid):
            break
        time.sleep(0.03)
    stopped = not process_is_alive(pid)
    if stopped:
        with contextlib.suppress(OSError):
            if pid_path.exists():
                pid_path.unlink()
        with contextlib.suppress(OSError):
            if path.exists() and not socket_is_alive(path):
                path.unlink()
    emit(json.dumps({"ok": stopped, "pid": pid, "running": not stopped, "socket": str(path)}, sort_keys=True))
    return 0 if stopped else 1


CODEX_HOOK_EVENTS = ("UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse")
CURSOR_HOOK_EVENTS = (
    "beforeSubmitPrompt",
    "preToolUse",
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "postToolUse",
    "afterShellExecution",
    "afterMCPExecution",
    "afterFileEdit",
    "afterAgentResponse",
    "afterAgentThought",
)
CURSOR_HOOK_MARKERS = (
    "asg-cursor-before-prompt",
    "asg-cursor-pretooluse",
    "asg-cursor-before-shell",
    "asg-cursor-before-mcp",
    "asg-cursor-before-read",
    "asg-cursor-posttooluse",
    "asg-cursor-after-shell",
    "asg-cursor-after-mcp",
    "asg-cursor-after-file-edit",
    "asg-cursor-after-agent-response",
    "asg-cursor-after-agent-thought",
)
PRIMARY_HARNESSES = ("claude", "codex", "cursor")


def cursor_installation_status() -> dict[str, Any]:
    app_paths = (
        Path("/Applications/Cursor.app"),
        Path.home() / "Applications/Cursor.app",
    )
    app_path = next((path for path in app_paths if path.exists()), None)
    bundled_cli = app_path / "Contents/Resources/app/bin/cursor" if app_path else None
    path_cli = shutil.which("cursor")
    agent_cli = shutil.which("cursor-agent")
    return {
        "available": bool(app_path or path_cli or agent_cli),
        "ide_app_available": bool(app_path),
        "ide_app_path": str(app_path) if app_path else None,
        "path_cli_available": bool(path_cli),
        "path_cli_path": path_cli,
        "bundled_cli_available": bool(bundled_cli and os.access(bundled_cli, os.X_OK)),
        "bundled_cli_path": str(bundled_cli) if bundled_cli and bundled_cli.exists() else None,
        "agent_cli_available": bool(agent_cli),
        "agent_cli_path": agent_cli,
    }


CLAUDE_HOOK_MARKERS = {
    "PreToolUse": (
        "secret-wrap",
        "cmd-leak-guard",
        "file-leak-guard",
        "secret-mcp-guard",
        "secret-url-guard",
        "secret-push-guard",
        "infisical-guard",
    ),
    "PostToolUse": ("secret-scan",),
}


def _iter_hook_commands(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "command" and isinstance(child, str):
                yield child
            else:
                yield from _iter_hook_commands(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_hook_commands(child)


def _load_json_config(path: Path) -> tuple[Any | None, str | None]:
    if not path.exists():
        return None, "missing"
    try:
        return json.loads(path.read_text()), None
    except json.JSONDecodeError as exc:
        return None, f"invalid-json line {exc.lineno} column {exc.colno}"
    except OSError as exc:
        return None, f"unreadable: {exc.__class__.__name__}"


def _hooks_root(config: Any) -> dict[str, Any]:
    if not isinstance(config, dict):
        return {}
    hooks = config.get("hooks")
    return hooks if isinstance(hooks, dict) else {}


def _event_command_counts(config: Any, events: Iterable[str], command_markers: str | Iterable[str]) -> dict[str, dict[str, int]]:
    markers = (command_markers,) if isinstance(command_markers, str) else tuple(command_markers)
    hooks = _hooks_root(config)
    counts: dict[str, dict[str, int]] = {}
    for event in events:
        commands = list(_iter_hook_commands(hooks.get(event, [])))
        counts[event] = {
            "commands": len(commands),
            "matching_commands": sum(1 for command in commands if any(marker in command for marker in markers)),
        }
    return counts


def _event_hook_commands(config: Any, events: Iterable[str]) -> list[dict[str, Any]]:
    hooks = _hooks_root(config)
    entries: list[dict[str, Any]] = []
    for event in events:
        for command_index, command in enumerate(_iter_hook_commands(hooks.get(event, []))):
            entries.append(
                {
                    "event": event,
                    "entry_index": command_index,
                    "hook_index": 0,
                    "command": command,
                }
            )
    return entries


def _command_entrypoint(command: str) -> tuple[str, str | None]:
    try:
        parts = shlex.split(command)
    except ValueError:
        return "", "invalid-shell-syntax"
    if not parts:
        return "", "empty-command"
    return parts[0], None


def _command_kind(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        return "invalid"
    if "herdr-agent-state.sh" in parts:
        return "herdr-agent-state.sh"
    if not parts:
        return "empty"
    return Path(parts[0]).name or parts[0]


def hook_command_health(config: Any, events: Iterable[str]) -> dict[str, Any]:
    entries = []
    static_failures = 0
    for item in _event_hook_commands(config, events):
        command = str(item["command"])
        try:
            command_parts = shlex.split(command)
        except ValueError:
            command_parts = []
        entrypoint, error = _command_entrypoint(command)
        kind = _command_kind(command)
        absolute = entrypoint.startswith("/")
        exists = Path(entrypoint).exists() if absolute else False
        executable = os.access(entrypoint, os.X_OK) if exists else False
        problems: list[str] = []
        if error:
            problems.append(error)
        elif not absolute:
            problems.append("non-absolute-entrypoint")
        elif not exists:
            problems.append("missing-entrypoint")
        elif not executable:
            problems.append("entrypoint-not-executable")
        if kind == "asg-fast" and any(part in {"codex-hook", "cursor-hook"} for part in command_parts[1:]):
            problems.append("direct-asg-fast-hook-command")
        if problems:
            static_failures += 1
        entries.append(
            {
                "event": item["event"],
                "entry_index": item["entry_index"],
                "hook_index": item["hook_index"],
                "kind": kind,
                "absolute_entrypoint": absolute,
                "entrypoint_exists": exists,
                "entrypoint_executable": executable,
                "argument_count": max(0, len(command_parts) - 1),
                "problems": problems,
            }
        )
    return {"entries": entries, "static_failures": static_failures}


def _codex_probe_payload(event: str) -> str:
    payload: dict[str, Any] = {"hook_event_name": event}
    if event in {"PreToolUse", "PermissionRequest"}:
        payload.update({"tool_name": "Bash", "tool_input": {"command": "true"}})
    elif event == "PostToolUse":
        payload.update({"tool_name": "Bash", "tool_response": {"stdout": "ok", "stderr": ""}})
    elif event == "UserPromptSubmit":
        payload.update({"prompt": "hello"})
    return json.dumps(payload)


def _safe_runtime_probe_command(command: str) -> bool:
    kind = _command_kind(command)
    return kind in {"asg-codex-hook", "dcg", "herdr-agent-state.sh"}


def _safe_claude_runtime_probe_command(command: str) -> bool:
    kind = _command_kind(command)
    return any(kind in markers for markers in CLAUDE_HOOK_MARKERS.values())


def _runtime_probe_case(
    *,
    name: str,
    argv: list[str],
    input_text: str,
    timeout: float,
    env_extra: dict[str, str] | None = None,
    expect_code: int = 0,
    expect_json: bool = False,
    forbidden_text: str = "",
) -> dict[str, Any]:
    started = time.perf_counter()
    env = {**os.environ, "ASG_DISABLE_HOOK_TELEMETRY": "1"}
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(  # nosec B603 - local ASG health probe executes fixed argv without shell.
            argv,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "ok": False,
            "exit_code": 124,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": "TimeoutExpired",
        }

    checks = {"exit_code": proc.returncode == expect_code}
    if forbidden_text:
        checks["no_forbidden_text_leak"] = forbidden_text not in proc.stdout + proc.stderr
    if expect_json:
        try:
            json.loads(proc.stdout or "{}")
            checks["json_output"] = True
        except json.JSONDecodeError:
            checks["json_output"] = False
    return {
        "name": name,
        "ok": all(checks.values()),
        "exit_code": proc.returncode,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "stdout_bytes": len(proc.stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(proc.stderr.encode("utf-8", errors="replace")),
        "checks": checks,
    }


def _version_open_stdin_probe(fast: Path, *, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        proc = subprocess.Popen(  # nosec B603 - local ASG health probe executes fixed argv without shell.
            [str(fast), "--version"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "ASG_DISABLE_HOOK_TELEMETRY": "1"},
        )
        proc.wait(timeout=timeout)
        stdout, stderr = proc.communicate(timeout=0.2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            proc.kill()  # type: ignore[possibly-undefined]
        return {
            "name": "version-open-stdin",
            "ok": False,
            "exit_code": 124,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": "TimeoutExpired",
        }

    return {
        "name": "version-open-stdin",
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
    }


def fast_client_runtime_probe(*, timeout: float = 2.0) -> dict[str, Any]:
    fast = Path.home() / ".local/bin/asg-fast"
    result: dict[str, Any] = {"checked": 0, "failures": [], "cases": []}
    if not fast.exists():
        result["failures"].append({"name": "asg-fast-present", "error": "missing"})
        result["ok"] = False
        return result

    with tempfile.TemporaryDirectory(prefix="asg-runtime-probe-") as temp_dir:
        env_extra = {
            "HOME": temp_dir,
            "ASG_AGENT_SECRET_GUARD": str(Path.home() / ".local/bin/agent-secret-guard"),
            "ASG_DAEMON_SOCKET": str(Path(temp_dir) / "missing-asg.sock"),
            "ASG_DAEMON_PID": str(Path(temp_dir) / "missing-asg.pid"),
            "ASG_FAST_DAEMON_TIMEOUT_MS": "100",
            "ASG_FAST_FALLBACK_TIMEOUT_MS": "1000",
            "ASG_FAST_CIRCUIT_SECONDS": "1",
        }
        synthetic_secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        cases = [
            _version_open_stdin_probe(fast, timeout=timeout),
            _runtime_probe_case(
                name="scan-missing-daemon-fallback",
                argv=[str(fast), "scan", "--surface", "bash-command", "--quiet", "--fail-on-detect"],
                input_text="echo hello",
                timeout=timeout,
                env_extra=env_extra,
            ),
            _runtime_probe_case(
                name="scan-positive-detection",
                argv=[str(fast), "scan", "--surface", "bash-command", "--quiet", "--fail-on-detect"],
                input_text="echo " + synthetic_secret,
                timeout=timeout,
                env_extra=env_extra,
                expect_code=2,
                forbidden_text=synthetic_secret,
            ),
            _runtime_probe_case(
                name="codex-hook-missing-daemon-fallback",
                argv=[str(fast), "codex-hook"],
                input_text=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}),
                timeout=timeout,
                env_extra=env_extra,
                expect_json=True,
            ),
            _runtime_probe_case(
                name="claude-pre-missing-daemon-fallback",
                argv=[str(fast), "claude-pre", "--surface", "bash-command"],
                input_text=json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hello"}}),
                timeout=timeout,
                env_extra=env_extra,
                expect_json=True,
            ),
        ]

    result["cases"] = cases
    result["checked"] = len(cases)
    result["failures"] = [case for case in cases if not case.get("ok")]
    result["ok"] = not result["failures"]
    return result


def _claude_probe_payload(command: str, event: str) -> str:
    kind = _command_kind(command)
    if event == "PostToolUse" or kind == "secret-scan":
        payload = {"tool_name": "Bash", "tool_input": {"command": "true"}, "tool_response": {"stdout": "ok", "stderr": ""}}
    elif kind == "file-leak-guard":
        payload = {"tool_name": "Read", "tool_input": {"file_path": "/tmp/project/README.md"}}
    elif kind == "secret-url-guard":
        payload = {"tool_name": "WebFetch", "tool_input": {"url": "https://example.test/status"}}
    elif kind == "secret-mcp-guard":
        payload = {"tool_name": "mcp__local__noop", "tool_input": {"text": "ok"}}
    else:
        payload = {"tool_name": "Bash", "tool_input": {"command": "true"}}
    return json.dumps(payload)


def claude_hook_runtime_probe(path: Path, *, timeout: float = 2.0) -> dict[str, Any]:
    config, error = _load_json_config(path)
    result: dict[str, Any] = {
        "checked": 0,
        "skipped": 0,
        "failures": [],
    }
    if error:
        result["error"] = error
        return result
    for item in _event_hook_commands(config, CLAUDE_HOOK_MARKERS):
        command = str(item["command"])
        if not _safe_claude_runtime_probe_command(command):
            result["skipped"] += 1
            continue
        try:
            proc = subprocess.run(  # nosec B603 - local hook health probe; command text comes from user config and output is suppressed.
                ["/bin/sh", "-c", command],
                input=_claude_probe_payload(command, str(item["event"])),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": str(Path.home()), "PATH": "", "TMPDIR": "/tmp", "ASG_DISABLE_HOOK_TELEMETRY": "1"},
                timeout=timeout,
                check=False,
            )
            exit_code = proc.returncode
            stderr_bytes = len(proc.stderr.encode("utf-8", errors="replace"))
        except subprocess.TimeoutExpired:
            exit_code = 124
            stderr_bytes = 0
        result["checked"] += 1
        if exit_code != 0:
            result["failures"].append(
                {
                    "event": item["event"],
                    "entry_index": item["entry_index"],
                    "hook_index": item["hook_index"],
                    "kind": _command_kind(command),
                    "exit_code": exit_code,
                    "stderr_bytes": stderr_bytes,
                }
            )
    return result


def daemon_circuit_status() -> dict[str, Any]:
    path = Path.home() / ".local/run/agent-secret-guard/asg-unhealthy-until"
    result: dict[str, Any] = {"path": str(path), "present": path.exists(), "open": False}
    if not path.exists():
        return result
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").strip()
        until = int(raw)
    except Exception as exc:
        result["error"] = exc.__class__.__name__
        return result
    now = int(time.time())
    result["unhealthy_until"] = until
    result["seconds_remaining"] = max(0, until - now)
    result["open"] = until > now
    return result


def codex_hook_runtime_probe(path: Path, *, timeout: float = 2.0) -> dict[str, Any]:
    config, error = _load_json_config(path)
    result: dict[str, Any] = {
        "checked": 0,
        "skipped": 0,
        "failures": [],
    }
    if error:
        result["error"] = error
        return result
    for item in _event_hook_commands(config, CODEX_HOOK_EVENTS):
        command = str(item["command"])
        if not _safe_runtime_probe_command(command):
            result["skipped"] += 1
            continue
        try:
            proc = subprocess.run(  # nosec B603 - local hook health probe; command text comes from user config and output is suppressed.
                ["/bin/sh", "-c", command],
                input=_codex_probe_payload(str(item["event"])),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": str(Path.home()), "PATH": "", "TMPDIR": "/tmp", "ASG_DISABLE_HOOK_TELEMETRY": "1"},
                timeout=timeout,
                check=False,
            )
            exit_code = proc.returncode
            stderr_bytes = len(proc.stderr.encode("utf-8", errors="replace"))
        except subprocess.TimeoutExpired:
            exit_code = 124
            stderr_bytes = 0
        result["checked"] += 1
        if exit_code != 0:
            result["failures"].append(
                {
                    "event": item["event"],
                    "entry_index": item["entry_index"],
                    "hook_index": item["hook_index"],
                    "kind": _command_kind(command),
                    "exit_code": exit_code,
                    "stderr_bytes": stderr_bytes,
                }
            )
    return result


def _cursor_probe_payload(event: str) -> str:
    payload: dict[str, Any] = {"hook_event_name": event}
    if event == "beforeSubmitPrompt":
        payload.update({"prompt": "status update"})
    elif event == "preToolUse":
        payload.update({"tool_name": "Bash", "tool_input": {"command": "true"}})
    elif event == "postToolUse":
        payload.update({"tool_name": "Bash", "tool_response": {"stdout": "ok", "stderr": ""}})
    elif event == "beforeShellExecution":
        payload.update({"command": "true"})
    elif event == "afterShellExecution":
        payload.update({"output": "ok"})
    elif event == "beforeMCPExecution":
        payload.update({"server_name": "local", "tool_name": "noop", "arguments": {"query": "status"}})
    elif event == "afterMCPExecution":
        payload.update({"server_name": "local", "tool_name": "noop", "result": {"text": "ok"}})
    elif event == "beforeReadFile":
        payload.update({"path": "/tmp/project/README.md"})
    elif event == "afterFileEdit":
        payload.update({"content": "ok"})
    elif event == "afterAgentResponse":
        payload.update({"text": "ok"})
    elif event == "afterAgentThought":
        payload.update({"text": "ok"})
    return json.dumps(payload)


def _safe_cursor_runtime_probe_command(command: str) -> bool:
    return _command_kind(command) in set(CURSOR_HOOK_MARKERS)


def cursor_hook_runtime_probe(path: Path, *, timeout: float = 2.0) -> dict[str, Any]:
    config, error = _load_json_config(path)
    result: dict[str, Any] = {
        "checked": 0,
        "skipped": 0,
        "failures": [],
    }
    if error:
        result["error"] = error
        return result
    for item in _event_hook_commands(config, CURSOR_HOOK_EVENTS):
        command = str(item["command"])
        if not _safe_cursor_runtime_probe_command(command):
            result["skipped"] += 1
            continue
        try:
            proc = subprocess.run(  # nosec B603 - local hook health probe; command text comes from user config and output is suppressed.
                ["/bin/sh", "-c", command],
                input=_cursor_probe_payload(str(item["event"])),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": str(Path.home()), "PATH": "", "TMPDIR": "/tmp", "ASG_DISABLE_HOOK_TELEMETRY": "1"},
                timeout=timeout,
                check=False,
            )
            exit_code = proc.returncode
            stderr_bytes = len(proc.stderr.encode("utf-8", errors="replace"))
        except subprocess.TimeoutExpired:
            exit_code = 124
            stderr_bytes = 0
        result["checked"] += 1
        if exit_code != 0:
            result["failures"].append(
                {
                    "event": item["event"],
                    "entry_index": item["entry_index"],
                    "hook_index": item["hook_index"],
                    "kind": _command_kind(command),
                    "exit_code": exit_code,
                    "stderr_bytes": stderr_bytes,
                }
            )
    return result


def _audit_marker_events(path: Path, events: Iterable[str], command_marker: str | Iterable[str]) -> dict[str, Any]:
    config, error = _load_json_config(path)
    result: dict[str, Any] = {
        "config_path": str(path),
        "config_present": error != "missing",
        "config_valid_json": error is None,
        "expected_events": list(events),
        "event_counts": {},
        "missing_events": list(events),
        "coverage": "config-missing" if error == "missing" else "invalid-json" if error else "missing",
    }
    if error:
        result["error"] = error
        return result

    counts = _event_command_counts(config, events, command_marker)
    missing = [event for event, event_counts in counts.items() if event_counts["matching_commands"] < 1]
    result["event_counts"] = counts
    result["missing_events"] = missing
    result["command_health"] = hook_command_health(config, events)
    result["coverage"] = "covered" if not missing else "missing"
    return result


def _audit_claude_config(path: Path) -> dict[str, Any]:
    config, error = _load_json_config(path)
    result: dict[str, Any] = {
        "config_path": str(path),
        "config_present": error != "missing",
        "config_valid_json": error is None,
        "expected_events": list(CLAUDE_HOOK_MARKERS),
        "event_counts": {},
        "missing_markers": CLAUDE_HOOK_MARKERS,
        "coverage": "config-missing" if error == "missing" else "invalid-json" if error else "missing",
    }
    if error:
        result["error"] = error
        return result

    hooks = _hooks_root(config)
    event_counts: dict[str, dict[str, Any]] = {}
    missing_markers: dict[str, list[str]] = {}
    for event, markers in CLAUDE_HOOK_MARKERS.items():
        commands = list(_iter_hook_commands(hooks.get(event, [])))
        marker_counts = {
            marker: sum(1 for command in commands if marker in command)
            for marker in markers
        }
        event_counts[event] = {"commands": len(commands), "marker_counts": marker_counts}
        missing = [marker for marker, count in marker_counts.items() if count < 1]
        if missing:
            missing_markers[event] = missing

    result["event_counts"] = event_counts
    result["missing_markers"] = missing_markers
    result["coverage"] = "covered" if not missing_markers else "missing"
    return result


def _audit_cursor_config(path: Path) -> dict[str, Any]:
    result = _audit_marker_events(path, CURSOR_HOOK_EVENTS, CURSOR_HOOK_MARKERS)
    cursor_status = cursor_installation_status()
    result["harness_available"] = bool(cursor_status["available"])
    result["harness"] = cursor_status
    if result.get("coverage") == "config-missing" and not result["harness_available"]:
        result["coverage"] = "harness-unavailable"
        result["note"] = "Cursor is not installed locally; generated cursor-hooks.json is available for future installs"
    else:
        result["known_limits"] = [
            "Cursor hook enforcement has current upstream reliability reports; deny is the only meaningful enforcement verdict.",
            "Some Cursor CLI/cloud-agent events may not fire consistently across versions.",
        ]
    return result


def active_harness_coverage(paths: dict[str, Path] | None = None) -> dict[str, Any]:
    home = Path.home()
    config_paths = {
        "claude": home / ".claude/settings.json",
        "codex": home / ".codex/hooks.json",
        "cursor": home / ".cursor/hooks.json",
    }
    if paths:
        config_paths.update(paths)

    return {
        "claude": _audit_claude_config(config_paths["claude"]),
        "codex": _audit_marker_events(config_paths["codex"], CODEX_HOOK_EVENTS, ("asg-codex-hook",)),
        "cursor": _audit_cursor_config(config_paths["cursor"]),
    }


def cmd_doctor(args: argparse.Namespace) -> int:
    commands = [
        "agent-secret-guard",
        "asg-fast",
        "asg-json-block",
        "asg-json-redact",
        "asg-stream-redact",
        "asg-bash-command-block",
        "asg-vcs-diff-block",
        "asg-run",
        "asg-recover",
        "asg-hook-lib",
        "asg-codex-hook",
        "asg-cursor-before-prompt",
        "asg-cursor-pretooluse",
        "asg-cursor-before-shell",
        "asg-cursor-before-mcp",
        "asg-cursor-before-read",
        "asg-cursor-posttooluse",
        "asg-cursor-after-shell",
        "asg-cursor-after-mcp",
        "asg-cursor-after-file-edit",
        "asg-cursor-after-agent-response",
        "asg-cursor-after-agent-thought",
        "secret-scan",
        "secret-filter",
        "secret-wrap",
        "secret-mcp-guard",
        "secret-url-guard",
        "secret-push-guard",
        "cmd-leak-guard",
        "file-leak-guard",
        "infisical-guard",
    ]
    external_scanners = ["gitleaks", "trufflehog", "detect-secrets"]
    harnesses = list(PRIMARY_HARNESSES)

    def which_map(names: list[str]) -> dict[str, dict[str, Any]]:
        return {
            name: {"available": bool(shutil.which(name)), "path": shutil.which(name)}
            for name in names
        }

    coverage = active_harness_coverage()
    fast_runtime = fast_client_runtime_probe()
    daemon_circuit = daemon_circuit_status()
    claude_runtime = claude_hook_runtime_probe(Path.home() / ".claude/settings.json")
    codex_runtime = codex_hook_runtime_probe(Path.home() / ".codex/hooks.json")
    cursor_runtime = cursor_hook_runtime_probe(Path.home() / ".cursor/hooks.json")
    hook_observations = hook_observation_summary()
    recent_hook_observations = hook_observation_summary(window_seconds=60 * 60)
    coverage["claude"]["runtime_probe"] = claude_runtime
    coverage["codex"]["runtime_probe"] = codex_runtime
    coverage["cursor"]["runtime_probe"] = cursor_runtime
    result = {
        "ok": True,
        "python": sys.version.split()[0],
        "commands": which_map(commands),
        "external_scanners": which_map(external_scanners),
        "harnesses": which_map(harnesses),
        "active_harness_coverage": coverage,
        "fast_client_runtime_probe": fast_runtime,
        "daemon_circuit": daemon_circuit,
        "hook_observations": hook_observations,
        "recent_hook_observations": recent_hook_observations,
        "notes": [
            "doctor reads only known agent hook config JSON files and emits structural coverage counts, never hook values",
            "doctor does not read project files, .env files, or session logs",
            "doctor probes asg-fast metadata and missing-daemon fallback under a strict timeout",
            "doctor fails when recent infrastructure fail-open or fail-closed telemetry or an open daemon circuit breaker is present",
            "doctor probes ASG Claude wrapper hooks with benign payloads when Claude hook config is present",
            "doctor probes known-safe Codex hooks with benign payloads under an empty PATH to catch code-127 failures",
            "doctor probes ASG Cursor wrapper hooks with benign payloads under an empty PATH when Cursor hook config is present",
            "hook_observations are payload-free ASG wrapper invocation counts and never contain tool input/output",
            "configured hook coverage is not proof that every agent runtime version fires every event",
        ],
    }
    result["harnesses"]["cursor"] = cursor_installation_status()
    missing_required = [name for name, item in result["commands"].items() if not item["available"]]
    if missing_required:
        result["ok"] = False
        result["missing_required"] = missing_required
    if fast_runtime.get("failures"):
        result["ok"] = False
        result["fast_client_runtime_failures"] = len(fast_runtime["failures"])
    if daemon_circuit.get("open"):
        result["ok"] = False
        result["daemon_circuit_open"] = True
    recent_fail_open = recent_hook_observations.get("events", {}).get("infrastructure:fail-open", {})
    if recent_fail_open.get("count", 0):
        result["ok"] = False
        result["recent_fail_open_events"] = int(recent_fail_open.get("count", 0))
    recent_fail_closed = recent_hook_observations.get("events", {}).get("infrastructure:fail-closed", {})
    if recent_fail_closed.get("count", 0):
        result["ok"] = False
        result["recent_fail_closed_events"] = int(recent_fail_closed.get("count", 0))
    codex_health = coverage.get("codex", {}).get("command_health", {})
    if codex_health.get("static_failures"):
        result["ok"] = False
        result["codex_hook_command_failures"] = int(codex_health.get("static_failures", 0))
    if codex_runtime.get("failures"):
        result["ok"] = False
        result["codex_hook_runtime_failures"] = len(codex_runtime["failures"])
    if claude_runtime.get("failures"):
        result["ok"] = False
        result["claude_hook_runtime_failures"] = len(claude_runtime["failures"])
    cursor_health = coverage.get("cursor", {}).get("command_health", {})
    if cursor_health.get("static_failures"):
        result["ok"] = False
        result["cursor_hook_command_failures"] = int(cursor_health.get("static_failures", 0))
    if cursor_runtime.get("failures"):
        result["ok"] = False
        result["cursor_hook_runtime_failures"] = len(cursor_runtime["failures"])
    emit(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _json_path(value: Any, path: tuple[Any, ...]) -> Any:
    current = value
    for part in path:
        if isinstance(part, int) and isinstance(current, list) and 0 <= part < len(current):
            current = current[part]
            continue
        if isinstance(part, str) and isinstance(current, dict):
            current = current.get(part)
            continue
        return None
    return current


def _proof_case(
    *,
    name: str,
    harness: str,
    surface: str,
    argv: list[str],
    input_value: Any,
    expect_code: int | None,
    canaries: list[str],
    expect_json: tuple[tuple[Any, ...], Any] | None = None,
    expect_contains: str = "",
    timeout: float = 5.0,
) -> dict[str, Any]:
    input_text = json.dumps(input_value) if not isinstance(input_value, str) else input_value
    started = time.perf_counter()
    try:
        proc = subprocess.run(  # nosec B603 - proof executes fixed local adapter argv without shell.
            argv,
            input=input_text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "ASG_DISABLE_HOOK_TELEMETRY": "1"},
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {
            "name": name,
            "harness": harness,
            "surface": surface,
            "ok": False,
            "error": exc.__class__.__name__,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    stderr_text = proc.stderr.decode("utf-8", errors="replace")
    leaked = any(canary and canary in stdout_text + stderr_text for canary in canaries)
    checks: dict[str, bool] = {"no_canary_leak": not leaked}
    if expect_code is not None:
        checks["exit_code"] = proc.returncode == expect_code
    if expect_contains:
        checks["stdout_contains_expected_marker"] = expect_contains in stdout_text
    if expect_json is not None:
        path, expected = expect_json
        try:
            parsed = json.loads(stdout_text or "{}")
        except json.JSONDecodeError:
            parsed = None
        checks["json_contract"] = _json_path(parsed, path) == expected

    return {
        "name": name,
        "harness": harness,
        "surface": surface,
        "ok": all(checks.values()),
        "exit_code": proc.returncode,
        "checks": checks,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def cmd_prove(args: argparse.Namespace) -> int:
    bin_dir = Path.home() / ".local/bin"
    core = str(bin_dir / "agent-secret-guard")
    python = shutil.which("python3") or sys.executable
    openai = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz" + "123456"
    github = "ghp_" + "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJ"
    anthropic = "sk-" + "ant-api03-" + "aZ7mQ9pL2rT4vW6xY8bC0dF3gH5jK7nP9qR2sT4uV6wX8"
    canaries = [openai, github, anthropic]

    cases = [
        _proof_case(
            name="core-scan-block",
            harness="generic",
            surface="text",
            argv=[core, "scan", "--quiet", "--fail-on-detect"],
            input_value=f"api_key={openai}",
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="core-redact-json",
            harness="generic",
            surface="text",
            argv=[core, "redact", "--json"],
            input_value=f"token={github}",
            expect_code=0,
            expect_contains="[REDACTED:",
            canaries=canaries,
        ),
        _proof_case(
            name="json-block",
            harness="generic",
            surface="tool-input",
            argv=[str(bin_dir / "asg-json-block")],
            input_value={"tool_input": {"apiKey": openai}},
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="json-redact",
            harness="generic",
            surface="tool-output",
            argv=[str(bin_dir / "asg-json-redact")],
            input_value={"tool_response": {"stdout": github}},
            expect_code=0,
            expect_contains="[REDACTED:",
            canaries=canaries,
        ),
        _proof_case(
            name="stream-redact",
            harness="generic",
            surface="stream",
            argv=[str(bin_dir / "asg-stream-redact")],
            input_value=f"token={github}",
            expect_code=0,
            expect_contains="[REDACTED:",
            canaries=canaries,
        ),
        _proof_case(
            name="bash-command-block",
            harness="generic",
            surface="bash-command",
            argv=[str(bin_dir / "asg-bash-command-block")],
            input_value=f"echo {openai}",
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="vcs-diff-block",
            harness="generic",
            surface="vcs-diff",
            argv=[str(bin_dir / "asg-vcs-diff-block")],
            input_value=f"+ API_KEY={openai}",
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="exec-wrapper-redacts-output",
            harness="generic",
            surface="exec-stdout",
            argv=[str(bin_dir / "asg-run"), python, "-c", 'print("sk-"+"proj-"+"abcdefghijklmnopqrstuvwxyz"+"123456")'],
            input_value="",
            expect_code=0,
            expect_contains="[REDACTED:",
            canaries=canaries,
        ),
        _proof_case(
            name="claude-cmd-leak-guard",
            harness="claude",
            surface="bash-command",
            argv=[str(bin_dir / "cmd-leak-guard")],
            input_value={"tool_name": "Bash", "tool_input": {"command": f"echo {openai}"}},
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="claude-file-leak-guard",
            harness="claude",
            surface="file-path",
            argv=[str(bin_dir / "file-leak-guard")],
            input_value={"tool_name": "Read", "tool_input": {"file_path": "/tmp/project/.env"}},
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="claude-secret-wrap",
            harness="claude",
            surface="bash-command",
            argv=[str(bin_dir / "secret-wrap")],
            input_value={"tool_name": "Bash", "tool_input": {"command": f"echo {openai}"}},
            expect_code=0,
            expect_json=(("hookSpecificOutput", "permissionDecision"), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="claude-post-redacts",
            harness="claude",
            surface="tool-output",
            argv=[str(bin_dir / "secret-scan")],
            input_value={"tool_name": "Bash", "tool_response": {"stdout": github}},
            expect_code=0,
            expect_contains="[REDACTED:",
            canaries=canaries,
        ),
        _proof_case(
            name="claude-url-guard",
            harness="claude",
            surface="url",
            argv=[str(bin_dir / "secret-url-guard")],
            input_value={"tool_name": "WebFetch", "tool_input": {"url": f"https://example.test/?access_token={openai}"}},
            expect_code=0,
            expect_json=(("hookSpecificOutput", "permissionDecision"), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="claude-mcp-guard",
            harness="claude",
            surface="outbound",
            argv=[str(bin_dir / "secret-mcp-guard")],
            input_value={"tool_name": "mcp__slack__send", "tool_input": {"text": github}},
            expect_code=0,
            expect_json=(("hookSpecificOutput", "permissionDecision"), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="claude-infisical-guard",
            harness="claude",
            surface="bash-command",
            argv=[str(bin_dir / "infisical-guard")],
            input_value={"tool_name": "Bash", "tool_input": {"command": "infisical secrets get API_KEY --env=dev --plain"}},
            expect_code=2,
            canaries=canaries,
        ),
        _proof_case(
            name="codex-pretooluse-deny",
            harness="codex",
            surface="tool-input",
            argv=[str(bin_dir / "asg-codex-hook")],
            input_value={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"echo {openai}"}},
            expect_code=0,
            expect_json=(("hookSpecificOutput", "permissionDecision"), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="codex-posttooluse-block",
            harness="codex",
            surface="tool-output",
            argv=[str(bin_dir / "asg-codex-hook")],
            input_value={"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": {"stdout": github}},
            expect_code=0,
            expect_json=(("decision",), "block"),
            canaries=canaries,
        ),
        _proof_case(
            name="codex-prompt-allow",
            harness="codex",
            surface="prompt",
            argv=[str(bin_dir / "asg-codex-hook")],
            input_value={"hook_event_name": "UserPromptSubmit", "prompt": anthropic},
            expect_code=0,
            expect_json=((), {}),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-before-prompt-allow",
            harness="cursor",
            surface="prompt",
            argv=[core, "cursor-hook", "--event", "beforeSubmitPrompt"],
            input_value={"prompt": f"Use {anthropic} for the next request"},
            expect_code=0,
            expect_json=(("continue",), True),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-pretooluse-deny",
            harness="cursor",
            surface="tool-input",
            argv=[core, "cursor-hook", "--event", "preToolUse"],
            input_value={"tool_name": "Shell", "tool_input": {"command": f"echo {openai}"}},
            expect_code=0,
            expect_json=(("permission",), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-posttooluse-deny",
            harness="cursor",
            surface="tool-output",
            argv=[core, "cursor-hook", "--event", "postToolUse"],
            input_value={"tool_name": "Shell", "tool_response": {"stdout": github}},
            expect_code=0,
            expect_json=(("permission",), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-before-shell-deny",
            harness="cursor",
            surface="bash-command",
            argv=[core, "cursor-hook", "--event", "beforeShellExecution"],
            input_value={"command": f"echo {openai}"},
            expect_code=0,
            expect_json=(("permission",), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-before-mcp-deny",
            harness="cursor",
            surface="outbound",
            argv=[core, "cursor-hook", "--event", "beforeMCPExecution"],
            input_value={"server_name": "github", "tool_name": "create_issue", "arguments": {"body": github}},
            expect_code=0,
            expect_json=(("permission",), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-before-read-deny",
            harness="cursor",
            surface="file-path",
            argv=[core, "cursor-hook", "--event", "beforeReadFile"],
            input_value={"path": "/tmp/project/.env"},
            expect_code=0,
            expect_json=(("permission",), "deny"),
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-after-agent-response-no-leak",
            harness="cursor",
            surface="tool-output",
            argv=[core, "cursor-hook", "--event", "afterAgentResponse"],
            input_value={"text": f"Completed with token {github}"},
            expect_code=0,
            canaries=canaries,
        ),
        _proof_case(
            name="cursor-after-agent-thought-no-leak",
            harness="cursor",
            surface="tool-output",
            argv=[core, "cursor-hook", "--event", "afterAgentThought"],
            input_value={"text": f"Need to use {openai}"},
            expect_code=0,
            canaries=canaries,
        ),
    ]

    coverage = active_harness_coverage()
    cursor_covered = coverage["cursor"].get("coverage") == "covered"
    cursor_status = cursor_installation_status()
    cases.append(
        {
            "name": "cursor-hooks-configured",
            "harness": "cursor",
            "surface": "prompt/pre/post/shell/mcp/read/file/agent-output",
            "ok": cursor_covered or not cursor_status["available"],
            "exit_code": None,
            "checks": {
                "configured_when_available": cursor_covered,
                "harness_available": bool(cursor_status["available"]),
                "ide_app_available": bool(cursor_status["ide_app_available"]),
                "bundled_cli_available": bool(cursor_status["bundled_cli_available"]),
                "agent_cli_available": bool(cursor_status["agent_cli_available"]),
            },
            "duration_ms": 0,
        }
    )

    failed = [case for case in cases if not case.get("ok")]
    result = {
        "ok": not failed,
        "proof_level": "adapter-contract",
        "case_count": len(cases),
        "failed": len(failed),
        "harnesses": sorted({str(case["harness"]) for case in cases}),
        "cases": cases,
        "limits": [
            "This proves installed ASG adapter commands and generated Cursor config semantics.",
            "It does not prove that each agent runtime fired every configured hook event in an interactive session.",
        ],
    }
    emit(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if result["ok"] else 1


def cmd_exec(args: argparse.Namespace) -> int:
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        emit("asg exec: missing command", file=sys.stderr)
        return 2

    command_text = shlex.join(argv)
    findings = scan_text(command_text, surface="bash-command", threshold=args.threshold)
    if findings:
        emit(reason_for(findings, prefix="Blocked command"), file=sys.stderr)
        return 2

    timeout = args.timeout if args.timeout > 0 else None
    try:
        proc = subprocess.run(  # nosec B603 - asg-run is explicitly an execution wrapper and never uses shell=True.
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        emit("asg exec: command timed out; output omitted", file=sys.stderr)
        return 124
    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    stderr_text = proc.stderr.decode("utf-8", errors="replace")
    redacted_stdout, _ = redact_text(stdout_text, surface="exec-stdout", threshold=args.threshold)
    redacted_stderr, _ = redact_text(stderr_text, surface="exec-stderr", threshold=args.threshold)
    sys.stdout.write(redacted_stdout)
    sys.stderr.write(redacted_stderr)
    return proc.returncode


def codex_hook(args: argparse.Namespace) -> int:
    payload = load_json_stdin()
    event = str(payload.get("hook_event_name") or args.event or "")
    record_hook_observation("codex", event)
    tool_input = payload.get("tool_input")
    tool_response = payload.get("tool_response")

    if event in {"PreToolUse", "PermissionRequest"}:
        findings = scan_json_strings(tool_input, surface=f"codex:{event}", path="", threshold=args.threshold)
        if not findings:
            emit(json.dumps({}))
            return 0
        if event == "PermissionRequest":
            emit(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PermissionRequest",
                            "decision": {
                                "behavior": "deny",
                                "message": reason_for(findings),
                            },
                        }
                    }
                )
            )
            return 0
        emit(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason_for(findings),
                    }
                }
            )
        )
        return 0

    if event == "PostToolUse":
        findings = scan_json_strings(tool_response, surface="codex:PostToolUse", path="", threshold=args.threshold)
        if findings:
            emit(json.dumps({"decision": "block", "reason": reason_for(findings, prefix="Blocked tool result")}))
            return 0
        emit(json.dumps({}))
        return 0

    if event == "UserPromptSubmit":
        emit(json.dumps({}))
        return 0

    emit(json.dumps({}))
    return 0


def cursor_hook(args: argparse.Namespace) -> int:
    payload = load_json_stdin()
    event = str(payload.get("hook_event_name") or payload.get("event") or args.event or "")
    record_hook_observation("cursor", event)
    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
    tool_input = payload.get("tool_input") or payload.get("args") or payload.get("input") or {}
    tool_output = payload.get("tool_response") or payload.get("output") or payload.get("result") or {}

    if event in {"beforeSubmitPrompt", "preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"}:
        if event == "beforeSubmitPrompt":
            emit(json.dumps({"continue": True}))
            return 0
        elif event == "beforeShellExecution":
            target: Any = payload.get("command") or payload.get("shell_command") or tool_input
            surface = "bash-command"
        elif event == "beforeMCPExecution":
            target = (
                payload.get("arguments")
                or payload.get("args")
                or payload.get("params")
                or payload.get("tool_input")
                or payload.get("input")
                or payload
            )
            surface = "outbound"
        elif event == "beforeReadFile":
            target = payload.get("path") or payload.get("file_path") or payload.get("file") or tool_input
            surface = "file-path"
        else:
            target = tool_input
            surface = "tool-input"

        findings = (
            scan_text(str(target), surface=surface, threshold=args.threshold)
            if isinstance(target, str)
            else scan_json_strings(target, surface=surface, path="", threshold=args.threshold)
        )
        if findings:
            kinds = ", ".join(sorted({finding.kind for finding in findings}))
            message = "Blocked by Agent Secret Guard. Content omitted."
            agent_message = f"Blocked {tool_name or event}: potential secret categories detected ({kinds}). Content omitted."
            if event == "beforeSubmitPrompt":
                emit(json.dumps({"continue": False, "user_message": message, "agent_message": agent_message}, sort_keys=True))
            else:
                emit(
                    json.dumps(
                        {
                            "permission": "deny",
                            "user_message": message,
                            "agent_message": agent_message,
                        },
                        sort_keys=True,
                    )
                )
            return 0
        if event == "beforeSubmitPrompt":
            emit(json.dumps({"continue": True}))
        else:
            emit(json.dumps({"permission": "allow"}))
        return 0

    if event in {"postToolUse", "afterShellExecution", "afterMCPExecution", "afterFileEdit", "afterAgentResponse", "afterAgentThought"}:
        if event == "afterFileEdit":
            target = payload.get("content") or payload.get("edits") or tool_output
        elif event in {"afterAgentResponse", "afterAgentThought"}:
            target = payload.get("text") or payload.get("message") or payload.get("content") or tool_output
        else:
            target = tool_output
        findings = (
            scan_text(str(target), surface="tool-output", threshold=args.threshold)
            if isinstance(target, str)
            else scan_json_strings(target, surface="tool-output", path="", threshold=args.threshold)
        )
        if event in {"afterAgentResponse", "afterAgentThought"}:
            emit(json.dumps({}))
            return 0
        if findings:
            kinds = ", ".join(sorted({finding.kind for finding in findings}))
            emit(
                json.dumps(
                    {
                        "permission": "deny",
                        "user_message": "Blocked by Agent Secret Guard. Tool output contained potential secret material.",
                        "agent_message": f"Blocked {tool_name or event} output: potential secret categories detected ({kinds}). Content omitted.",
                    },
                    sort_keys=True,
                )
            )
            return 0
        emit(json.dumps({}))
        return 0

    emit(json.dumps({}))
    return 0


def claude_pre(args: argparse.Namespace) -> int:
    payload = load_json_stdin()
    record_hook_observation("claude", "PreToolUse")
    tool_name = str(payload.get("tool_name") or "unknown")
    tool_input = payload.get("tool_input") or {}
    path = ""
    if isinstance(tool_input, dict):
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")

    if args.surface == "bash-command" and isinstance(tool_input, dict):
        scan_target = str(tool_input.get("command") or "")
    elif args.surface == "url" and isinstance(tool_input, dict):
        scan_target = str(tool_input.get("url") or json.dumps(tool_input, sort_keys=True))
    else:
        scan_target = json.dumps(tool_input, sort_keys=True)

    findings = scan_text(scan_target, surface=args.surface, path=path, threshold=args.threshold)
    if findings:
        kinds = ", ".join(sorted({finding.kind for finding in findings}))
        emit(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"Blocked {tool_name}: potential secret categories detected "
                            f"({kinds}). Content omitted to avoid logging secrets."
                        ),
                    }
                }
            )
        )
        return 0

    emit(json.dumps({"continue": True}))
    return 0


def claude_post(args: argparse.Namespace) -> int:
    payload = load_json_stdin()
    record_hook_observation("claude", "PostToolUse")
    tool_name = str(payload.get("tool_name") or "unknown")
    tool_input = payload.get("tool_input") or {}
    path = ""
    if isinstance(tool_input, dict):
        path = str(tool_input.get("file_path") or tool_input.get("path") or "")

    response = payload.get("tool_response")
    redacted_response, findings = redact_json_strings(response, surface=f"claude-post:{tool_name}", path=path, threshold=args.threshold)
    if not findings:
        emit(json.dumps({"continue": True}))
        return 0

    categories = "\n".join(f"  - {kind}" for kind in sorted({finding.kind for finding in findings}))
    emit(
        json.dumps(
            {
                "continue": True,
                "suppressOutput": True,
                "systemMessage": f"REDACTED {len(findings)} potential secret(s) from {tool_name} output",
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": redacted_response,
                    "additionalContext": (
                        "SECRET REDACTION APPLIED\n\n"
                        "Detected and redacted categories:\n"
                        f"{categories}\n\n"
                        "The original value was omitted. Refer to secrets by location, not value."
                    ),
                },
            }
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Portable local secret detector for agent harnesses.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan stdin and emit secret findings as JSON")
    scan.add_argument("--surface", default="text")
    scan.add_argument("--path", default="")
    scan.add_argument("--threshold", type=float, default=None)
    scan.add_argument("--include-pii", action="store_true")
    scan.add_argument("--fail-on-detect", action="store_true")
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--fingerprints", action="store_true", help="include keyed fingerprints, never matched values")
    scan.add_argument("--baseline", default="", help="suppress findings whose keyed fingerprints are in this baseline")
    scan.set_defaults(func=cmd_scan)

    redact = sub.add_parser("redact", help="redact secrets from stdin")
    redact.add_argument("--surface", default="text")
    redact.add_argument("--path", default="")
    redact.add_argument("--threshold", type=float, default=DEFAULT_REDACT_THRESHOLD)
    redact.add_argument("--include-pii", action="store_true")
    redact.add_argument("--json", action="store_true")
    redact.set_defaults(func=cmd_redact)

    json_block = sub.add_parser("json-block", help="scan all JSON string values and exit 2 on detection")
    json_block.add_argument("--surface", default="tool-input")
    json_block.add_argument("--path", default="")
    json_block.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    json_block.add_argument("--quiet", action="store_true")
    json_block.set_defaults(func=cmd_json_block)

    json_redact = sub.add_parser("json-redact", help="redact all JSON string values and emit redacted JSON")
    json_redact.add_argument("--surface", default="tool-output")
    json_redact.add_argument("--path", default="")
    json_redact.add_argument("--threshold", type=float, default=DEFAULT_REDACT_THRESHOLD)
    json_redact.set_defaults(func=cmd_json_redact)

    baseline = sub.add_parser("baseline-create", help="create a reviewed baseline from stdin without emitting matched values")
    baseline.add_argument("--surface", default="text")
    baseline.add_argument("--path", default="")
    baseline.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    baseline.add_argument("--include-pii", action="store_true")
    baseline.set_defaults(func=cmd_baseline_create)

    doctor = sub.add_parser("doctor", help="check local install and optional scanner availability")
    doctor.set_defaults(func=cmd_doctor)

    prove = sub.add_parser("prove", help="exercise installed adapters with synthetic canaries without emitting canary values")
    prove.add_argument("--pretty", action="store_true")
    prove.set_defaults(func=cmd_prove)

    eval_parser = sub.add_parser("eval", help="run the no-leak eval corpus and emit metrics")
    eval_parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    eval_parser.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    eval_parser.add_argument("--quiet", action="store_true")
    eval_parser.set_defaults(func=cmd_eval)

    external = sub.add_parser("external-scan", help="run installed third-party scanners and sanitize their reports")
    external.add_argument("--scanner", action="append", choices=["all", "gitleaks", "trufflehog", "detect-secrets"], default=["all"])
    external.add_argument("--timeout", type=int, default=30)
    external.add_argument("--fail-on-detect", action="store_true")
    external.set_defaults(func=cmd_external_scan)

    external_eval = sub.add_parser("external-eval", help="compare ASG corpus cases against installed external scanners")
    external_eval.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    external_eval.add_argument("--scanner", action="append", choices=["all", "gitleaks", "trufflehog", "detect-secrets"], default=["all"])
    external_eval.add_argument("--timeout", type=int, default=30)
    external_eval.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    external_eval.add_argument("--format", choices=["summary", "full"], default="summary")
    external_eval.add_argument("--case-limit", type=int, default=20)
    external_eval.add_argument("--requirement-limit", type=int, default=12)
    external_eval.add_argument("--quiet", action="store_true")
    external_eval.set_defaults(func=cmd_external_eval)

    serve = sub.add_parser("serve", help=argparse.SUPPRESS)
    serve.add_argument("--socket", default="")
    serve.add_argument("--pid-file", default="")
    serve.set_defaults(func=cmd_serve)

    daemon_start = sub.add_parser("daemon-start", help="start the local Unix-socket daemon for low-latency hooks")
    daemon_start.add_argument("--socket", default="")
    daemon_start.add_argument("--pid-file", default="")
    daemon_start.add_argument("--timeout", type=float, default=2.0)
    daemon_start.set_defaults(func=cmd_daemon_start)

    daemon_status = sub.add_parser("daemon-status", help="check whether the local low-latency daemon is running")
    daemon_status.add_argument("--socket", default="")
    daemon_status.add_argument("--pid-file", default="")
    daemon_status.set_defaults(func=cmd_daemon_status)

    daemon_stop = sub.add_parser("daemon-stop", help="stop the local low-latency daemon")
    daemon_stop.add_argument("--socket", default="")
    daemon_stop.add_argument("--pid-file", default="")
    daemon_stop.add_argument("--timeout", type=float, default=2.0)
    daemon_stop.set_defaults(func=cmd_daemon_stop)

    exec_parser = sub.add_parser("exec", help="run a command with pre-scan and redacted stdout/stderr")
    exec_parser.add_argument("--threshold", type=float, default=DEFAULT_REDACT_THRESHOLD)
    exec_parser.add_argument("--timeout", type=int, default=0, help="optional child process timeout in seconds; 0 disables timeout")
    exec_parser.add_argument("argv", nargs=argparse.REMAINDER)
    exec_parser.set_defaults(func=cmd_exec)

    codex = sub.add_parser("codex-hook", help="Codex hook adapter")
    codex.add_argument("--event", default="")
    codex.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    codex.set_defaults(func=codex_hook)

    cursor = sub.add_parser("cursor-hook", help="Cursor hook adapter")
    cursor.add_argument("--event", default="")
    cursor.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    cursor.set_defaults(func=cursor_hook)

    pre = sub.add_parser("claude-pre", help="Claude PreToolUse adapter")
    pre.add_argument("--surface", default="outbound", choices=["bash-command", "file-path", "outbound", "url", "text"])
    pre.add_argument("--threshold", type=float, default=DEFAULT_BLOCK_THRESHOLD)
    pre.set_defaults(func=claude_pre)

    post = sub.add_parser("claude-post", help="Claude PostToolUse adapter")
    post.add_argument("--threshold", type=float, default=DEFAULT_REDACT_THRESHOLD)
    post.set_defaults(func=claude_post)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
