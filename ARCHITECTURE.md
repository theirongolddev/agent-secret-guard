# Agent Secret Guard — Technical Architecture Report

> Generated 2026-06-03. References are `file:line`. Treat as orientation, not a spec.

## Executive Summary

`agent-secret-guard` (ASG) is a **portable, dependency-free secret detector and
redactor for AI agent harnesses** (Claude Code, Codex, Cursor, and any generic
harness). A single ~6,350-line Python engine does all detection; everything else
is thin adapters that route a harness's hook events through it without ever
echoing the original payload. A small compiled C client (`asg-fast`) front-runs a
resident Unix-socket daemon for low-latency hook calls and falls back to the CLI.

- **Engine:** `src/agent_secret_guard.py` (6,351 lines), stdlib-only Python 3.
- **Fast client:** `src/asg_fast.c` (721 lines), C, talks to the daemon over a
  `0600` Unix socket, falls back to the Python CLI on miss/timeout.
- **Detectors:** 107 provider `RegexDetector`s + 54 `CommandRule`s, plus
  structural/entropy/encoding/URL/header/PII passes.
- **Test+eval:** `bin/agent-secret-guard-tests` (53 tests) + `share/eval-corpus.json`
  (538 cases, 101 requirement buckets). Stated baseline: precision/recall 1.000.
- **Core invariant:** findings and logs **never contain the matched secret value** —
  only `kind`, `confidence`, `span`, `reason`.

---

## Entry Points

| Entry | Location | Purpose |
|-------|----------|---------|
| CLI `main()` | `src/agent_secret_guard.py:6344` | Parse argv, dispatch to `args.func` |
| `build_parser()` | `src/agent_secret_guard.py:6221` | Defines all 18 subcommands |
| `agent-secret-guard` launcher | `bin/agent-secret-guard:1` | `exec python3 ~/.local/lib/agent_secret_guard.py "$@"` |
| `asg-fast` C client `main` | `src/asg_fast.c` | Daemon-or-fallback dispatch for hot-path commands |
| Installer | `bin/agent-secret-guard-install:1` → `tools/asg_package.py` | Build manifest, merge hook configs |
| `install.py` / `uninstall.py` | repo root | Thin wrappers over `tools.asg_package.cmd_install/cmd_uninstall` |

### CLI subcommands (`build_parser`, `:6221`)

`scan`, `redact`, `json-block`, `json-redact`, `baseline-create`, `doctor`,
`prove`, `eval`, `external-scan`, `external-eval`, `serve` (hidden daemon),
`daemon-start/-status/-stop`, `exec`, and the harness adapters `codex-hook`,
`cursor-hook`, `claude-pre`, `claude-post`.

### Harness adapter scripts (`bin/`)

All adapters source `bin/asg-hook-lib` (fail-open/fail-closed helpers +
payload-free telemetry, `:1-123`), call `asg-fast`, and **fail closed on
high-risk surfaces** if the engine is unavailable. `{{ASG_HOME}}` is templated at
install time.

- Generic: `asg-json-block` (`:1`, exit 2 on detect), `asg-json-redact`,
  `asg-stream-redact`, `asg-bash-command-block`, `asg-vcs-diff-block`, `asg-run`.
- Claude compat: `secret-scan` (PostToolUse redact), `secret-filter`,
  `secret-push-guard`, `secret-url-guard`, `secret-mcp-guard`, `infisical-guard`,
  `cmd-leak-guard`, `file-leak-guard`, `secret-wrap`.
- Codex: `asg-codex-hook` (`:1`).
- Cursor: `asg-cursor-*` (before/after prompt, shell, mcp, read, file-edit,
  agent-response/-thought; pre/post tool use).

---

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Finding` | `src/agent_secret_guard.py:177` (frozen dataclass) | `kind`, `confidence`, `start`, `end`, `reason` — **no value field by design** |
| `RegexDetector` | `:194` | One provider token pattern + validator + confidence + hint |
| `CommandRule` | `:204` | A shell-command pattern documented to emit secrets (deny policy) |
| `PathRule` | `:213` | File-path leak policy (e.g. reading `.env`) |
| `StaticString` | `:222` | A literal extracted from source for joined-literal dataflow checks |
| `AgentSecretGuardServer/Handler` | `:4661`, `:4670` | Threaded `UnixStreamServer` daemon |

Detector tables: `TOKEN_DETECTORS` (`:1147`, 107 entries),
`TOKEN_DETECTOR_HINTS` (`:1303`), command rules feed `add_command_policy_findings`
(`:2018`, 54 `CommandRule`s).

---

## Data Flow

```
stdin / hook JSON
      │
      ▼
adapter script (bin/asg-*)  ──fail-closed if engine down──▶ deny/redact stub
      │  (asg-fast over Unix socket, else CLI fallback)
      ▼
cmd_scan/redact/json-* (:3599+)
      │
      ▼
scan_text()  (:3440)  ── orchestrates ~20 passes ──┐
   command-policy · file-path · structural · regex │
   · composite · auth/url · assignment · joined-    │
   literal · display-normalize · softwrap · chunked │
   · entropy · pii · escaped/html/percent/hex/blob  │
      │                                             │
      ▼                                             │
dedupe_findings(threshold) (:3197) ◀───────────────┘
      │
      ├─ scan:   JSON findings (value-free) ; exit 2 if --fail-on-detect ≥ 0.8
      └─ redact: apply_redactions() (:3482) → "[REDACTED:KIND]" markers (idempotent)
```

`scan_text` (`:3440`) is the heart: it appends to a `findings` list through
~20 specialized `add_*` passes, short-circuits on text `< 4` chars, strips
env-template listing spans, then dedupes. JSON variants
(`scan_json_strings`/`redact_json_strings`, `:3553`/`:3584`) walk JSON recursively
and tag each finding with its JSON path.

**Threshold policy** (intentionally split, `:45-46`): `scan` reports at **0.65**,
`redact` masks at 0.65, but `scan --fail-on-detect` hard-denies only at **0.8**.
Bare entropy-only findings stay visible but non-blocking so normal agent work
isn't interrupted.

---

## Detection Passes (selected)

| Pass | Location | What it catches |
|------|----------|-----------------|
| `add_regex_findings` | `:1629` | 107 provider token formats (validated) |
| `add_command_policy_findings` | `:2018` | Cloud CLI commands that print secrets (AWS STS/IAM/ECR, GCP, Azure) |
| `add_assignment_findings` | `:2211` | `KEY=value` / sensitive-key heuristics |
| `add_auth_and_url_findings` | `:2097` | Authorization/cookie headers, credential URLs |
| `add_high_entropy_findings` | `:2791` | Shannon-entropy blobs (warn-grade) |
| `add_joined_literal_findings` | `:2725` | Tokens reconstructed from concatenated source literals |
| `add_display_normalized_findings` | `:2939` | ANSI/Unicode-format-char obfuscation |
| `add_softwrap_findings` / `add_chunked_token_findings` | `:3000`/`:3030` | Tokens split across log lines / space-tab-colon chunks |
| `add_escaped/html/percent/hex/encoded_blob` | `:3085`–`:3164` | Decode-then-rescan (base64 UTF-8/UTF-16, `\x`, entities, `%`, hex) |

Validators (`valid_*`, `:742`–`:1040`) gate regex hits — JWT structure, Luhn,
GitHub fine-grained PAT, ~30 provider-specific shape checks — to keep false
positives near zero. Policy favors **structure over raw entropy**, and promotes
identifiers (e.g. an AWS access-key ID) only when they form a usable
credential **pair**.

---

## Daemon & Fast Client

- **Why:** per-hook process spawn is too slow. `asg-fast` (C) sends
  scan/redact/hook commands over a Unix socket to a resident daemon.
- **Protocol:** length-prefixed frames, `DAEMON_HEADER_STRUCT`/`DAEMON_RESPONSE_STRUCT`
  (`:57-58`); forwards **only** safe env overrides
  (`ASG_HOOK_TELEMETRY_PATH`, `ASG_DISABLE_HOOK_TELEMETRY`, `:60`), not the caller
  environment.
- **Socket:** `~/.local/run/agent-secret-guard/asg.sock`, dir `0700`, socket `0600`
  (`daemon_socket_path` `:4457`).
- **Fallback:** on stale socket / timeout / unsupported command, `asg-fast` runs
  the normal CLI; a circuit breaker (`ASG_DEFAULT_CIRCUIT_SECONDS`) avoids
  retrying a wedged daemon. Tests `:2746`/`:2817` exercise wedged/stale paths.
- **Perf budget (enforced, `test_performance_budget` `:2684`):** 1.66 MB benign
  scan < 200 ms; secret-bearing scan < 5 ms; daemon `asg-fast` benign < 20 ms avg.

---

## External Dependencies

| Dependency | Purpose | Critical? |
|------------|---------|-----------|
| Python 3 stdlib only | Engine — `re`, `base64`, `hmac`, `socketserver`, `ast`, `unicodedata`, … (`:14-42`) | Yes (no 3rd-party) |
| C compiler (`cc`/`clang`/`gcc`) | Builds `asg-fast` (`package_manifest.json:13`) | Optional (CLI works without) |
| Gitleaks / TruffleHog / detect-secrets | `external-scan`/`external-eval` comparison bridge (`:3966`–`:4040`) | Optional |

The external-scanner bridge captures their output internally and emits **only**
name/kind/location/verification/fingerprint — it drops Gitleaks `Secret`/`Match`
and TruffleHog raw values.

---

## Configuration

| Source | Location | Notes |
|--------|----------|-------|
| Constants | `:45-79` | `DEFAULT_REDACT_THRESHOLD=0.65`, `DEFAULT_BLOCK_THRESHOLD=0.8`, `MAX_DECODE_DEPTH=2` |
| Env vars | `asg_env` `:90` | `ASG_HOME`, `ASG_HOOK_TELEMETRY_PATH`, `ASG_DISABLE_HOOK_TELEMETRY`, socket/PID overrides |
| Corpus | `~/.local/share/agent-secret-guard/eval-corpus.json` | `DEFAULT_CORPUS` `:48` |
| Fingerprint key | `~/.local/share/.../fingerprint.key` | `:49`, HMAC-SHA256 key, secret material |
| Telemetry | `~/.local/state/.../hook-events.jsonl` | `:50`, payload-free (ts/harness/event only), 512 KB cap |
| Install manifest | `package_manifest.json` | Source→install map, file modes, C build spec |
| Generated hook snippets | `share/{claude-settings,codex,cursor}-hooks.json` | Mergeable via installer `--apply` |

`agent-secret-guard-install --apply` merges canonical ASG hooks into Claude/Codex/
Cursor user JSON, preserving non-ASG entries and making `0600` backups first.

---

## Test Infrastructure

| Type | Location | Count |
|------|----------|-------|
| Functional/regression tests | `bin/agent-secret-guard-tests` | 53 `test_*` functions |
| Eval corpus | `share/eval-corpus.json` | 538 cases, 101 requirement buckets |
| Self-metrics | `test_metrics` `:624`, `test_eval_corpus` `:2328` | Reports tp/fp/fn/tn, precision/recall/fpr |

**Stated baseline** (README `:309`): `METRICS tp=77 fp=0 fn=0 tn=58` and
`CORPUS tp=248 fp=0 fn=0 tn=273`, precision/recall 1.000.

Quality gates worth knowing (enforced by `cmd_eval`/`evaluate_corpus_quality`
`:3301`, test `:2415`): every requirement needs ≥2 cases, every positive
detection obligation needs a negative counterexample, and every regex detector
kind needs a positive case + literal hint (≥3 chars) or structural prefilter.

Non-leak tests (`test_redaction_no_leaks` `:777`,
`test_external_scanner_parsers_no_leak` `:2588`,
`test_redaction_output_is_idempotently_safe_to_rescan` `:900`) guard the central
invariant: no path emits the original secret, and redaction markers don't become
fresh findings on rescan.

---

## Notes & Gotchas

- **Dogfooding is live.** This repo runs ASG as a Claude PostToolUse hook — during
  this exploration a PEM-header regex literal in grep output was auto-redacted to
  `[REDACTED:PRIVATE_KEY_BLOCK]`. Expect tool output to be scrubbed.
- **Fail-closed semantics differ by surface** (`asg-hook-lib:76-123`): PreToolUse /
  shell / VCS / MCP block when the engine is down; prompt-submit and Cursor
  `afterAgent*` events are advisory and fail **open**.
- **Codex hook wiring caveat** (README `:211`): keep the hook pointed at the
  `asg-codex-hook` wrapper, not `asg-fast codex-hook` directly — Codex may treat
  the whole string as the executable path.
- **Provider additions are source-backed.** Every detector traces to public
  provider docs / mainstream scanner coverage (README `:326`–`:716`); narrow
  prefix rules are preferred over generic assignment rules.
- **VCS:** repo is `jj`-managed (`.jj/` present, colocated `.git/`). An autonomous
  multi-pass skill-loop has been committing here (see `.skill-loop-progress.md`);
  uncommitted changes currently sit in `src/agent_secret_guard.py` and
  `bin/agent-secret-guard-tests`.
- **Known-issue log:** `bugs/` holds dated false-positive/false-negative writeups
  (env-var refs, git-remote verbose output, committed `settings.json` reads).
```
