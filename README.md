# Agent Secret Guard

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-stdlib_only-brightgreen">
  <img alt="Install target" src="https://img.shields.io/badge/install-%7E%2F.local-informational">
  <img alt="Fast client" src="https://img.shields.io/badge/asg--fast-1.1-informational">
</p>

Local secret scanning and redaction for coding-agent hooks, shell commands,
tool output, outbound payloads, and pre-push diffs.

```bash
tmp="$(mktemp -d)" && curl -fsSL https://github.com/theirongolddev/agent-secret-guard/archive/refs/heads/master.tar.gz -o "$tmp/asg.tgz" && tar -xzf "$tmp/asg.tgz" -C "$tmp" --strip-components=1 && python3 "$tmp/install.py"
```

## TL;DR

### The Problem

Agent sessions leak secrets through surfaces normal repo scanners do not see:
tool output, prompt logs, shell commands that print credentials, browser URLs,
MCP payloads, and generated diffs before they reach a remote.

### The Solution

Agent Secret Guard (ASG) installs local hook adapters plus a Python detector and
a small compiled fast client. It blocks high-risk tool/action payloads, redacts
post-tool output before it is persisted, and proves the installed hook contract
with synthetic canaries that are never printed.

### Why Use ASG?

| Capability | What it does | Concrete command |
|------------|--------------|------------------|
| Hook-native blocking | Blocks tool input, shell commands, URLs, outbound payloads, and VCS diffs | `agent-secret-guard scan --surface tool-input --fail-on-detect` |
| Safe redaction | Masks findings without logging matched values | `agent-secret-guard redact --surface tool-output` |
| Low-latency hooks | Uses `asg-fast` over a local Unix socket when the daemon is running | `agent-secret-guard daemon-start` |
| Install health proof | Checks active Claude, Codex, and Cursor hook coverage | `agent-secret-guard doctor` |
| Canary proof | Exercises adapters without emitting the canary values | `agent-secret-guard prove --pretty` |
| External scanner bridge | Runs optional scanners and sanitizes reports | `agent-secret-guard external-scan --scanner all` |

## Quick Example

```bash
# 1. Install from the current checkout.
python3 install.py --dry-run
python3 install.py

# 2. Start the fast local hook path.
~/.local/bin/agent-secret-guard daemon-start

# 3. Verify install and adapter coverage.
~/.local/bin/agent-secret-guard doctor
~/.local/bin/agent-secret-guard prove --pretty

# 4. Redact a generic tool-output stream.
printf '%s\n' 'tool output: SECRET_VALUE_OMITTED' |
  ~/.local/bin/agent-secret-guard redact --surface tool-output

# 5. Create a reviewed baseline without printing matched values.
printf '%s\n' 'reviewed sample text' |
  ~/.local/bin/agent-secret-guard baseline-create --surface text > asg-baseline.json
```

For a real positive-path detection test, use `agent-secret-guard prove`. It
generates synthetic canaries internally and reports only pass/fail metadata.

## Design Philosophy

| Principle | Meaning |
|-----------|---------|
| Agent surfaces first | ASG models agent-specific inputs and outputs, not just repository files. |
| Do not print the secret | Findings include kind, confidence, spans, reasons, and optional keyed fingerprints, not matched values. |
| Block actions, advise on prompts | Tool/action hooks enforce. Prompt handling stays advisory so false-positive reports and debugging text remain pasteable. |
| Structure beats entropy | Provider formats, command intent, paired credentials, and context suppress false positives before entropy rules escalate. |
| Local and dependency-light | The core scanner is Python standard library code; `asg-fast` is a tiny C client for hot hook paths. |

## Comparison

| Tool | Best at | ASG difference |
|------|---------|----------------|
| Gitleaks | Repository and commit-history secret scanning | ASG scans live agent surfaces such as tool payloads, shell commands, URLs, and hook JSON. |
| TruffleHog | Verified secret discovery across repos and SaaS integrations | ASG avoids emitting raw matches and focuses on local hook enforcement. |
| detect-secrets | Baseline-driven repo scanning | ASG baselines use keyed fingerprints and are designed for agent transcript safety. |
| Shell wrappers alone | Blocking a narrow command class | ASG combines command policy, provider detectors, redaction, JSON adapters, and harness coverage checks. |

ASG is not a replacement for repository scanners in CI. It covers a different
risk window: what agents are about to run, read, print, send, or push.

## Installation

### Option 1: Curl Source Tarball

```bash
tmp="$(mktemp -d)"
curl -fsSL https://github.com/theirongolddev/agent-secret-guard/archive/refs/heads/master.tar.gz -o "$tmp/asg.tgz"
tar -xzf "$tmp/asg.tgz" -C "$tmp" --strip-components=1
python3 "$tmp/install.py"
```

### Option 2: Git Checkout

```bash
git clone https://github.com/theirongolddev/agent-secret-guard.git
cd agent-secret-guard
python3 install.py --dry-run
python3 install.py
```

### Option 3: Existing Checkout or Packaged Source Tree

```bash
python3 tools/asg_package.py verify-layout
python3 tools/asg_package.py install --dry-run
python3 tools/asg_package.py install
```

### Optional Hook Merge

```bash
python3 install.py --apply-hooks
```

`--apply-hooks` merges ASG entries into supported user-level Claude, Codex, and
Cursor hook configs. It preserves non-ASG hook entries and writes chmod-600
backups before rewriting existing config files.

### Installed Files

| Path | Purpose |
|------|---------|
| `~/.local/bin/agent-secret-guard` | Main CLI wrapper |
| `~/.local/bin/asg-fast` | Compiled low-latency hook client |
| `~/.local/lib/agent_secret_guard.py` | Scanner engine |
| `~/.local/bin/agent-secret-guard-tests` | Regression suite |
| `~/.local/share/agent-secret-guard/README.md` | Adapter spec |
| `~/.local/share/agent-secret-guard/eval-corpus.json` | Local eval corpus |

## Quick Start

```bash
# Install.
python3 install.py

# Start the daemon for low-latency hook calls.
~/.local/bin/agent-secret-guard daemon-start

# Check local install health.
~/.local/bin/agent-secret-guard doctor

# Prove wrappers and generated hook snippets.
~/.local/bin/agent-secret-guard prove --pretty

# Run the bundled corpus.
~/.local/bin/agent-secret-guard eval --corpus ~/.local/share/agent-secret-guard/eval-corpus.json
```

## Command Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `scan` | Scan stdin and emit JSON findings | `printf '%s\n' 'sample text' | agent-secret-guard scan --surface text` |
| `redact` | Redact findings from stdin | `printf '%s\n' 'sample text' | agent-secret-guard redact --surface tool-output` |
| `json-block` | Scan all JSON string values and exit nonzero on detection | `agent-secret-guard json-block --surface tool-input < payload.json` |
| `json-redact` | Redact all JSON string values and emit JSON | `agent-secret-guard json-redact --surface tool-output < payload.json` |
| `baseline-create` | Create keyed fingerprints without matched values | `agent-secret-guard baseline-create --surface text < reviewed.txt > asg-baseline.json` |
| `doctor` | Check install, optional scanners, and hook coverage | `agent-secret-guard doctor` |
| `prove` | Exercise installed adapters with synthetic canaries | `agent-secret-guard prove --pretty` |
| `eval` | Run the local no-leak eval corpus | `agent-secret-guard eval --quiet` |
| `external-scan` | Run optional third-party scanners through a sanitized bridge | `agent-secret-guard external-scan --scanner all` |
| `external-eval` | Compare ASG corpus cases against optional scanners | `agent-secret-guard external-eval --format summary` |
| `daemon-start` | Start the local Unix-socket daemon | `agent-secret-guard daemon-start` |
| `daemon-status` | Check daemon state | `agent-secret-guard daemon-status` |
| `daemon-stop` | Stop the daemon | `agent-secret-guard daemon-stop` |
| `exec` | Run a child command with pre-scan and redacted output | `agent-secret-guard exec -- python3 --version` |
| `codex-hook` | Codex hook adapter | normally invoked by `asg-codex-hook` |
| `cursor-hook` | Cursor hook adapter | normally invoked by `asg-cursor-*` wrappers |
| `claude-pre` | Claude pre-tool adapter | normally invoked by compatibility scripts |
| `claude-post` | Claude post-tool adapter | normally invoked by compatibility scripts |

### Common Options

| Option | Commands | Meaning |
|--------|----------|---------|
| `--surface` | `scan`, `redact`, JSON commands, baseline | Selects policy context such as `text`, `tool-input`, `tool-output`, `bash-command`, `url`, or `vcs-diff`. |
| `--threshold` | scanner commands | Overrides the default confidence threshold. |
| `--quiet` | blocking/eval commands | Suppresses normal report output. |
| `--fail-on-detect` | `scan`, `external-scan` | Returns a failing status when findings meet the block threshold. |
| `--fingerprints` | `scan` | Includes keyed fingerprints, never raw matched values. |
| `--baseline` | `scan` | Suppresses findings whose keyed fingerprints are in a reviewed baseline. |

## Configuration

The installer generates hook snippets under
`~/.local/share/agent-secret-guard/` and can merge them into active configs with
`python3 install.py --apply-hooks`.

Minimal Codex hook shape:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "{{ASG_HOME}}/.local/bin/asg-codex-hook",
            "timeout": 2,
            "statusMessage": "Checking tool input for secrets"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "{{ASG_HOME}}/.local/bin/asg-codex-hook",
            "timeout": 2,
            "statusMessage": "Checking tool output for secrets"
          }
        ]
      }
    ]
  }
}
```

Runtime environment controls:

| Variable | Effect |
|----------|--------|
| `ASG_HOOK_TELEMETRY_PATH` | Overrides the payload-free hook observation log path. |
| `ASG_DISABLE_HOOK_TELEMETRY=1` | Disables payload-free hook observation logging. |

The observation log records timestamp, harness, and hook event only. It does not
record prompts, commands, URLs, file paths, tool input, tool output, or detected
values.

## Architecture

```text
Agent runtime
  |
  | hook JSON / shell payload / tool output / VCS diff
  v
Harness wrapper
  |  Claude: secret-* compatibility adapters
  |  Codex:  asg-codex-hook
  |  Cursor: asg-cursor-* wrappers
  v
asg-fast
  |  local Unix socket when daemon is healthy
  |  direct CLI fallback when unsupported or unavailable
  v
agent_secret_guard.py
  |  provider detectors
  |  command policy
  |  URL and JSON scanning
  |  entropy and context checks
  |  safe redaction and keyed fingerprints
  v
Decision
  |  block before action
  |  redact after action
  |  advise prompt path
  v
Agent transcript / tool result / push gate
```

## Troubleshooting

| Symptom | Check | Fix |
|---------|-------|-----|
| Hooks feel slow | `agent-secret-guard daemon-status` | Run `agent-secret-guard daemon-start`; `asg-fast` falls back to the Python CLI when the daemon is unavailable. |
| Hook command not found | `agent-secret-guard doctor` | Reinstall with `python3 install.py`; for active configs run `python3 install.py --apply-hooks`. |
| Codex hook fails before ASG runs | Inspect generated config shape, not command payloads | Keep Codex pointed at the no-argument `asg-codex-hook` wrapper, not a raw `asg-fast codex-hook` command string. |
| False positive in prompt text | Confirm whether it is prompt-only or tool/action payload | Prompt handling is advisory by design; enforce only on tool/action surfaces. |
| Scanner output contains no raw match | Expected behavior | Use `--fingerprints` or `baseline-create` for review workflows; ASG intentionally avoids printing matched values. |
| Third-party scanner missing | `agent-secret-guard external-scan --scanner all` | Install the optional scanner or rely on ASG's local corpus; missing scanners are reported as skipped. |

## Limitations

| Limitation | Why it matters |
|------------|----------------|
| No package-manager release is declared in this repo | Use source install until a real Homebrew, PyPI, or system package exists. |
| No license file is present | Treat reuse rights as undefined until a license is added. |
| Hook coverage is runtime-dependent | `doctor` proves local config shape and safe probes, not that every future agent runtime version fires every event. |
| Prompt hooks are advisory | This preserves debugging workflows and false-positive reports; enforcement belongs on tool/action surfaces. |
| External scanners are optional | ASG reports missing Gitleaks, TruffleHog, or detect-secrets as skipped. |
| Synthetic corpus is not exhaustive proof | The corpus is regression evidence, not a guarantee that every credential family is covered. |

## FAQ

### Is ASG a replacement for Gitleaks or TruffleHog?

No. Use repo scanners in CI. ASG covers local agent execution surfaces before
content becomes a commit, log, browser fetch, outbound payload, or persisted
transcript.

### Does ASG print detected secrets?

No. Normal findings omit matched values. Fingerprints are keyed HMAC values
using `~/.local/share/agent-secret-guard/fingerprint.key`.

### Why does ASG include a C client?

`asg-fast` keeps hook latency low by sending supported commands to the local
Unix-socket daemon. It falls back to the normal CLI when needed.

### Why are prompts advisory?

False-positive reports and debugging text often contain secret-shaped examples.
Blocking prompt submission makes the tool harder to fix. ASG enforces on
tool/action payloads where leakage risk becomes concrete.

### Can I run ASG without merging hooks?

Yes. Use direct commands such as `agent-secret-guard scan`,
`agent-secret-guard redact`, `asg-json-block`, and `asg-vcs-diff-block`. Hook
merge is for automatic runtime coverage.

### Where is the detailed adapter spec?

The installable adapter spec lives at `share/README.md` in this repo and is
installed to `~/.local/share/agent-secret-guard/README.md`.

## About Contributions

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Codex or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

No license file is present in this repository at the time this README was
written.
