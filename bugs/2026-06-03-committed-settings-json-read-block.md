# Agent Secret Guard (ASG) Regression Report

> Filed 2026-06-03 from a Claude Code session (repo: `/Users/tayloreernisse/harvest21`).
> ASG's `file-leak-guard` blocked a **read** of a **git-tracked** `.claude/settings.json`
> as a "known secret-bearing path", halting legitimate project-hook configuration.

## Classification

**False positive:** a non-secret, version-controlled config file was blocked from
being read. `.claude/settings.json` is committed to git (it is the shared project
hook/permission config); by definition it cannot safely hold secrets — those live
in the gitignored `.claude/settings.local.json` or in env/Infisical. Blocking the
read of a committed config impedes a core, benign workflow (configuring a committed
PreToolUse hook) with no secret-exposure upside.

## Surface

`file-path` — PreToolUse Read via `file-leak-guard` **blocked** the call.

## Harness

Claude

## Exact Reproduction Text

No secret is involved. The blocked path is a git-tracked file:

```text
.claude/settings.json
```

Distinguishing facts:

- `git ls-files .claude/settings.json` → tracked (committed).
- `.gitignore` ignores only `.claude/settings.local.json*` (the secret-bearing
  variant), NOT `.claude/settings.json`.

So the policy is treating the **committed** settings file the same as the
**gitignored/global** ones. Only the latter can hold live secrets.

## Exact Command

```bash
# What the agent did (blocked):
#   Read tool on .claude/settings.json
# Equivalent path-policy check:
printf '%s\n' '.claude/settings.json' | ~/.local/bin/asg-fast scan --surface file-path --fingerprints
```

## Actual Behavior

- Exit: `file-leak-guard` blocked the Read (non-zero).
- Detector kind: file-path policy ("known secret-bearing path").
- Confidence: not surfaced.
- Reason: "central Agent Secret Guard file path policy detected a known
  secret-bearing path."
- Flagged path: `.claude/settings.json`.
- Was it blocked, redacted, or reported? **Blocked.**

## Expected Behavior

- **Must not block** reads of a **git-tracked** `.claude/settings.json`. A file
  under version control is, by team policy, non-secret; the agent needs to read it
  to merge a new committed hook without clobbering existing ones.
- **May still block/guard** `.claude/settings.local.json` (gitignored) and the
  global `~/.claude/settings.json` (outside any repo), which legitimately can carry
  tokens/env. The distinction is **git-tracked project settings vs. local/global
  settings**.

Why this is not secret material:

```text
.claude/settings.json is committed to the repository. If it held a secret, that
secret would already be in git history and shared with every collaborator — the
secret would be the bug, not the read. The team contract (mirrored by .gitignore)
puts secrets in .claude/settings.local.json, which IS gitignored. So a read of the
TRACKED settings.json exposes nothing; blocking it only breaks legitimate config.
```

## Context

- Command output: configuring a new committed PreToolUse(Bash) hook
  (`.claude/hooks/git-identity-guard.sh`) that forces agent GitHub actions through
  a bot identity. Needed to read `.claude/settings.json` to merge the hook entry
  alongside the repo's existing hooks without removing them.
- Agent harness: Claude Code.
- Repo/path: `/Users/tayloreernisse/harvest21`.
- Tool event: PreToolUse Read (blocked).
- Note: the same session also had `cat .claude/settings.json` blocked by
  `cmd-leak-guard` (LEAKY_COMMAND) — same root cause on the bash surface.

## Fix Requirements For The Agent

Fix this Agent Secret Guard (ASG) regression. ASG is the local secret
blocking/redaction system implemented by `~/.local/lib/agent_secret_guard.py`
and exposed through `~/.local/bin/asg-fast`.

Do not weaken blocking globally. First add this report as a regression case in
`~/.local/share/agent-secret-guard/eval-corpus.json` (a `must_not_block`
file-path case for a git-tracked `.claude/settings.json`, paired with a
`must_block`/guarded case for `.claude/settings.local.json` so the distinction is
tested both ways), then add or update a focused test in
`~/.local/bin/agent-secret-guard-tests`, then patch the narrowest file-path policy
logic so that a **git-tracked** `.claude/settings.json` is exempt while
`.claude/settings.local.json` and global `~/.claude/settings.json` remain guarded.

Required verification:

```bash
~/.local/bin/agent-secret-guard-tests
~/.local/bin/asg-fast prove
~/.local/bin/asg-fast doctor
~/.local/bin/asg-fast external-eval
```

Finally rerun the exact reproduction and report before/after behavior.

## Acceptance Criteria

- Reading a git-tracked `.claude/settings.json` is **not** blocked.
- `.claude/settings.local.json` and global `~/.claude/settings.json` remain
  guarded (the fix is the tracked-vs-local distinction, not a blanket allow).
- The new corpus cases fail before the fix and pass after.
- The focused regression test fails before the fix and passes after.
- No real secret value is printed anywhere.
- `agent-secret-guard-tests`, `asg-fast prove`, `asg-fast doctor`, and
  `asg-fast external-eval` all pass.
- No broad threshold change unless the report proves the threshold itself is the
  broken contract.
