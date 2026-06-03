# Agent Secret Guard (ASG) Regression Report

This report concerns Agent Secret Guard (ASG), the local secret blocking and
redaction system for agent harnesses.

Authoritative local paths:

- Engine: `~/.local/lib/agent_secret_guard.py`
- Fast CLI: `~/.local/bin/asg-fast`
- Test harness: `~/.local/bin/agent-secret-guard-tests`
- Eval corpus: `~/.local/share/agent-secret-guard/eval-corpus.json`
- Installer: `~/.local/bin/agent-secret-guard-install`
- Docs: `~/.local/share/agent-secret-guard/README.md`
- Hook adapters: `~/.local/bin/cmd-leak-guard` (Bash PreToolUse),
  `~/.local/bin/file-leak-guard` (Read/file PreToolUse)

Reported: 2026-06-02 · Repo where encountered: `~/harvest21` · Harness: Claude Code

---

## Summary (two related false positives)

Two engine rules block **read-only introspection commands that agents must be
able to run without a human in the loop**. Neither command exposes a secret in
the cases that were blocked, and the engine already supports a strictly-better
response (redact output) than the one taken (block command).

| #   | Rule                 | Blocked command       | Why it's a false positive                                                                                                                                                 |
| --- | -------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A   | `git-remote-verbose` | `git remote -v`       | Block is too blunt; should **redact output** (a remote URL _may_ embed a token, but the command is essential and the leak is in the _output_, not the act of running it). |
| B   | `read-secret-path`   | `cat .infisical.json` | `.infisical.json` is **not secret-bearing** — it holds only project ID, workspace ID, and environment slugs, and is designed to be committed to the repo.                 |

Both are the same operational failure: an agent could not determine its own git
remote protocol or read a committed, non-secret project-config file, halting
legitimate CI/CD setup work.

## Classification

- **False positive: non-secret text was blocked.**

## Surface

- Case A: `bash-command`
- Case B: `bash-command` (via `cat`) **and** `file-path` (via the Read tool /
  `file-leak-guard`). The Read-tool path to `.infisical.json` is blocked by
  `file-leak-guard` with the same underlying `read-secret-path` rule.

## Harness

- Claude (Claude Code). Both `cmd-leak-guard` and `file-leak-guard` PreToolUse
  hooks reproduce the block.

## Exact Reproduction Text

These are the literal, non-secret commands that were blocked. No real secrets
are present in any of them.

```text
git remote -v
cat .infisical.json
```

For reference, the commands that scanned **clean** on their own (count 0) and
were only blocked as collateral when sharing a compound command line with the
two above:

```text
jj git remote list
git config --get-all credential.helper
infisical secrets --env=dev --domain=http://ai-server.tail093fcb.ts.net:8080 -o json | jq -r '.[].secretKey'
```

## Exact Command

The hook scans the literal command string, so a diagnostic command that _quotes_
the trigger text (`git remote -v`) is itself blocked. Reproduce by feeding the
snippet from a file via stdin redirect, so the invoking command line is clean:

```bash
mkdir -p /tmp/asg-repro
printf '%s\n' 'git remote -v' > /tmp/asg-repro/a.txt
printf '%s\n' 'cat .infisical.json' > /tmp/asg-repro/b.txt

~/.local/bin/asg-fast scan   --surface bash-command --fingerprints < /tmp/asg-repro/a.txt
~/.local/bin/asg-fast redact --surface bash-command               < /tmp/asg-repro/a.txt
~/.local/bin/asg-fast scan   --surface bash-command --fingerprints < /tmp/asg-repro/b.txt
```

## Actual Behavior

### Case A — `git remote -v`

- Exit code: `0` (scan succeeded; finding present)
- Detector kind: `LEAKY_COMMAND`
- Confidence: `0.91`
- Reason: `git remotes can embed credentials; rule=git-remote-verbose`
- Flagged substring: `git remote -v` (span 0–14)
- Disposition: **blocked** by `cmd-leak-guard` PreToolUse hook.
- Note: `asg-fast redact --surface bash-command` on the same input returns
  `[REDACTED:LEAKY_COMMAND]` — i.e. a redaction path already exists.

### Case B — `cat .infisical.json`

- Exit code: `0`
- Detector kind: `LEAKY_COMMAND`
- Confidence: `0.91`
- Reason: `reading known secret-bearing files is unsafe; rule=read-secret-path`
- Flagged substring: `cat .infisical.json` (span 0–20)
- Disposition: **blocked** by `cmd-leak-guard`; the equivalent Read-tool access
  to `.infisical.json` is **blocked** by `file-leak-guard`.

### Collateral (not themselves flagged)

`jj git remote list`, `git config --get-all credential.helper`, and the keys-only
`infisical … -o json | jq -r '.[].secretKey'` projection each return
`{"count": 0, "ok": true}` from `asg-fast scan`. They were blocked in practice
only because they appeared in the same compound command line as a Case A/B
snippet. No rule change is requested for these; they are listed so the fix's
regression test confirms they stay clean.

## Expected Behavior

### Case A — `git remote -v`

- **Must not block the command.** May **redact the output** if (and only if) a
  remote URL embeds userinfo/token (`https://<user>:<token>@host/…`).
- Rationale: `git remote -v` is a mandatory, high-frequency introspection
  command for any agent doing VCS/CI/CD work. The risk it guards against lives in
  the _output_ of the command (a credential-bearing URL), not in the act of
  running it. The engine already has a redaction surface (`tool-output`) and the
  redact path demonstrably works. Convert this rule from a `bash-command` **block**
  into a `tool-output` **redaction** (redact `://user:secret@` userinfo), leaving
  the command runnable. The overwhelmingly common cases — an SSH remote
  (`git@github.com:org/repo.git`) or a clean HTTPS remote with no embedded token —
  carry no secret at all and must pass untouched.

### Case B — `.infisical.json`

- **Must not block, and must not redact.** `.infisical.json` is non-secret
  project configuration.
- Rationale: the Infisical CLI writes `.infisical.json` to hold the workspace/
  project ID and environment slugs so the project can resolve which Infisical
  project it belongs to. It contains **no** secret values — secrets live only in
  the Infisical instance and are injected at runtime via `infisical run`. The file
  is intended to be committed. Remove `.infisical.json` from the
  `read-secret-path` deny list. (Keep genuinely secret-bearing paths such as
  `.env`, `.env.*`, private-key files, and any token-cache files.)

```text
Why this text is NOT secret material:
- `git remote -v` output is secret-bearing ONLY when a URL embeds inline
  userinfo; that is an output-redaction concern, not a reason to forbid the
  command. SSH and clean-HTTPS remotes — the norm — contain no secret.
- `.infisical.json` is a committed project-config manifest (project/workspace
  IDs + env slugs). It is the Infisical equivalent of a `package.json`-style
  pointer, not a credential store. Blocking reads of it breaks legitimate
  project introspection with zero security benefit.
```

## Context

- Command output: produced while setting up a GitHub App bot identity for the
  Harvest 21 CI/CD work — needed to determine the git remote protocol (SSH vs
  HTTPS, which decides the GitHub App credential-helper design) and to confirm
  Infisical project linkage.
- Agent harness: Claude Code, PreToolUse `cmd-leak-guard` / `file-leak-guard`.
- Repo/path: `~/harvest21` (jj-colocated git repo).
- Tool event: `Bash` (Cases A/B), `Read` (Case B file-path variant).
- Recent command: branch/remote introspection during agent-identity provisioning.
- Relevant surrounding text: the same blocks recur for any compound command line
  that includes `git remote -v`, because the hook matches the literal substring
  in the command string before the engine runs.

## Fix Requirements For The Agent

Fix this Agent Secret Guard (ASG) regression. ASG is the local secret
blocking/redaction system implemented by `~/.local/lib/agent_secret_guard.py`
and exposed through `~/.local/bin/asg-fast`.

Do not weaken blocking globally. First add both cases as regression entries in
`~/.local/share/agent-secret-guard/eval-corpus.json`, then add or update focused
tests in `~/.local/bin/agent-secret-guard-tests`, then patch the narrowest logic:

- **Case A (`git-remote-verbose`):** reclassify from a `bash-command` block to a
  `tool-output` redaction that strips `://<user>:<secret>@` userinfo from remote
  URLs. The command itself must be allowed to run. Add corpus cases for: SSH
  remote (no finding), clean HTTPS remote (no finding), and HTTPS remote with
  embedded token (output redacted, command still allowed).
- **Case B (`read-secret-path`):** remove `.infisical.json` from the
  secret-bearing path set used by both the engine and `file-leak-guard`. Add a
  corpus case asserting `.infisical.json` is allowed, and a paired case asserting
  `.env` / private-key paths remain blocked (so the deny list isn't over-trimmed).

Keep the narrowest possible change. Do not alter global thresholds.

Required verification:

```bash
~/.local/bin/agent-secret-guard-tests
~/.local/bin/asg-fast prove
~/.local/bin/asg-fast doctor
~/.local/bin/asg-fast external-eval
```

Finally rerun the exact reproduction commands (via the file-redirect form above
so the diagnostic isn't self-blocked) and report before/after behavior.

## Acceptance Criteria

- `git remote -v` is **allowed to run**; its output is redacted only when a
  remote URL embeds inline userinfo. SSH and clean-HTTPS remotes pass untouched.
- `cat .infisical.json` and the Read-tool access to `.infisical.json` are
  **allowed**.
- `.env`, `.env.*`, and private-key/token-cache paths remain **blocked**
  (deny list not over-trimmed).
- `jj git remote list`, `git config --get-all credential.helper`, and the
  keys-only `infisical … secretKey` projection remain clean.
- Each new corpus case fails before the fix and passes after.
- Each focused regression test fails before the fix and passes after.
- No real secret value is printed in command output, test output, docs, or
  session logs.
- `agent-secret-guard-tests`, `asg-fast prove`, `asg-fast doctor`, and
  `asg-fast external-eval` all pass.
- No broad threshold change is used.
