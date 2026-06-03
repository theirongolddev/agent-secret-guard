# Agent Secret Guard (ASG) Regression Report

This report concerns Agent Secret Guard (ASG), the local secret blocking and
redaction system for Claude, Codex, Cursor, and generic agent harnesses.

Authoritative local paths:

- Engine: `~/.local/lib/agent_secret_guard.py`
- Fast CLI: `~/.local/bin/asg-fast`
- Test harness: `~/.local/bin/agent-secret-guard-tests`
- Eval corpus: `~/.local/share/agent-secret-guard/eval-corpus.json`
- Installer: `~/.local/bin/agent-secret-guard-install`
- Docs: `~/.local/share/agent-secret-guard/README.md`

## Classification

Choose one:

- False positive: non-secret text was redacted or blocked.
- False negative: secret-shaped text was allowed or leaked.
- Hook failure: Claude, Codex, or Cursor hook failed or returned invalid output.
- Performance regression: scanning slowed down enough to affect agent work.

## Surface

Choose the surface that matches the failing path:

- `tool-output`
- `tool-input`
- `vcs-diff`
- `bash-command`
- `prompt`
- `file-path`
- `url`
- `outbound`
- `text`

## Harness

Choose one:

- Claude
- Codex
- Cursor
- Generic CLI

## Exact Reproduction Text

Paste the smallest exact snippet that reproduces the issue.

Do not paste real secrets. For false negatives, use a synthetic canary with the
same prefix, separators, character classes, and length as the real value.

```text
PASTE_NON_SECRET_OR_SYNTHETIC_CANARY_SNIPPET_HERE
```

## Exact Command

Use the same surface as the failure. Keep output redacted in session logs.

```bash
printf '%s\n' 'PASTE_SNIPPET_HERE' | ~/.local/bin/asg-fast scan --surface tool-output --fingerprints | ~/.local/bin/asg-fast redact --surface tool-output
printf '%s\n' 'PASTE_SNIPPET_HERE' | ~/.local/bin/asg-fast redact --surface tool-output
```

For VCS/push regressions:

```bash
printf '%s\n' 'PASTE_DIFF_OR_COMMIT_TEXT_HERE' | ~/.local/bin/asg-fast scan --surface vcs-diff --fingerprints | ~/.local/bin/asg-fast redact --surface tool-output
```

## Actual Behavior

- Exit code:
- Detector kind:
- Confidence:
- Reason:
- Flagged substring:
- Was it blocked, redacted, or only reported?

## Expected Behavior

State the intended behavior precisely:

- Must not redact.
- Must not block, but may warn.
- Must block.
- Must redact output without leaking the original value.

Explain why:

```text
EXPLAIN_WHY_THIS_TEXT_IS_OR_IS_NOT_SECRET_MATERIAL
```

## Context

Where did this come from?

- Command output:
- Agent harness:
- Repo/path:
- Tool event:
- Recent command:
- Any relevant surrounding text:

## Fix Requirements For The Agent

Fix this Agent Secret Guard (ASG) regression. ASG is the local secret
blocking/redaction system implemented by `~/.local/lib/agent_secret_guard.py`
and exposed through `~/.local/bin/asg-fast`.

Do not weaken blocking globally. First add this report as a regression case in
`~/.local/share/agent-secret-guard/eval-corpus.json`, then add or update a
focused test in `~/.local/bin/agent-secret-guard-tests`, then patch the
narrowest detector, extraction, scoring, or hook-adapter logic.

Required verification:

```bash
~/.local/bin/agent-secret-guard-tests
~/.local/bin/asg-fast prove
~/.local/bin/asg-fast doctor
~/.local/bin/asg-fast external-eval
```

Finally rerun the exact reproduction command and report before/after behavior.

## Acceptance Criteria

- The exact reproduction behaves as expected.
- The new corpus case fails before the fix and passes after the fix.
- The focused regression test fails before the fix and passes after the fix.
- No real secret value is printed in command output, test failure output, docs,
  or session logs.
- `agent-secret-guard-tests`, `asg-fast prove`, `asg-fast doctor`, and
  `asg-fast external-eval` all pass.
- No broad threshold change is used unless the report proves the threshold
  itself is the broken contract.
