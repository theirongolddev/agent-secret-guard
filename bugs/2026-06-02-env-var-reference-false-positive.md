# Agent Secret Guard (ASG) Regression Report

> Filed 2026-06-02 from a Claude Code session (repo: `/Users/tayloreernisse/harvest21`).
> ASG repeatedly blocked/redacted **secret-by-reference** shell, halting a
> read-only CI-log diagnostic. Multiple distinct false positives, same root cause:
> the detector treats a _reference to_ a secret (a `$VAR`, or a `--plain` fetch
> piped into a variable) as if it were the secret _value_.

> **Meta-evidence:** this file was itself redacted by ASG on write. The
> `[REDACTED:OBFUSCATED_SECRET_LITERAL]` and `[REDACTED:SENSITIVE_ASSIGNMENT]`
> markers below are ASG flagging the (non-secret) reproduction snippets in a bug
> report _about_ ASG over-flagging — none of those snippets contained a credential.
> Where a snippet is redacted, the surrounding prose restates it in
> redaction-proof form.

## Classification

**False positive:** non-secret text (a shell environment-variable _reference_) was
both redacted (`OBFUSCATED_SECRET_LITERAL`) and blocked.

## Surface

Two surfaces, same root cause:

- `bash-command` — PreToolUse Bash via `cmd-leak-guard` **blocked** the call.
- `tool-output` / `file-path` — PostToolUse Write/Read **redacted** the span as
  `OBFUSCATED_SECRET_LITERAL`.

## Harness

Claude

## Exact Reproduction Text

None of the following lines contain a secret **value**. The first is a pure
variable _reference_; this is the canonical safe way to pass a credential to a
subprocess without the value ever appearing in the command text.

```text
curl -s -H "Circle-Token: $CIRCLECI_API_TOKEN" https://circleci.com/api/v2/workflow/abc123/job
```

Redaction-proof restatement of the _only_ span that matters (in case the line
above is itself redacted in this file): an HTTP auth header whose **value
position is a POSIX variable reference** — the characters dollar-sign, then
`CIRCLECI_API_TOKEN`. There is no credential on the line, only the name of one.

Second, related pattern, blocked on the `bash-command` surface — the "fetch a
secret into a variable, never print it" idiom that the user's own security rules
prescribe (e.g. `LEN=$(infisical secrets get X --plain | wc -c)`):

```text
TOK=$(infisical secrets get CIRCLECI_API_TOKEN --env=dev --plain); curl -s -H "Circle-Token: $TOK" https://circleci.com/api/v2/...
```

The fetched value is used only in a request header — never echoed, logged, or
written to a file.

## Exact Command

```bash
printf '%s\n' 'curl -s -H "Circle-Token: $CIRCLECI_API_TOKEN" https://circleci.com/api/v2/workflow/abc123/job' | ~/.local/bin/asg-fast scan --surface bash-command --fingerprints | ~/.local/bin/asg-fast redact --surface tool-output
printf '%s\n' 'curl -s -H "Circle-Token: $CIRCLECI_API_TOKEN" https://circleci.com/api/v2/workflow/abc123/job' | ~/.local/bin/asg-fast redact --surface tool-output
```

## Actual Behavior

- Exit code: `cmd-leak-guard` blocked the Bash call (non-zero, exit 2); the
  PostToolUse Write/Read hook rewrote the span.
- Detector kind: `OBFUSCATED_SECRET_LITERAL`
- Confidence: not surfaced to the agent.
- Reason: "central Agent Secret Guard command policy detected potential secret
  exposure" (bash) / "Detected and redacted categories: OBFUSCATED_SECRET_LITERAL"
  (write/read).
- Flagged substring: the `-H "Circle-Token: $CIRCLECI_API_TOKEN" "https://..."`
  span was replaced with `[REDACTED:OBFUSCATED_SECRET_LITERAL]`.
- Both **blocked** (bash) and **redacted** (file write + read-back).
- **Discriminating evidence:** on the same written line, the adjacent literal
  `PROJ="circleci/8Kex3wAQ2X99HAcrbhTiPY/LvG8GSUmsuu6QJWYZCAasM"` was **not**
  flagged. So the trigger is specifically the `<auth-header>: $VAR` shape — not a
  high-entropy literal. The detector is keying on the auth-header context and
  then mis-classifying the variable reference that follows as the secret.

## Expected Behavior

- **Must not redact, must not block** the pure-reference case. `$NAME` /
  `${NAME}` in an auth-header value position is a _reference_, not a literal.
  Redacting it protects nothing (no value is present) while breaking the safe
  pattern and pushing agents toward worse ones (inlining the literal, or — as
  happened here — abandoning a legitimate read-only diagnostic).
- For the second case (`VAR=$(secret-fetch … --plain)` whose value is only used
  in a header or piped to a hash/`wc`), the guard **may warn but must not block**:
  the value is injected into a subprocess and never emitted to stdout, a
  transcript, or a file. This is exactly the idiom the user's security rules
  document as safe.

Why this text is not secret material:

```text
A detector named the match OBFUSCATED_SECRET_LITERAL, but there is no literal —
obfuscated or otherwise. The bytes are the *name* of an environment variable.
Treating "auth-header: $VAR" as a credential is a category error: it conflates a
reference with a value. The correct heuristic is the inverse — "$VAR" / "${VAR}"
in the value position is positive evidence the author is AVOIDING a literal
secret, and should LOWER suspicion, not raise it.
```

## Context

- Command output: fetching CircleCI job-step logs (API v2 + v1.1) to diagnose a
  failed `staging-verify` job; authenticating with `CIRCLECI_API_TOKEN` passed by
  env-var reference (and via `infisical run` injection).
- Agent harness: Claude Code.
- Repo/path: `/Users/tayloreernisse/harvest21`.
- Tool event: PreToolUse Bash (blocked) and PostToolUse Write/Read (redacted).
- Recent command: a shell script of `curl … | jq` calls against the CircleCI API,
  written to `/tmp` and intended to run under `infisical run -- bash <script>`.
- Impact: blocks an entire class of legitimate, read-only operations — any
  authenticated API call where the token is supplied by reference — i.e. exactly
  the secure pattern the guard should be _encouraging_.

## Fix Requirements For The Agent

Fix this Agent Secret Guard (ASG) regression. ASG is the local secret
blocking/redaction system implemented by `~/.local/lib/agent_secret_guard.py`
and exposed through `~/.local/bin/asg-fast`.

Do not weaken blocking globally. First add this report as a regression case in
`~/.local/share/agent-secret-guard/eval-corpus.json` (as a `must_not_flag` case),
then add or update a focused test in `~/.local/bin/agent-secret-guard-tests`,
then patch the narrowest detector / extraction / scoring logic so that a shell
variable reference (`$NAME`, `${NAME}`) in an auth-header or assignment value
position is exempt from literal-secret detection. Treat `$VAR`/`${VAR}` and
`$(secret-fetch … --plain)` command-substitution (when the result is not echoed)
as reference patterns, not literals.

Required verification:

```bash
~/.local/bin/agent-secret-guard-tests
~/.local/bin/asg-fast prove
~/.local/bin/asg-fast doctor
~/.local/bin/asg-fast external-eval
```

Finally rerun the exact reproduction command and report before/after behavior.

## Acceptance Criteria

- The exact reproduction behaves as expected (the `$VAR` reference is neither
  blocked nor redacted; the `--plain`-into-variable idiom is at most warned).
- The new corpus case fails before the fix and passes after the fix.
- The focused regression test fails before the fix and passes after the fix.
- No real secret value is printed in command output, test failure output, docs,
  or session logs.
- `agent-secret-guard-tests`, `asg-fast prove`, `asg-fast doctor`, and
  `asg-fast external-eval` all pass.
- No broad threshold change is used unless the report proves the threshold itself
  is the broken contract. The fix must be the reference-vs-literal distinction,
  not a global sensitivity reduction.

## Note On A Genuine Adjacent Case (Do Not Over-Correct)

`cat .npmrc` / `cat ~/.npmrc` _can_ legitimately expose a literal registry token
and is reasonable to flag. The fix here is **not** to stop scanning file reads —
it is solely to stop classifying `$VAR` references and non-echoing `--plain`
command-substitution as literal secrets.
