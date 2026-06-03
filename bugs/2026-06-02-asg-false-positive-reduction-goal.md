# Goal: Reduce Agent Secret Guard False Positives With Robust TDD

Implement this goal:

Reduce Agent Secret Guard false positives without weakening protection against actual secret-value exposure. Use robust TDD: first add failing tests that reproduce each false positive, then implement the narrowest fix, then prove adjacent dangerous cases still fail.

## Scope

Work in:

- `{{ASG_HOME}}/.local/lib/agent_secret_guard.py`
- `{{ASG_HOME}}/.local/bin/agent-secret-guard-tests`
- `{{ASG_HOME}}/.local/share/agent-secret-guard/eval-corpus.json`
- ASG wrapper scripts only if required

Do not read `.env*` files. Do not print real secrets. Use only synthetic fixtures or reference-only examples.

## Required Policy Contract

1. Prompt hooks are advisory only.
   - Codex `UserPromptSubmit` must never block prompt content.
   - Cursor `beforeSubmitPrompt` must never block prompt content.
   - Prompt hook infra failure may warn/telemetry, but must allow.

2. Bash command hooks block value exposure, not safe references.
   - Allow `$TOKEN` / `${TOKEN}` in auth-header value positions.
   - Allow `TOKEN=$(infisical secrets get ... --plain)` when the value is only passed by reference to a subprocess header or safe sink.
   - Block `echo "$TOKEN"`, `printf "$TOKEN"`, env dumps, writing token references to files, and literal token values in command text.

3. Tool output redaction targets actual values.
   - Do not redact detector fixture names, false-positive bug reports, safe shell snippets, or CircleCI workflow/project identifiers.
   - Still redact/suppress real synthetic secret values.

4. Reconstruction heuristics must not treat safe shell references as obfuscated literals.
   - Skip joined/chunked reconstruction when spans contain `$VAR`, `${VAR}`, safe Infisical command substitution, or shell URL/header argument structure.
   - Do not globally lower thresholds.

5. ASG infrastructure failure behavior remains:
   - High-risk tool/action hooks fail closed with recovery instructions.
   - Prompt hooks allow.
   - Recovery message must mention `{{ASG_HOME}}/.local/bin/asg-recover`.
   - `doctor` must report unhealthy for recent high-risk fail-open/fail-closed telemetry or open daemon circuit.

## TDD Methodology

Use strict red/green/refactor.

1. Red phase:
   - Add focused unit tests and corpus cases before changing detector logic.
   - Run only the new focused tests first and confirm they fail for the intended reason.
   - Record the failing detector kind/rule name without printing matched secret-like text.
   - If a new test passes unexpectedly, stop and explain why the bug is already fixed or why the reproduction is wrong.

2. Green phase:
   - Implement the smallest code change that makes the new red tests pass.
   - Do not change global thresholds unless a test proves threshold semantics are the bug.
   - Re-run the focused tests until green.

3. Refactor phase:
   - Clean up helper naming and duplicate policy logic.
   - Re-run focused tests after refactor.
   - Then run broader verification.

4. Regression guard:
   - For every new negative case, add an adjacent positive case that must still block/redact.
   - Do not accept a fix unless both the negative and adjacent positive cases pass.

## Required Test Layers

Implement all relevant layers.

1. Pure detector unit tests
   - Call `asg-fast scan` / `agent_secret_guard.scan_text` on synthetic strings.
   - Validate `count`, `kinds`, and no source-value leakage.
   - Include bash-command, tool-output, file-path, and prompt surfaces.

2. Wrapper contract tests
   - Run actual wrappers with JSON payloads:
     - `{{ASG_HOME}}/.local/bin/asg-codex-hook`
     - `{{ASG_HOME}}/.local/bin/secret-wrap`
     - `{{ASG_HOME}}/.local/bin/secret-scan`
     - `{{ASG_HOME}}/.local/bin/cmd-leak-guard`
   - Validate harness-native responses:
     - Codex benign prompt returns `{}`.
     - Codex PreToolUse dangerous command returns deny.
     - Claude PreToolUse safe reference returns `continue: true`.
     - Claude PreToolUse dangerous command returns deny/exit 2 as appropriate.
     - Claude PostToolUse benign diagnostic output is not suppressed.
     - Claude PostToolUse synthetic secret output is suppressed/redacted.

3. Active hook config runtime probes
   - Use existing ASG runtime probe functions or installer dry-run probes.
   - Validate active Claude/Codex configs, not only generated snippets.
   - Confirm checked count > 0 and failures `[]`.

4. E2E-style hook smoke tests
   - Simulate realistic hook payloads through the actual installed wrapper commands.
   - Include the exact reported CircleCI diagnostic command as a Claude Bash PreToolUse payload.
   - Include the exact false-positive text as a Codex prompt payload.
   - Include benign PostToolUse diagnostic output with CircleCI IDs and `OUTPUT_URL_PRESENT`.
   - Include dangerous variants that must still block.
   - Assert each command completes under a strict timeout, e.g. 1-2 seconds.
   - Assert no synthetic canary appears in stdout/stderr.

5. Infra failure E2E tests
   - Use temp `HOME`, missing scanner path, temp telemetry path.
   - Confirm high-risk PreToolUse fails closed with `asg-recover` instruction.
   - Confirm prompt hooks allow with advisory recovery text.
   - Confirm telemetry is payload-free.
   - Confirm default real telemetry is not polluted by tests.

6. Corpus tests
   - Add negative `expected_kinds: []` cases for safe references.
   - Add positive cases for actual value exposure.
   - Run corpus quality enforcement and full eval.

## Must Add Negative Cases

These must not flag:

- `curl -H "Circle-Token: $TOKEN" ...`
- `curl -H "Authorization: Bearer $TOKEN" ...`
- `curl -H "Authorization: Bearer ${TOKEN}" ...`
- `TOKEN=$(infisical secrets get CIRCLECI_API_TOKEN --env=dev --plain); curl -H "Circle-Token: $TOKEN" ...`
- A multi-line CircleCI diagnostic command that fetches a token into `TOKEN`, uses `$TOKEN` only in headers, stores project/workflow/job IDs, and prints only job metadata.
- False-positive bug report prose containing detector names like `OBFUSCATED_SECRET_LITERAL`.
- Source/test text containing synthetic fixture construction.
- CircleCI project slugs, workflow IDs, job numbers, and `OUTPUT_URL_PRESENT`.

## Must Add Positive Cases

These must still block/redact:

- `echo "$CIRCLECI_API_TOKEN"`
- `printf "$TOKEN"` after `TOKEN=$(infisical ... --plain)`
- `cat ~/.npmrc`
- `env`, `printenv`, `set`, `declare -p`
- `curl -H "Circle-Token: literal-token-value"` using a synthetic literal token
- writing `$TOKEN` or a literal synthetic token to a file
- `infisical secrets get ... --plain` with no safe sink

## Implementation Requirements

1. Add explicit policy helpers:
   - `is_shell_variable_reference`
   - `safe_secret_reference_header`
   - `safe_infisical_plain_assignment`
   - `secret_reference_is_exfiltrated`

2. Patch only narrow logic:
   - `credible_assignment_value`
   - `credible_transport_secret_value`
   - `add_auth_and_url_findings`
   - `add_command_policy_findings`
   - reconstruction heuristics

3. Replace or constrain whole-script command-policy regexes:
   - Regexes must not cross unrelated newline-separated statements unless explicitly intended.
   - Prefer statement-aware scanning over broad `.*`.

4. Add payload-safe explainability if needed:
   - report detector kind/rule/confidence/source subsystem
   - never print matched text

## Success Criteria

Complete only when all are true:

1. Red tests were observed failing before the fix, or documented as already passing with explanation.
2. Focused tests pass after the fix.
3. Adjacent positive cases still block/redact.
4. Exact reported CircleCI diagnostic command is allowed by:
   - `asg-fast scan --surface bash-command --quiet --fail-on-detect`
   - `cmd-leak-guard`
   - active Claude hook runtime/smoke test

5. Exact reported command is not redacted by:
   - `asg-fast redact --surface tool-output`
   - Claude PostToolUse wrapper for benign diagnostic output

6. Prompt false-positive reports are pasteable:
   - Codex `UserPromptSubmit` with synthetic secret-like text returns allow/empty response.
   - No prompt block occurs.

7. E2E-style wrapper tests pass:
   - safe reference hooks allowed
   - dangerous value hooks blocked
   - benign diagnostic output not suppressed
   - synthetic secret output suppressed/redacted
   - all within timeout
   - no canary leakage

8. Infra failure E2E tests pass:
   - high-risk tool hooks fail closed with `asg-recover`
   - prompt hooks allow
   - telemetry payload-free

9. Required full verification passes:

```bash
{{ASG_HOME}}/.local/bin/agent-secret-guard-tests
{{ASG_HOME}}/.local/bin/asg-fast prove
{{ASG_HOME}}/.local/bin/asg-fast doctor
{{ASG_HOME}}/.local/bin/asg-fast external-eval
```

10. Final health:
   - `asg-fast doctor` reports `ok=true`
   - ASG daemon circuit is closed
   - no unexpected recent fail-open/fail-closed telemetry
   - Codex and Claude hook configs runtime-probe clean
   - Cursor remains unchanged unless explicitly requested

## Non-Goals

Do not disable ASG globally. Do not remove auth-header detection. Do not remove secret-manager detection. Do not make high-risk tool hooks fail open. Do not solve this by lowering all thresholds.
