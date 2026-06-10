# ASG v2 — Redesign RFC: From "Looks Like a Secret" to "Is a Secret"

> Status: proposal. Written 2026-06-10 from a full ruleset archaeology of the
> current engine plus external research (citations at bottom). Code references
> are `file:line` against the current working copy. Supported harnesses:
> Claude Code, Codex CLI, Pi/Hermes, plus a generic adapter spec. §6 records
> approaches that were considered and rejected — do not drift back into them.

## 0. Summary

ASG v1 got the invariants right (never emit the matched value, enforce on
action surfaces, advise on prompts) and the detection economics wrong. It
treats *statistical resemblance to a secret* as the primary signal, enforces
with a binary deny at almost every surface, ships zero configuration levers,
and has no feedback loop from production. Each of those four choices
independently produces the failure mode that got it uninstalled: high-friction
false positives that neither the agent nor the human can do anything about.

The redesign inverts the detection stack and widens the action space:

1. **Exact knowledge first.** Fingerprint secrets the system can actually
   know about — harness-process environment values, explicitly registered
   values, injector-wrapped child environments, and (optionally, behind a
   provider-agnostic adapter contract) any vault's contents — the way GitHub
   Actions masks known values. Exact match → near-zero FP, near-perfect
   recall on the secrets that actually matter. The layer is an accelerator,
   not a foundation: every enforcement decision that *relaxes* v1 behavior is
   gated on this layer demonstrably having coverage (§2.3), and everything
   degrades gracefully to Tiers 1–4 when no exact source is configured.
2. **Structure second.** Provider detectors with validators/checksums keep
   doing what they do well (this is v1's strongest layer — keep it).
3. **Statistics last, and never enforcing alone.** Bare entropy drops from
   "redact" to "observe". Published data: entropy-only detection runs ~21%
   precision; structured-format detection runs 99%+ (§1.1).
4. **Five actions, not two.** `allow / observe / redact / ask / deny` replace
   the redact≥0.65 / block≥0.8 pair, with explicit headless degradation
   (`ask` never hangs an unattended session).
5. **Rules as data + layered config.** Every rule gets a stable ID, a default
   action per surface, and a user override path. Profiles
   (`paranoid/strict/standard/trusting`), per-rule actions, per-path
   allowlists, tracked-file exemptions, committable ignore files.
6. **Every denial is a doorway.** Structured block envelopes with event IDs
   (value spans masked), `asg approve <id>` (declared-reason bypass, audited,
   scoped grants), `asg fp <id>` (FP report feeding tuning), redaction
   markers that carry handles for explanation and re-run-under-grant.
7. **Auditable by construction.** One value-free, schema-versioned decision
   journal across all harnesses feeds `asg log`/`asg stats` and, later, a
   zero-dependency localhost dashboard (§2.8).

The end state: a guard that is *certain* about your real secrets and *humble*
about everything else — which is exactly the posture that fades into the
background.

---

## 1. Diagnosis

### 1.1 The detection economics are inverted

`HIGH_ENTROPY_TOKEN` fires at confidence 0.66 (`src/agent_secret_guard.py:2858`)
— exactly 0.01 above the redact threshold (`DEFAULT_REDACT_THRESHOLD = 0.65`,
`:45`) and below the block threshold. Translation: every bare-entropy finding
redacts output and none ever blocks. So the noisiest detector class is wired
directly to the most visible annoyance (mangled tool output), and the eval
can't see it: `--fail-on-detect` evaluates at 0.8, so entropy FPs are
invisible to the corpus gate (this is the known redact-threshold blind spot).

The external evidence says this layer cannot be fixed by tuning:

- Entropy-only detection: **21.1% precision** on CredData (Betterleaks
  analysis). SecretBench: ~85% of regex candidates in the wild are FPs.
- Structured-format-only detection with three cheap post-filters: **99.29%
  precision** at GitHub scale (Meli et al., NDSS 2019).
- GitHub push protection *blocks* only on "highly identifiable patterns";
  generic/entropy findings alert but never block. That asymmetry is the
  industry-converged answer.
- No statistic computed on the string alone can separate "random and secret"
  from "random and public" (git SHA, UUID, content hash, SRI integrity) —
  they are all outputs of uniform random processes. Separation must come from
  format, checksum, context, or exact knowledge.

v1's response to this reality is `add_high_entropy_findings`'s pile of 17
inline suppressor predicates (`:2820-2841`), four of which were added in the
final week before uninstall (commit log: vercel metadata, repo slugs, VCS
refs, env-template URLs). Each real-world FP becomes a new hardcoded Python
function plus a corpus case plus a reinstall. The space of legitimate
high-entropy strings is unbounded; this loop does not converge.

### 1.2 Confidence values are router codes, not probabilities

Every CommandRule is 0.91 (`:210`), every PathRule 0.93 (`:219`), assignments
0.82/0.88 (`:2234`), entropy 0.66. These numbers exist to steer rule classes
into the {ignore, redact, block} buckets created by the two global
thresholds. They carry no calibrated meaning, can't be tuned per rule or per
surface, and make per-surface cost asymmetry (an FP block on `vcs-diff` is
cheap; an FP block on `file-read` stalls the session) inexpressible.

Meanwhile the corpus reports precision/recall 1.000 while four FP regression
reports landed in `bugs/` within two days of dogfooding. The corpus measures
coverage of cases already encoded; there is no production signal at all —
telemetry records only fail-open/fail-closed events (`bin/asg-hook-lib:31`),
not which rule fired or what action was taken.

### 1.3 Rules are code; identity is prose

No config file is read anywhere in the engine. The only runtime levers are
two telemetry env vars and a `--threshold` flag the hook adapters never pass.
Rule names exist (`PathRule("...", "claude-settings", ...)` `:1525`) but reach
the output only as text appended to the reason string
(`f"{rule.reason}; rule={rule.name}"`, `:1897`). The in-flight
`bin/cmd-leak-guard` work has to shell-glob against reason *sentences* to
categorize blocks — direct evidence of the missing abstraction. Consequences:

- No per-rule disable. Turning off the `claude-settings` block requires
  editing a 6,400-line file and reinstalling.
- No allowlists (path, stopword, fingerprint, project).
- No profiles, no per-project config, no `regexTarget`-style scoping.
- Gitleaks/detect-secrets both treat rule IDs and a layered suppression
  ladder (config allowlist → committable ignore-file → inline allow comment
  → baseline) as core public API. v1 has none of the ladder.

### 1.4 Response misallocation: deny where redact/rewrite/ask would do

- **Path rules are binary deny by filename pattern with no ground truth.**
  `.claude/settings.json` (`:1525`) and `secrets?.*.{yaml,json,toml,env}`
  (`:1540`) block reads regardless of whether the file is git-tracked and
  regardless of what the file actually contains — even though ASG is a local
  tool that could simply *scan the file* before deciding. The
  `.infisical.json` and committed-settings bugs in `bugs/` are both this.
- **Command rules deny output-leaky commands instead of scrubbing output.**
  `git remote -v`, `supabase status`, `ps aux`, `printenv` are denied
  outright (`:1545-1582`), yet the risk lives in their *output*, which the
  engine can already redact. The June 2 bug writeup says exactly this ("the
  engine already supports a strictly-better response than the one taken").
- **Harness primitives unused.** Claude Code PreToolUse supports
  `permissionDecision: allow|deny|ask|defer` and `updatedInput` (rewrite the
  call); PostToolUse supports `updatedToolOutput`. Codex hooks support
  deny and input rewriting. Hermes accepts Claude-style block directives and
  exposes output-transform hooks. v1 emits only deny (or exit-2 stderr).
  There is no "ask the human" path even where the harness ships one.

### 1.5 No escape hatch, no feedback, weak messages

`bin/file-leak-guard:34-46` omits the blocked path from its message — but the
agent *composed* that path; only values are secret. Pointless opacity that
makes remediation harder for zero security benefit. There is no event ID, no
`asg approve`, no FP-report channel, and redaction markers
(`[REDACTED:KIND]`) carry no handle for review. The TruffleHog `badlist.txt`
incident (silent suppression hiding real secrets, and silent enforcement
confusing users) is the cautionary tale: every decision must be observable
and addressable.

### 1.6 Fail-closed overreach

When the engine is unavailable, the Claude PostToolUse adapter suppresses the
*entire tool output uninspected* (`asg-hook-lib:86`). A daemon hiccup becomes
total information loss mid-task. Fail-closed is correct for `vcs-diff` and
`outbound`; for `tool-output` the cost/benefit is upside down.

### 1.7 What v1 got right (keep all of this)

- The value-free findings invariant, end to end (including external-scanner
  report sanitization). Non-negotiable; carry it forward.
- The 107 provider detectors with shape validators and literal-hint
  prefilters — this is the industry-standard high-precision layer.
- Decode-then-rescan (base64/UTF-16/escapes/entities/percent/hex, depth 2) —
  TruffleHog does the same to depth 5.
- Daemon + C fast client; enforced perf budgets.
- Enforce-on-action / advise-on-prompt; reference-vs-value fixes
  (`is_shell_variable_reference`, `safe_secret_reference_header`).
- Corpus quality gates (≥2 cases/requirement, negative counterexample per
  positive obligation).
- The in-flight remediation-guidance work — directionally right; §2.4
  generalizes it from prose-matching to rule metadata.

---

## 2. Target architecture

### 2.0 Decision model: tiers × actions

Five actions, ordered: `allow < observe < redact < ask < deny`.
(`observe` = log to the decision journal, touch nothing.)

Five detection tiers, by *kind of knowledge*:

| Tier | Knowledge | Examples | Default action ceiling |
|------|-----------|----------|------------------------|
| 0 | **Exact** — value is in the known-secrets fingerprint index | admitted env values, `asg mask`-registered values, synced vault values | deny (pre-action) / redact (output) |
| 1 | **Checksum-verified** provider token | `ghp_*`/`npm_*` CRC32-valid, `glpat-*` routable, Luhn PAN | deny / redact |
| 2 | **Validated structural** provider token (v1's 107 detectors) | JWT that parses, AWS pair, PEM block | deny / redact |
| 3 | **Contextual generic** — sensitive key/header + credible value | `API_KEY=<opaque-30-chars>` in .env-like context | redact / ask |
| 4 | **Statistical** — entropy/LM score alone | bare opaque blob in output | **observe only** |

The tier ceiling is policy: no configuration can make Tier 4 deny, and only
explicit user opt-down can make Tier 0–1 weaker than redact. Within the
ceiling, the action is `f(tier, surface, config)` — fixed per-tier defaults
shipped per profile, tunable per rule. (Score calibration is offline tooling
that *recommends* settings; it is never in the enforcement path — §2.5, §6.)

Checksum validation is symmetric and free: a CRC32-valid `ghp_` candidate is
promoted to Tier 1 (block with near-certainty); a UUID with correct
version/variant nibbles, an SRI hash with exact `sha512-`+88-char shape, a
ULID whose timestamp decodes to a plausible date, a 40/64-hex blob adjacent
to VCS context — all are demoted deterministically. This converts the worst
entropy-FP classes (and the worst entropy-FN class: checksummed real tokens)
into deterministic decisions before any statistics run.

**Headless rule.** Adapters detect non-interactive operation (no TTY /
harness signal). In headless sessions every `ask` degrades to a configured
action — default `deny` with the full envelope (§2.4) so the agent can adapt
or queue the approval for later — and never to an indefinite prompt. An
unanswered interactive `ask` times out to the same degradation. Unanswered
and degraded asks are journaled distinctly (`ask-degraded`) so ask-storms are
visible in `asg stats` before they drive anyone to `profile = "trusting"`.

### 2.1 Tier 0: the exact-knowledge layer (highest leverage, zero required deps)

Prior art: GitHub Actions' runner masks every known secret *plus ~11
precomputed encoding variants each* (base64 at all 3 byte-alignment shifts
with padding trimmed, URI-escaped, JSON-escaped, etc.). GitLab enforces a
≥8-char floor so masking can't shred output. HCP Vault Radar treats "matches
a value actually in your vault" as a distinct, maximum-severity,
near-zero-FP finding class.

**Portability constraint (architectural).** ASG must install and deliver its
full value anywhere — no particular vault, no network, no account. Tier 0 is
therefore an *accelerator with pluggable sources*, never a foundation: Tiers
1–4 carry the system on a bare machine, every Tier 0 source below is
optional, and §2.3's coverage-gating rule ensures an empty index never
weakens enforcement.

**Sources**, with honest coverage statements:

1. **Harness-process environment.** At hook time the client fingerprints the
   *values* of environment variables visible to the harness process (hooks
   inherit that environment). Coverage: secrets exported in the user's shell
   rc, and secrets present because the harness itself was launched under an
   injector (`infisical run -- claude`). **Not covered:** secrets injected
   only into tool subprocesses (`infisical run -- npm test` puts values in
   `npm`'s environment, a process no hook inhabits) — which is precisely the
   hygienic workflow security-conscious users follow, and on Codex,
   `shell_environment_policy` strips secret-named vars from spawned shells
   anyway. This source is cheap and on by default, but it is a partial
   source and is never treated as more (§6, rejected: env-as-foundation).
2. **Injector wrapping.** The PreToolUse adapter recognizes runtime-injector
   invocations (`infisical run`, `op run`, `doppler run`, `dotenvx run`) and
   — per config `wrap_injectors = "suggest" | "auto" | "off"` (default
   `suggest`) — routes them through `asg exec`, which fingerprints the
   *child* environment after injection (delta vs. parent), feeds the
   session index, and scrubs the child's output. This converts the main
   coverage gap of source 1 into an integration point.
3. **Explicit registration.** `asg mask` reads values from stdin (or a named
   env var) and adds their fingerprints to the session or persistent index —
   the `::add-mask::` equivalent, scriptable by anyone from anything.
4. **Vault adapters (optional plugins behind one trivial contract).** A
   provider is any executable that prints **NUL-delimited** values to stdout
   (NUL, not newline — multi-line secrets like PEM keys must survive
   framing). `asg vault sync --provider <name>` runs the configured command
   and fingerprints the stream. Reference adapters ship as *data in config,
   not code in the engine*:

   ```toml
   [vault.providers.infisical]
   command = ["sh", "-c", "infisical secrets --plain --silent | tr '\\n' '\\0'"]  # or a -0 flag where supported
   refresh = "1h"   # and/or the provider's own change-hook runs `asg vault sync`

   [vault.providers.dotenv]
   command = ["asg-dotenv-values", "-0", "./.env.production"]
   ```

   Nothing in the engine knows what Infisical (or 1Password, or HashiCorp
   Vault, or a dotenv file) is. It knows: run command, fingerprint
   NUL-delimited values, discard plaintext.

**Admission gates (every source).** Indexing a non-secret at the
maximum-trust tier is the most expensive FP the system can produce, so
values are screened before admission:

- length ≥ 8 (GitLab's floor) and ≤ a sanity cap for single-token entries
  (longer material goes to the fragment/multi-line path);
- not on the common-value blocklist (dictionary words, `production`,
  `localhost`, well-known hostnames/ports);
- not value-shaped-as-infrastructure: paths (`/run/user/...`), URLs without
  embedded credentials, socket addresses;
- for env capture, name-pattern refinement: `*_TOKEN/_KEY/_SECRET/_PASSWORD`
  admit; `*_URL/_HOST/_NAME/_PATH/_SOCK/_ADDRESS/_DIR` do not
  (`SSH_AUTH_SOCK` and `DBUS_SESSION_BUS_ADDRESS` must never enter the
  index);
- rejected candidates are journaled as `tier0-rejected` with the *source
  name only* (env var name / vault key name — never the value), so gaps are
  diagnosable.

Every index entry records provenance (source + key name). `asg explain`
shows it; `asg unmask <key-or-id>` evicts an entry and journals the
eviction. This is the difference between "certain" and "stubborn."

**Index construction** (identical for all sources):

```
values (memory only, post-admission)
  → expand variants: raw · base64 ×3 shifts (padding trimmed) · hex ·
    url-encoded · json-escaped · shell-escaped
  → HMAC-SHA256(install_key, variant)  → exact-match set
  → all 16-grams of each value → rolling-hash fragment set
  → write keyed index (0600); plaintext never touches disk
```

**Scanning and plumbing.**

- Exact-token probing: candidate tokens (already extracted by the prefilter,
  §2.6) are HMAC-probed against the exact-match set. Pure Python, bounded by
  candidate count, always available.
- Fragment probing (partial leaks ≥16 chars, split/wrapped values; winnowing
  k=16, w=16 for multi-line material guarantees detection of any leaked
  substring ≥31 chars at ~12% fingerprint density): a full-stream
  rolling-hash pass that lives in the **C helper**. Installs without a C
  compiler degrade to exact-token matching only; `doctor` reports the
  degraded mode explicitly rather than letting it pass silently.
- Env values reach the scanner from the *client* process (which inherits the
  harness env) over the 0600 Unix socket in a dedicated frame; they are used
  in memory, never journaled, never persisted. Daemonless fallback computes
  fingerprints in-process.
- Freshness: the env source is computed live per hook; persistent sources
  rebuild on `daemon-start`, on TTL, and on provider change-hooks where the
  provider offers one. Every rebuild bumps `index_rev` (which the verdict
  cache keys on, §2.6).
- The index is keyed: an unkeyed SHA-256 index of secret values would be an
  offline-crackable oracle (GitGuardian uses peppered scrypt for the
  networked version of this). Threat model is accidental exposure, not a
  local adversary who already owns `$HOME`; state this in docs.

Why this is the highest-leverage layer: once the secrets that demonstrably
exist on this machine are caught deterministically, every heuristic layer
can afford to be humble. The guard's promise changes from "I block things
that look like secrets" to "I *will not let your actual secrets leave*, and
I'll politely flag lookalikes."

### 2.2 Rules as data + layered configuration

Extract the rule classes users actually override — path rules, command
rules, per-rule actions, suppressor shape lists — into a versioned, shipped
ruleset file. Each rule carries: stable `id` (`path.claude-settings`,
`cmd.ps-args`, `token.github-pat`, `heur.entropy`), tier, per-surface default
action, keyword prefilter, pattern, validator reference, remediation
template, and a doc link.

**The data/code seam, stated plainly:** token detectors and their ~30
validator functions (Luhn, CRC32, JWT parse, provider shapes,
`valid_*` `:742-1040`) remain *code*, addressed by stable IDs; the ruleset
file references validators by registry name. `doctor` fails on dangling
validator references and on ruleset/engine version skew. Users can add
pattern-only rules in config; validator-bearing rules require code — that
boundary is explicit, not aspirational.

Config layering (TOML), highest wins:

```
built-in defaults
  < ~/.config/asg/config.toml          # user
  < <project>/.asg/config.toml         # project (trust-gated, see below)
  < ASG_* env overrides                # session
```

```toml
profile = "standard"        # paranoid | strict | standard | trusting

[rules."path.claude-settings"]
action = "observe"          # one line, no reinstall

[rules."path.*"]
allow_if_vcs_tracked = true # see scope limits in §2.3

[allow]
paths = ["**/.infisical.json", "share/eval-corpus.json"]
stopwords = ["example", "synthetic"]

[surfaces.vcs-diff]
fail_policy = "closed"      # per-surface fail posture
[surfaces.tool-output]
fail_policy = "open-warn"
```

- **Project-config trust model.** A repo's `.asg/config.toml` may only
  *tighten* policy unless the project path is allowlisted in the user config
  (direnv-style). "Tighten" is defined per knob as an explicit partial
  order, not left to intuition: actions move only up the
  `allow→observe→redact→ask→deny` lattice (with `ask` ranked per the
  session's headless degradation, so it can never silently weaken a `deny`);
  allowlists/stopwords/ignores may only *shrink*; new project-supplied
  patterns run with a hard regex time budget so a pathological pattern
  cannot induce timeout→fail-open. Knobs with no defined order are
  user-config-only.
- **Suppression ladder** (all diffable text): config rule/action overrides →
  committable `.asg/ignore` → keyed-fingerprint baselines (local) → inline
  `# asg:allow` for source files. The committable ignore file uses
  **structural fingerprints** (`rule-id : path : line-window`) — portable
  across machines by construction. Keyed value-fingerprints (HMAC under the
  per-install key) are strictly local artifacts: they never enter a repo,
  because they are meaningless on any other machine and an unkeyed
  alternative would be a crackable oracle. The ignore file is part of
  project config and trust-gated like the rest of it.
- **Profiles** set the tier→action matrix wholesale. `paranoid` ≈ v1
  behavior; `standard` is the redesign default described here; `trusting`
  drops Tier 3 to observe.

### 2.3 Right-sized responses on each surface

**The coverage-gating rule (load-bearing).** Several v1 denies are relaxed
below into allow+scrub. Every such relaxation is *conditional* on the scrub
actually being available and meaningful for this session and harness:

1. the harness supports output rewriting for the surface (§2.9 matrix), and
2. the payload is within the harness's rewrite limits (see the large-output
   protocol below), and
3. the Tier 0 index is non-trivial for the session (env admissions > 0, a
   vault sync configured, or injector wrapping active) **or** the rule is
   explicitly configured `scrub_without_index = true`.

When the conditions fail, the surface falls back to `ask` (interactive) /
`deny` (headless) — never to silent allow. `doctor` warns when scrub
surfaces are active against an empty exact index, and the journal records
`tier0_index_size` with every scrub decision so the gap is queryable.

**File reads.** Replace name-pattern deny with a decision cascade:

1. Path matches a rule? If `allow_if_vcs_tracked` applies → allow (observe).
   Scope limits: the exemption requires a configured remote (no remote ⇒
   nothing was "already shared"), and **never applies to the dotenv or
   private-key rule families** — a tracked `.env` is the canonical leak, not
   an exemption case.
2. Otherwise **scan the actual content** before deciding. The scan includes
   Tier 0–2 everywhere **plus Tier 3 for env-shaped/secret-named files**
   (`KEY=value` config is the definitional Tier 3 context; scanning a
   `.env`-like file without Tier 3 would wave through `DB_PASSWORD=...`).
   Clean → allow. Findings → allow + PostToolUse `updatedToolOutput`
   redaction of exactly the secret spans (Claude/Hermes), or deny with an
   envelope pointing at `asg read <path>` (prints redacted content) where
   output rewriting is unavailable. Private-key material (`*.pem`, `id_*`)
   → deny always.
3. Operational limits: scans are size-capped (prefix scan with binary sniff;
   oversized or binary files downgrade to the rule-based path decision plus
   the large-output protocol on the read result). TOCTOU between scan and
   read is acknowledged residual risk, mitigated by the PostToolUse backstop
   where it exists and *stated* in the doctor coverage matrix where it
   doesn't.

**The large-output protocol.** Harnesses cap hook payloads (Claude Code caps
hook output strings at ~10k chars and delivers oversized tool results to
hooks as a preview plus a file path). Adapters must therefore: (a) detect
the spill format and submit the referenced file to the daemon for a full
scan, treating the spill file as part of the surface; (b) when a redacted
result would exceed the rewrite cap, fall back per config — Bash surfaces
prefer an `updatedInput` rewrite that pipes through `asg-stream-redact`
up front; otherwise the adapter replaces the result with a short redaction
notice + `asg read`-style retrieval instructions rather than emitting a
truncated mangle; (c) journal every truncated/spilled hook payload
(`payload-spilled`) — this is a known leak trapdoor, and it must be
measurable, not assumed away.

**Bash commands.** Split the 54-rule LEAKY_COMMAND monolith into intents:

- *Output-leaky* (`ps aux`, `printenv`, `env`, `git remote -v`,
  `supabase status`): **allow + scrub output**, under the coverage-gating
  rule above. Where the gate fails (no index, no output rewriting on this
  harness, payload too large), the v1-style deny remains — with the v2
  envelope, which is the actual fix for the friction.
- *Argv-value* (literal credential in the command text — Tier 0/1/2 match in
  argv): deny with a rewrite suggestion (`use $VAR / --file / stdin`), or
  auto-rewrite via `updatedInput` when the substitution is unambiguous
  (opt-in: `rewrite = "auto"`).
- *Credential-minting* (`aws iam create-access-key`,
  `gcloud iam service-accounts keys create`, `az ad sp create-for-rbac`):
  **ask** where the harness supports it (Claude); deny-with-envelope
  elsewhere and in headless sessions.
- *Injector invocations*: see §2.1 source 2 (wrap via `asg exec`).
- *Secret-fetch-by-reference* (`TOK=$(infisical secrets get … --plain)` piped
  to a safe sink): allow; the session/vault index guards the value
  downstream. (v1's June-2 policy contract, kept and made enforceable.)

**Outbound / vcs-diff / MCP payloads:** unchanged enforcement posture (deny
on Tier 0–2 ≥ threshold), now with the exact layer raising recall where it
matters most.

**Prompts:** advisory, as in v1.

### 2.4 Agent ergonomics: every denial is a doorway

Structured envelope on every non-allow decision (both harness-native fields
and a JSON blob the agent can parse):

```json
{
  "event": "asg-7f3k9q",
  "action": "deny",
  "rule": "cmd.argv-credential",
  "tier": 1,
  "surface": "bash-command",
  "target": "curl --user user:[ASG:GITHUB_TOKEN] https://api.github.com/…",
  "why": "literal credential in argv (checksum-verified github token)",
  "fix": [
    "move the value to an env var: curl --user user:$GH_TOKEN …",
    "or fetch at call time: --user user:$(infisical secrets get GH_TOKEN --plain)"
  ],
  "escape": "ask the user to run: asg approve asg-7f3k9q"
}
```

Principles:

- Never omit what the agent already knows (paths, command shape) — **but the
  `target` field is span-masked for Tier 0–2 findings before emission**. In
  the argv-credential case the blocked thing *is* a literal credential;
  echoing it raw into an envelope that lands in transcripts and session logs
  would re-leak it through the guard's own mouth. Masked target, full shape.
- Remediation comes from rule metadata, not prose-matching (generalizing the
  in-flight `cmd-leak-guard` work).
- Dual-audience messaging where the harness distinguishes audiences; on
  Claude, `permissionDecisionReason` (model) + `systemMessage` (user).

Human-side verbs (GitHub push-protection semantics — bypass with declared
reason, never silent, always audited):

- `asg approve <event> [--once | --ttl 1h]` — reason required
  (`false-positive | test-data | accept-risk`); each reason drives a
  different downstream state (FP → auto-suggest a config/ignore entry;
  accept-risk → time-boxed grant, open item in the decision log). **Grant
  scoping:** grants bind to `{rule-id, normalized target pattern}` — not to
  exact event content, so the agent's slightly-varied retry still matches —
  and default to the requesting session (`--all-sessions` to widen; a TTL
  grant for one agent must not silently loosen a concurrent one). Grants
  persist in the state directory (they survive daemon restarts) and every
  grant/use/expiry is journaled.
- `asg explain <event>` — rule, tier, span lengths, provenance (source/key
  *names* for Tier 0), and the config that produced the decision.
- `asg fp <event> [--note]` — appends a value-free FP report (rule, surface,
  context features, fingerprint) to the local FP log: the production
  feedback loop v1 never had. FP reports become corpus candidates and tuning
  inputs.
- Redaction markers carry handles: `[ASG:HIGH_ENTROPY:asg-7f3k9q]` →
  `asg explain asg-7f3k9q`, and re-execution under a one-shot grant
  (`asg approve asg-7f3k9q --once`, then retry) when the human agrees the
  content is needed. There is deliberately **no un-redaction command**: the
  redacted value is not retained anywhere, so revealing it is impossible by
  construction (§6). An agent staring at a redacted line can now *do
  something* other than re-running the command five different ways.

### 2.5 Scoring: replace Shannon-primacy with validate → checksum → LM

For the residual generic pool (Tier 3 candidates only — statistics never
enforce alone):

1. **Deterministic suppressors as data**: UUID nibbles, ULID timestamp, SRI
   prefix+length, 40/64-hex near VCS context, k8s suffix alphabet, webpack
   contenthash shape, JWT-header-decodes-to-JSON (header/payload are
   public-by-design; only the signature segment is sensitive). These replace
   most of the 17 hardcoded suppressor functions with a shipped, extensible
   list.
2. **Character trigram log-likelihood** (gibberish detector trained on
   code-identifier + English corpora; ~2–5 µs/token in pure Python) +
   optional frozen-vocab token-efficiency ratio (the Betterleaks signal:
   57.3% precision / 98.6% recall standalone vs entropy's 21.1/70.4).
   Shannon survives only as a cheap pre-gate. The LM is a versioned,
   shipped artifact with a checked-in corpus build script; rebuilding it and
   re-running the eval is a release step with an owner, not a hope. It is an
   *input* to Tier 3 classification only — on domain-heavy codebases where
   it misfires, the blast radius is capped by the Tier 3 ceiling
   (redact/ask, configurable down).
3. **Thresholds are fixed per-tier defaults** shipped with each profile and
   tuned from the corpus + accumulated FP reports. `asg tune` is an
   *offline* report that recommends threshold changes with evidence; humans
   apply them via config/release. No statistical machinery sits in the
   enforcement path, and no output of it is described as a guarantee (§6,
   rejected: calibration-as-certification).

### 2.6 Reliability & performance

- **Verdict cache** in the daemon keyed by `(content_hash, config_rev,
  ruleset_rev, index_rev, grant_rev)` — a vault sync, env admission, or new
  grant must invalidate, or the cache becomes a recall hole. Honest
  accounting: hashing content is itself O(n), so the cache saves
  detection-pass time, not I/O; that is still the bulk of the budget for
  repeat scans.
- **Prefilter architecture** (ripgrep model, stdlib-feasible): one
  candidate-token regex pass (~5–15 ms/MB) + `str.find` literal-anchor scan
  for the ~50 known prefixes (Crochemore-Perrin in C, effectively free) →
  windowed per-family regexes only around anchors → LM scoring only on
  survivors. Budget: ≤1 ms for 4 KB hook payloads, 20–60 ms/MB. (Pure-Python
  Aho-Corasick is measured ~50× too slow; §6. The rolling-hash fragment
  probe lives in the C helper; §2.1.)
- **Fail policy per surface**: closed for `vcs-diff`/`outbound`; open-warn
  for `tool-output`/`file-read` (configurable). Kill the
  suppress-entire-output behavior (`asg-hook-lib:86`); a degraded guard must
  degrade gracefully. Adapters on harnesses whose hook runner fails open on
  crashes (Hermes parses stdout even on non-zero exit) must emit an explicit
  block directive on internal failure for fail-closed surfaces — exit codes
  alone are not a fail-closed mechanism there.
- **Shadow mode**: `mode = "shadow"` runs a candidate ruleset/config beside
  the active one, logging decision diffs to the journal without enforcing —
  the safe rollout path for every future ruleset change.
- **Decision journal**: see §2.8.

### 2.7 Guard integrity: the legitimate concern behind the settings lockdown

The v1 settings-file block descended from a real requirement: an agent must
not be able to *modify its own harness configuration* to disable or bypass
the guard in pursuit of a goal. The threat is real — but it is a **write**
threat about *specific content*, and v1 implemented it as a **read** block on
a filename. Scoped correctly:

- **Reads of harness/agent config: allow**, subject to the same content scan
  as any other file. Inspecting settings is legitimate work.
- **Writes are content-aware, not path-blind.** A Write/Edit whose result
  touches guard-relevant content — hook entries referencing ASG adapters,
  the `hooks` block as a whole, permission allowlists, `.asg/` config, the
  ruleset/index files, ASG binaries — gets **ask** (deny-with-envelope when
  headless). Unrelated edits to the same file (model choice, theme, an MCP
  server without inline credentials) pass untouched.
- **Tamper detection is the backstop**, because no hook intercepts every
  write path to files the user owns (shell redirects, `tee`, `python -c`),
  and a guard that pretends otherwise is theater. The daemon keeps integrity
  hashes of installed hook configs, ASG binaries, ruleset, and active
  config; verification runs at daemon start **and on a periodic tick**
  (start-only checks can lag drift by days); drift — including hook
  *removal* — raises a `guard-integrity` journal event and a user-facing
  warning instead of passing silently.
- **Re-attestation is a first-class verb**, or drift warnings become noise
  that trains the user to ignore the one real tamper: `asg attest`
  re-baselines the hashes after a human-reviewed change; changes that went
  through an approved `ask` auto-attest; installer runs attest themselves.
- **Approval grants and config changes are journaled** (§2.8), so "the
  guard's rules changed" is always an inspectable fact.

This keeps the original requirement — agents can't quietly defang the guard —
while deleting the false-positive class that motivated this redesign.

### 2.8 Observability backend → `asg dash`

Auditability is a first-class output, and the decision journal is the
integration point. The backend is designed now so a UI is a rendering detail
later:

- **One append-only, schema-versioned, value-free event stream**
  (`decisions.jsonl`): every decision (`allow/observe/redact/ask/deny`),
  ask-degradations, approval grant/use/expiry, FP report, index/vault-sync
  and `tier0-rejected` events, `payload-spilled` events, fail-open/closed,
  `guard-integrity` drift and attestations. Every record carries `v` (schema
  version), `ts`, `event_id`, `session_id` + `harness` (passed through from
  hook payloads so events group by agent), `surface`, `rule`, `tier`,
  `action`, span lengths, `tier0_index_size` where relevant, keyed
  fingerprint — never content. Size-based rotation with archived segments
  (v1's 512 KB cap, but rotate, don't truncate).
- **Query verbs before pixels**: `asg log [--since --rule --surface
  --session --action]` and `asg stats`. These verbs are the API the
  dashboard consumes — and the proof the schema is right.
- **A standing watchlist**, surfaced by `asg stats` and `doctor`, of the
  leading indicators that precede every known failure mode: redaction
  density attributed to `tier0.*` rules (over-admission), scrub decisions
  with `tier0_index_size = 0` (coverage gap), `payload-spilled` counts
  (large-output trapdoor), `ask-degraded` counts (ask-storms),
  `ruleset_rev`/LM/threshold staleness vs engine releases (maintenance
  drift). These metrics exist precisely because each one is the first
  observable symptom of a way this design fails.
- **`asg dash`** (later phase, zero new dependencies): stdlib `http.server`
  bound to 127.0.0.1, serving one embedded HTML page; endpoints `/events`
  (filtered journal as JSON), `/stats`, `/health` (daemon state, index
  freshness, per-harness coverage matrix from doctor). Polling first, SSE
  tail if it earns it. The stream is value-free by construction, so the
  dashboard leaking is an annoyance, not an incident.
- **Cross-agent by default**: all harness adapters write the same journal,
  so "what have my agents done security-wise today" is one page.

### 2.9 Harness support matrix

Supported: **Claude Code** (reference target), **Codex CLI**, **Pi/Hermes**.
Anything else integrates through the generic adapter spec
(`asg-json-block` / `asg-json-redact` / `asg-stream-redact`), which requires
only "run a command with JSON on stdin, honor its exit code/stdout."

| Capability | Claude Code | Codex CLI | Hermes | Pi |
|---|---|---|---|---|
| Pre-tool decision | allow / deny / **ask** / defer | allow / deny | block (accepts Claude-style `{"decision":"block"}` payloads) | extension hostcall allow/deny |
| Input rewrite | `updatedInput` | `updatedInput` | no | via extension capability policy |
| Output rewrite | `updatedToolOutput` (≈10k cap; spill protocol §2.3) | whole-result replacement (coarse) | `transform_tool_result` plugin | extension-mediated |
| Event coverage | all tools | shell, `apply_patch`, MCP | `pre/post_tool_call` (all tools), `pre_llm_call` | tool hostcalls |
| Headless `ask` | degrades per §2.0 | n/a (no ask) → deny-with-envelope | n/a → deny-with-envelope | n/a → deny-with-envelope |
| Fail posture notes | exit-2 blocks; other codes pass | hooks are "a guardrail, not an enforcement boundary" (their docs) | non-zero exit is logged and stdout still parsed → adapters must print explicit block directives for fail-closed surfaces | extension policy is in-process |

Per-harness integration shape:

- **Claude Code**: the full v2 design — ask, input rewrite, span-level output
  redaction with the large-output protocol.
- **Codex**: shell/patch/MCP blocking with envelopes; coarse output
  replacement where span surgery is impossible; `shell_environment_policy`
  already strips secret-named env vars from spawned shells (complementary
  name-based hygiene; ASG adds value-based detection on top).
- **Hermes**: a `hooks:` entry in `~/.hermes/config.yaml` pointing at the ASG
  adapter for `pre_tool_call` (Claude-compatible block payloads mean the
  Claude adapter logic is reused nearly verbatim), plus a small Hermes plugin
  implementing `transform_tool_result` for output redaction. Hermes's
  first-use consent allowlist and `hermes hooks doctor` slot into `asg
  doctor`'s coverage matrix.
- **Pi**: an ASG extension using the capability-policy/hostcall gate
  (QuickJS extension runtime) to route tool calls through `asg-fast`. The
  extension API's exact redaction affordances are the open verification item
  for this harness; until verified, Pi's matrix row is enforced
  block/allow plus advisory messaging, and `doctor` reports it as such.

`doctor` renders this matrix *live* — per harness, per surface, which
guarantees actually hold on this install (C helper present? output rewrite
available? index non-empty?) — because a guard whose coverage is assumed
rather than reported is how silent gaps become incidents.

---

## 3. The reported pain points, before → after

| Case | v1 behavior | v2 behavior |
|------|-------------|-------------|
| Read committed `.claude/settings.json` | deny (`path.claude-settings`, name-match) | tracked-file exemption or content scan → allow; any real inline MCP token gets span-redacted; one-line config to disable the rule entirely |
| Agent edits its own hooks/permissions to defang the guard | read-block only; no content awareness, no tamper detection | content-aware write gate → ask; integrity hashes + `guard-integrity` journal alarm on drift; `asg attest` (§2.7) |
| Read `.infisical.json` | deny (`read-secret-path`) | content scan → clean → allow |
| Read a *tracked* `.env` | deny by name | still guarded: exemption excludes dotenv family; content scan includes Tier 3 → values redacted |
| `git remote -v` | deny | allow + output scrub when coverage-gated conditions hold; envelope-deny otherwise |
| `ps aux`, `printenv` | deny | allow + exact-layer scrub under the coverage gate; deny-with-envelope when the index is empty |
| `curl -H "X: $TOKEN"` | historically blocked (reference-vs-value) | allow by rule (reference is safe); value guarded downstream by env/injector fingerprints |
| `infisical run -- npm test` leaking via child output | unseen by env-based detection | injector wrapping (`asg exec`) fingerprints the child env and scrubs child output (§2.1) |
| Random high-entropy line in output (git SHA, bundle hash) | `[REDACTED:HIGH_ENTROPY_TOKEN]`, no recourse | untouched (Tier 4 = observe); if redacted by a Tier ≤3 rule, marker carries an event handle → `asg explain` / approve-and-rerun |
| Writing an FP bug report containing secret-shaped repro text | report itself redacted | Tier 4 observe + `# asg:allow` inline + `asg approve --once`; prompts stay advisory |
| Engine/daemon hiccup mid-session | whole tool output suppressed | open-warn on output surfaces; closed only where exfiltration is irreversible |

## 4. Migration path (each phase shippable, v1 invariants preserved)

**Phase 1 — config + messaging (2–4 weeks; kills the top friction)**
Rule IDs as structured finding fields (touches every `Finding` construction
across ~20 passes plus dedupe, JSON emission, corpus, and the test suite —
this, not the config parser, is the critical path); layered config with
per-rule `action` and path allowlists; entropy → observe in the default
profile; structured block envelopes with event IDs and masked targets;
per-surface fail policy (fix PostToolUse suppression); schema-versioned
decision journal with session/harness tags + `asg log`/`asg stats`;
empirical characterization of each harness's hook payload caps and spill
formats. Detachable if needed: tracked-file exemption (needs a cached
git/jj-tracked lookup to stay inside hook budgets) and dropping the hard
`jq` dependency in adapters.

**Phase 2 — exact layer + cache + approvals (the keystone)**
Admission-gated env fingerprinting + `asg mask` + `asg unmask` + provenance;
injector wrapping via `asg exec`; provider-agnostic `asg vault sync`
(NUL-framed contract; reference adapters: dotenv-file, infisical, 1password,
vault); fragment probe in the C helper with doctor-visible degradation;
verdict cache (all five key components); `asg approve/explain/fp` + scoped,
persistent grants; coverage-gated command-intent split (output-leaky →
allow+scrub); large-output spill protocol; guard-integrity write gating +
tamper hashes + `asg attest`.

**Phase 3 — scoring + rules-as-data + dashboard**
Extract path/command rules and suppressor lists to data files (detectors and
validators stay code with IDs; doctor validates references); trigram LM as a
versioned artifact with a build script; `asg tune` offline threshold
reports; shadow mode; `updatedInput` rewrite (suggest-first, auto opt-in);
Hermes plugin + Pi extension adapters; `asg dash` localhost dashboard over
the journal (§2.8).

**Phase 4 — frontier (optional, high ceiling)**
Session taint tracking (fingerprint values observed flowing out of
secret-fetch commands; block those exact values on outbound surfaces);
cross-session FP learning; a small local context-classifier as a
post-detection precision stage on Tier 3 only (GitGuardian FP-Remover
pattern: tag, never delete; tuned for ~100% precision on the "ignore"
decision); continuous canary probes through real harness surfaces
(extending `prove`).

## 5. Risks and honest tradeoffs

- **Exact-layer sync briefly holds enumerated values in memory** (any
  provider). Acceptable for the accidental-exposure threat model; document
  it, build the index in one process, never write plaintext, key the index.
- **Tier 0 over-admission is the new FP vector with the highest trust.** The
  admission gates, provenance, `tier0-rejected` journaling, and `asg unmask`
  exist because of this; the §2.8 watchlist makes over-admission visible in
  week one rather than at uninstall time.
- **Relaxing v1 denies trades a known annoyance for a recall risk.** The
  coverage-gating rule (§2.3) is the containment: relaxation never happens
  against an empty index, on a harness that can't rewrite output, or past
  payload caps. The residual risk — a secret that exists nowhere ASG can
  know about, printed by an allowed command — is real and is the price of a
  usable guard; it is bounded by Tier 1–3 output scanning, which still runs.
- **Large-output spill paths are a structural leak trapdoor** in
  hook-based architectures. The spill protocol + `payload-spilled` metric
  treat it as a first-class surface, not a footnote.
- **`updatedInput` auto-rewrites can surprise**; default to
  suggest-in-deny-message, make auto-rewrite opt-in.
- **Tracked-file exemption** assumes committed ⇒ already shared. The
  exemption is scoped (remote required, dotenv/key families excluded,
  content scan still applies) because the assumption fails for unpushed
  repos, soon-to-be-public repos, and just-committed secrets under active
  remediation.
- **Harness asymmetry is permanent.** Codex has no ask and coarse output
  replacement; Hermes hooks fail open on crashes (adapters compensate with
  explicit directives); Pi's redaction affordances are unverified. The
  doctor coverage matrix states, per harness, which guarantees hold —
  assumed coverage is how silent gaps become incidents.
- **The C helper is optional but load-bearing for fragment detection**; a
  no-compiler install silently loses partial-leak coverage unless doctor
  says so. Doctor says so.
- **More configurability = more footgun surface**; the tier ceilings (Tier
  0–1 can't be weakened below redact; Tier 4 can't enforce) and the
  project-config tighten-only partial order bound the blast radius of any
  config.

## 6. Considered and rejected (do not drift back here)

- **Cursor support.** Rejected. Cursor's `beforeReadFile` is allow/deny-only
  (no content redaction) and carries no agent-facing message on denial, and
  Cursor has no shell-output rewriting at all — so on Cursor the design
  collapses back to v1's choices: blanket denies (the friction this redesign
  exists to remove) or unscrubbed allows (recall loss), with no way to honor
  the "every denial is a doorway" contract. Supported harnesses are Claude
  Code, Codex, and Pi/Hermes. Revisit only if Cursor ships output rewriting
  plus agent-visible deny reasons.
- **`asg reveal` (un-redaction).** Rejected as physically incompatible with
  the value-free invariant: revealing a redacted span requires having
  retained it, and nothing retains it — the journal is value-free, plaintext
  never touches disk, and the original output is rewritten and discarded.
  An encrypted value-store would create a new crown-jewels asset and a new
  key lifecycle to protect it. The supported flow is `asg explain` +
  `asg approve --once` + re-run.
- **Session-env fingerprinting as the universal Tier 0 foundation.**
  Rejected. Hooks see the harness's environment, not the environments of
  tool subprocesses; runtime injectors (`infisical run -- cmd`) put secrets
  precisely where hooks aren't. Env capture is kept as one admission-gated
  source among four, and no enforcement relaxation may be justified by Tier
  0 except under the coverage-gating rule (§2.3). Treating env capture as
  "works everywhere" would have shipped a recall regression disguised as an
  FP fix.
- **Keyed value-fingerprints in committable ignore files.** Rejected:
  HMAC-under-a-per-install-key matches nothing on a teammate's machine, and
  the unkeyed alternative is an offline-crackable oracle of your secrets.
  Committable suppression uses structural fingerprints (rule:path:window);
  keyed value fingerprints stay local.
- **Statistical calibration (Platt/conformal) in the enforcement path, and
  any "certified FP rate" claim.** Rejected. The guarantees require
  exchangeability between the calibration set (~hundreds of curated
  synthetic cases plus self-selected FP reports) and production traffic;
  that assumption is false, and the resulting number would be v1's
  "precision 1.000" corpus artifact with better vocabulary. Calibration
  survives only as `asg tune`, an offline advisor whose output a human
  applies through config.
- **Live provider verification (TruffleHog-style API calls).** Rejected for
  the default path: it transmits candidate strings off-host — itself an
  exfiltration channel — and imports rate limits and provider drift into
  the hot path. Checksum/structure validation captures most of the
  precision benefit locally. Could return someday as an explicit,
  per-provider opt-in for *post-hoc triage* (never pre-action blocking).
- **Pure-Python full-stream scanning (Aho-Corasick or per-byte rolling
  hash).** Rejected on measurement: ~50× over budget at 1 MB. The prefilter
  + C-helper split is the architecture; pure-Python installs run
  exact-token Tier 0 and all of Tiers 1–4, with doctor-visible degradation
  of fragment detection.
- **Entropy as an enforcing detector** (v1's design). Rejected — §1.1. Tier
  4 observes, permanently.
- **Filename-pattern read denial for config files** (v1's design). Rejected
  in favor of content-conditional decisions + write-side guard integrity
  (§2.7). The motivating threat was write-shaped all along.
- **An LLM judge in the hot path.** Rejected for latency and
  non-determinism on every tool call. A small local classifier may appear
  in Phase 4, post-detection, on Tier 3 only, tuned so "ignore" decisions
  are ~100% precise, tagging rather than deleting.

## 7. Sources (selected)

- Meli et al., *How Bad Can It Git*, NDSS 2019 — 99.29% precision via
  structured formats + cheap filters.
- SecretBench / FPSecretBench (MSR 2023); nine-tool comparison
  (arXiv:2307.00714) — best precision 75% (GitHub), recall 88% (Gitleaks).
- GitHub engineering: token formats (prefix + Base62 + CRC32); push
  protection bypass-with-reason UX; Actions runner `SecretMasker` +
  ValueEncoders + ADR 0297 (base64 padding/shifts).
- Gitleaks config model (rule IDs, allowlists, stopwords, `.gitleaksignore`);
  detect-secrets filters/baseline/audit; TruffleHog verification + the
  badlist.txt lesson (silent suppression); Semgrep Secrets local validators;
  GitGuardian FP Remover (post-detection ML, tag-don't-delete).
- Claude Code hooks reference (permissionDecision allow/deny/ask/defer,
  `updatedInput`, `updatedToolOutput`, 10k output cap + file spill,
  additionalContext); Codex hooks + `shell_environment_policy`; Hermes
  shell-hooks (`agent/shell_hooks.py`: Claude-compatible block payloads,
  consent allowlist, stdout-parsed-on-nonzero-exit) and plugin hooks
  (`transform_tool_result`); pi_agent_rust extension runtime (QuickJS,
  capability policy, hostcall allow/deny).
- HIBP k-anonymity; GitGuardian HasMySecretLeaked (peppered, keyed
  fingerprints); HCP Vault Radar (vault correlation as severity).
- Betterleaks/CredData (entropy 21.1%P/70.4%R; token-efficiency 57.3%/98.6%);
  Nostril (n-gram identifier oracle >99%); winnowing (SIGMOD '03).
