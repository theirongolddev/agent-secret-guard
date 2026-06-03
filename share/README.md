# Agent Secret Guard Adapter Spec

`agent-secret-guard` is the portable engine. Harness-specific scripts are
adapters.

## Installable Files

- `~/.local/bin/agent-secret-guard`
- `~/.local/bin/asg-fast`
- `~/.local/lib/agent_secret_guard.py`
- `~/.local/bin/agent-secret-guard-install`
- generic adapters under `~/.local/bin/asg-*`
- optional Claude compatibility adapters under `~/.local/bin/secret-*`
- generated harness snippets under `~/.local/share/agent-secret-guard/`
- `~/.local/share/agent-secret-guard/eval-corpus.json`
- payload-free hook observations under
  `~/.local/state/agent-secret-guard/hook-events.jsonl`

The core has no third-party Python dependencies.

For low-latency hooks, start the resident Unix-socket daemon:

```bash
agent-secret-guard daemon-start
agent-secret-guard daemon-status
agent-secret-guard daemon-stop
```

`asg-fast` is a small compiled client used by the adapter scripts. It sends
hot-path scan/redact and hook-adapter commands over the local socket when the
daemon is running, and falls back to the normal CLI for unsupported commands or
when the daemon is unavailable. The default socket is
`~/.local/run/agent-secret-guard/asg.sock`; the directory is `0700` and the
socket is `0600`.

The daemon request protocol forwards only safe ASG control overrides such as
`ASG_HOOK_TELEMETRY_PATH` and `ASG_DISABLE_HOOK_TELEMETRY`; it does not proxy the
caller environment wholesale.

The hot path is designed for agent hooks: cheap substring gates run before
provider regexes, URL decoding, assignment scanning, entropy checks, UTF-8 and
UTF-16 base64 decoding, escape-sequence decoding, HTML entity decoding, percent
decoding, and hex byte decoding. Display normalization catches terminal escape codes and
Unicode format characters that visually expose split secrets. Soft-wrap
reconstruction catches provider tokens split across rendered log lines while
staying disabled for shell-command and VCS-diff surfaces. Chunk reconstruction
catches provider tokens split into same-line space, tab, or colon chunks. The
regression test currently enforces:

- large benign scan, 1.66 MB in process: under 200 ms
- small secret-bearing scan in process: under 5 ms per scan
- daemon-backed `asg-fast` small benign scans: under 20 ms average

Refresh the install manifest:

```bash
agent-secret-guard-install
```

Preview or apply active user-level hook config merges:

```bash
agent-secret-guard-install --dry-run
agent-secret-guard-install --apply
```

`--apply` merges canonical ASG hooks into Claude, Codex, and installed Cursor
user JSON configs. It preserves non-ASG hook entries, creates chmod-600 backups
before rewriting existing files, and prints only structural install counts plus
sanitized coverage/runtime health.

Check local install, optional third-party scanner availability, and active
Claude/Codex/Cursor hook coverage:

```bash
agent-secret-guard doctor
```

`doctor` reads only known agent hook config JSON files and reports structural
coverage counts. It does not print hook command values, project files, `.env`
files, or session logs. For Codex and Cursor, it also probes known-safe ASG
hooks with benign payloads under an empty `PATH` to catch command-shape failures
such as code 127. Treat this as install/runtime-contract evidence, not proof
that every agent runtime version fires every hook event.

ASG adapters also append payload-free live invocation observations containing
only timestamp, harness, and hook event. The default file is
`~/.local/state/agent-secret-guard/hook-events.jsonl`; set
`ASG_HOOK_TELEMETRY_PATH` to override it or `ASG_DISABLE_HOOK_TELEMETRY=1` to
disable it. `doctor` summarizes these observations as evidence that wrappers
have actually been invoked by live runtimes. The observation log never contains
tool input, tool output, prompts, commands, file paths, URLs, or detected
values.

Cursor availability is reported as separate facts: IDE app presence, bundled
`Cursor.app` CLI presence, PATH `cursor`, and PATH `cursor-agent`. A local
Cursor IDE install can be covered even when `cursor-agent` is not installed.

Prove the installed adapter contract with synthetic canaries:

```bash
agent-secret-guard prove
```

`prove` exercises generic wrappers plus Claude, Codex, and Cursor adapters. It
reports pass/fail metadata only; canary values are never printed.

Run the local regression corpus:

```bash
agent-secret-guard eval --corpus ~/.local/share/agent-secret-guard/eval-corpus.json
```

Eval output includes aggregate metrics, a requirement coverage matrix, and
corpus-quality checks. Each case is tagged to one or more obligations such as
`provider:anthropic`, `provider:cloudflare`, `provider:supabase`,
`structured:json-sensitive-key`, or `command:shell-leak-policy`. Eval fails
when a case requirement is missing from the catalog, a catalog entry is unused,
a catalog description is blank, any requirement has fewer than two cases, or
any positive detection obligation lacks a negative counterexample. Eval also
fails when a regex detector kind has no positive corpus case, no literal hint,
no structural prefilter pattern, or no positive corpus case that exercises its
hint or prefilter.

The provider corpus is maintained from public provider docs and mainstream
scanner coverage, with narrow prefix rules preferred over generic assignment
rules. Current source-backed additions include expanded GitLab token prefixes,
GitHub fine-grained PAT coverage, GitHub App installation JWT token format
changes, Grafana service-account tokens, Doppler service and API tokens, 1Password
service-account tokens, SonarQube Cloud scoped organization tokens, Fly.io
access tokens, Buildkite tokens, CircleCI API tokens, Pulumi access tokens,
Atlassian API tokens, Shopify access tokens, PlanetScale tokens, Prefect API
keys, Heroku OAuth tokens, Airtable personal access tokens, Databricks personal
access tokens, Sourcegraph access tokens, Duffel API access tokens, Frame.io API
tokens, Lob API keys, Mapbox secret access tokens, Terraform Cloud tokens,
Postman API keys, Bitrise workspace API tokens, Inngest API/signing keys, and
Azure OpenAI API keys.

Command-denial rules are maintained separately from provider token-format rules.
Current source-backed command rules block cloud CLI commands documented to emit
secret payloads or bearer/password tokens, including AWS STS/SSO/exported
credentials, AWS IAM access-key/service-specific credential creation and reset,
AWS ECR and CodeArtifact authorization tokens, GCP auth token printing variants
with gcloud-wide flags and alpha/beta command groups, GCP Secret Manager
`gcloud secrets versions access`, GCP service-account private-key creation,
Azure `az account get-access-token`, Azure Key Vault secret value reads, Azure
AD service-principal/app credential creation and reset, Azure Storage account
keys/connection strings, Azure Container Registry token/credential outputs, and
Azure App Service publishing credentials/profiles, while allowing nearby
metadata/list commands.

Create a reviewed false-positive baseline without emitting matched values:

```bash
agent-secret-guard baseline-create --surface text > asg-baseline.json
agent-secret-guard scan --baseline asg-baseline.json --fail-on-detect
```

Compare installed third-party scanners through a sanitized bridge:

```bash
agent-secret-guard external-scan --scanner all
agent-secret-guard external-eval --corpus ~/.local/share/agent-secret-guard/eval-corpus.json
```

The bridge captures scanner output internally and emits only scanner name,
kind, location, verification status, and fingerprints. It intentionally drops
raw-match fields such as Gitleaks `Secret`/`Match` and TruffleHog raw values.
`external-eval` writes applicable corpus cases to one chmod-600 temporary
directory and invokes each installed scanner at most once, then maps findings
back to cases by reported file path. By default it emits a concise summary with
ASG stats, scanner stats, bounded disagreement samples, and per-scanner
requirement gaps. Use `--format full` only when you need the complete case
matrix. It is expected to show gaps because repo scanners do not model
agent-specific shell intent, outbound URLs, or JSON hook semantics.

Detector policy favors structure over raw entropy. For paired credentials, ASG
blocks the secret-bearing value and only promotes nearby identifiers when they
form a usable credential pair. For example, a standalone AWS access key ID is
not a blocking secret; the same ID near an AWS secret access key is reported as
part of the credential pair.

Sensitive-looking identifier keys such as `private_key_id`, `secret_name`,
fingerprints, and thumbprints are treated as identifiers unless the associated
value is independently secret-bearing. A Google service-account JSON object
with only `private_key_id` is not blocked; the same object with a `private_key`
PEM value is blocked as a private-key finding.

Reporting/redaction and blocking intentionally use different defaults:
`scan` reports warning-grade findings at 0.65, `redact` masks them, and
`scan --fail-on-detect` hard-denies only at 0.8 unless a caller overrides
`--threshold`. Bare entropy-only findings remain visible in reports/redaction
without blocking normal agent work.

Redaction output is intended to be idempotently safe: ASG redaction markers
must not become fresh findings when downstream hooks or logs rescan them.

Generated harness artifacts:

- `claude-settings-hooks.json`: Claude hook snippet using the legacy
  `secret-*` compatibility adapters
- `codex-hooks.json`: Codex hook snippet using `asg-codex-hook`
- `cursor-hooks.json`: Cursor hook snippet using no-argument `asg-cursor-*`
  wrappers for prompt submission, generic tool use, shell execution, MCP
  execution, file read, file edit, agent response, and agent thought events
  `before*`/permission events are blocking surfaces. Cursor `afterAgent*`
  events are fire-and-forget observation surfaces; ASG proves the adapter does
  not leak detected canaries, but Cursor does not let those events prevent an
  already-produced response.

For Codex, keep `hooks.json` pointed at the no-argument `asg-codex-hook`
wrapper. Do not install `/path/to/asg-fast codex-hook` directly as the hook
command; Codex runtimes can treat the whole string as the executable path,
which fails before ASG runs.

The installer manifest includes `active_harness_coverage`,
`generated_harness_coverage`, and `runtime_probe`; `doctor` also reports
payload-free `hook_observations`. Generated and active Codex and Cursor probes
must have no failures before an installer build is considered shippable.

## Required Harness Integration Points

Every agent harness should wire these surfaces where available:

| Surface | Direction | Action |
|---------|-----------|--------|
| `tool-input` | before local tool execution | block on detection |
| `bash-command` | before shell execution | block on detection |
| `tool-output` | after tool execution | redact before transcript/log persistence |
| `outbound` | before chat/email/doc/comment send | block on detection |
| `url` | before browser/web fetch | block on detection |
| `vcs-diff` | before push/share/publish | block on detection |

## Blocking Adapter

```bash
if ! printf '%s' "$PAYLOAD" |
  asg-fast scan --surface tool-input --quiet --fail-on-detect
then
  # Deny without echoing $PAYLOAD.
  exit 2
fi
```

Direct wrapper:

```bash
asg-json-block < hook-payload.json
```

## Redaction Adapter

```bash
printf '%s' "$TOOL_OUTPUT" |
  asg-fast redact --surface tool-output
```

Direct wrapper:

```bash
asg-json-redact < hook-payload.json
```

## Harness-Specific Adapters

Use direct adapters when a harness exposes a native event schema:

| Harness | Adapter | Status |
|---------|---------|--------|
| Claude | `secret-*` compatibility scripts | snippet generated and mergeable with `--apply` |
| Codex | `asg-codex-hook` | snippet generated and mergeable with `--apply` |
| Cursor | `asg-cursor-*` wrappers | snippet generated; mergeable with `--apply` when Cursor is installed or config exists |

Use the generic `asg-*` wrappers for any other agent harness.

## JSON Findings

Findings intentionally exclude the matched value:

```json
{
  "kind": "GITHUB_TOKEN",
  "confidence": 0.95,
  "span": {"start": 10, "end": 50},
  "reason": "GitHub token"
}
```

Adapters may log `kind`, `confidence`, and `reason`. They must not log source
text, matched spans, or original payloads.

Fingerprints are opt-in via `scan --fingerprints` or `baseline-create`. They
are HMAC-SHA256 values keyed by
`~/.local/share/agent-secret-guard/fingerprint.key`, not raw hashes of secrets.
The key file must be treated as secret material and must not be read into agent
logs.

## Verification

After installing or changing an adapter:

```bash
agent-secret-guard-tests
agent-secret-guard prove
```

Expected current synthetic baseline:

```text
PASS test_performance_budget
PASS test_daemon_fast_client
METRICS tp=77 fp=0 fn=0 tn=58 precision=1.000 recall=1.000 fpr=0.000
CORPUS tp=248 fp=0 fn=0 tn=273 precision=1.000 recall=1.000 fpr=0.000
```

The corpus currently has 101 requirement buckets, 521 synthetic cases, and 712
requirement-case coverage edges. The eval quality gate requires catalog
coverage for every requirement, at least two cases per requirement, and at
least one negative counterexample for every positive detection obligation. It
also requires positive corpus coverage and hint coverage for every regex
detector kind. Literal hints must be at least three characters; shorter
structural triggers use cheap prefilter regexes instead.
Treat it as regression coverage, not as proof that all secret classes are
handled.

Source-backed provider additions are limited to token families with stable,
strongly identifying public structure:

- GitLab token prefixes from GitLab's token overview:
  https://docs.gitlab.com/security/tokens/#token-prefixes
- Shopify Admin API docs confirm access-token authentication, Shopify's
  changelog documents prefixed Admin API tokens using `shpat_`, `shpca_`, and
  `shppa_`, and Gitleaks supplies exact 32-hex body rules including `shpss_`:
  https://shopify.dev/docs/api/admin-rest
  https://shopify.dev/changelog/length-of-the-shopify-access-token-is-increasing
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- PlanetScale docs confirm service-token CLI/API authentication and publish an
  OAuth token example using `pscale_oauth_`; Gitleaks supplies bounded
  `pscale_tkn_`, `pscale_oauth_`, and `pscale_pw_` token-body rules:
  https://planetscale.com/docs/cli/service-tokens
  https://planetscale.com/docs/api/reference/oauth/create-token
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Prefect docs confirm API-key authentication through `PREFECT_API_KEY`, and
  Prefect troubleshooting docs state user keys start with `pnu_` while service
  account keys start with `pnb_`; Gitleaks supplies the 36-alnum user-key body:
  https://docs.prefect.io/v3/how-to-guides/cloud/manage-users/api-keys
  https://docs.prefect.io/v3/how-to-guides/cloud/troubleshoot-cloud
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Heroku OAuth docs state access tokens are bearer credentials, 65 characters
  long, and prefixed `HRKU-`; Gitleaks supplies the narrower `HRKU-AA` plus
  58-character token-body rule:
  https://devcenter.heroku.com/articles/oauth
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Airtable support docs confirm personal access tokens are the scoped API
  credential replacing legacy API keys; Gitleaks supplies the deterministic
  `pat` token-id plus 64-hex body rule:
  https://support.airtable.com/docs/creating-personal-access-tokens
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Databricks docs confirm personal access tokens authenticate workspace-level
  APIs through `DATABRICKS_TOKEN`; credential docs document the `dapi` prefix,
  and Gitleaks supplies the 32-hex body plus optional numeric suffix rule:
  https://docs.databricks.com/en/dev-tools/auth/pat.html
  https://docs.n8n.io/integrations/builtin/credentials/databricks/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Sourcegraph docs confirm access-token authentication through
  `SRC_ACCESS_TOKEN` and `Authorization: token ...`; Gitleaks supplies the
  deterministic `sgp_` prefixed token structures used here:
  https://sourcegraph.com/docs/cli/how-tos/creating-an-access-token
  https://sourcegraph.com/docs/cli/explanations/env
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Duffel docs confirm bearer access-token authentication and state test mode
  tokens start with `duffel_test_`; Gitleaks supplies the deterministic
  `duffel_test_`/`duffel_live_` plus 43-character body rule:
  https://duffel.com/docs/api/overview/requests
  https://duffel.com/docs/guides/testing
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Frame.io docs confirm legacy developer tokens are bearer credentials for the
  API; Gitleaks and TruffleHog agree on the narrow `fio-u-` plus 64-character
  token shape:
  https://developer.frame.io/docs/
  https://next.developer.frame.io/platform/docs/guides/authentication/overview
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/frameio/frameio.go
- Lob docs confirm API basic-auth usage against `api.lob.com`, including
  `test_...` sample keys; Gitleaks supplies the stricter `live_`/`test_` plus
  35-hex shape, while TruffleHog supplies the Lob-context verification method:
  https://docs.lob.com/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/lob/lob.go
- Mapbox docs classify `sk` as secret, `pk` as public, and `tk` as temporary
  token header values. ASG blocks only JWT-shaped `sk.eyJ...` secret tokens and
  treats `pk.eyJ...` public tokens as non-secret identifiers, even though
  Gitleaks currently has a `pk.` Mapbox rule:
  https://docs.mapbox.com/help/dive-deeper/access-tokens/
  https://docs.mapbox.com/accounts/guides/tokens/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Dropbox docs confirm OAuth access tokens are bearer credentials and now
  short-lived by default; Dropbox community staff document the `sl.` prefix for
  short-lived access tokens. ASG requires a Dropbox token/key assignment context,
  while Gitleaks and TruffleHog provide the third-party scanner shape baseline:
  https://developers.dropbox.com/oauth-guide
  https://community.dropbox.com/en/discussion/554402/is-dropbox-access-tokenwill-expire-after-some-time
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/dropbox/dropbox.go
- LaunchDarkly docs state REST API access tokens authenticate the Authorization
  header and are private. They also state server-side SDK keys are secret and
  start with `sdk-`, while mobile keys start with `mob-` and do not need to be
  kept secret. TruffleHog supplies the `api-`/`sdk-` UUIDv4 token shape used for
  the secret detectors:
  https://launchdarkly.com/docs/guides/api/rest-api
  https://launchdarkly.com/docs/home/account/api-create
  https://launchdarkly.com/docs/home/account/environment/keys
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/launchdarkly/launchdarkly.go
- Clojars docs confirm deploy tokens are password substitutes for publishing and
  are shown only once. Leiningen docs publish the `CLOJARS_` sample shape,
  Gitleaks supplies the 60-character lowercase alphanumeric body rule, and
  GitGuardian classifies this as a prefixed package-registry token:
  https://github.com/clojars/clojars-web/wiki/Deploy-Tokens
  https://leiningen.org/deploy
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/clojars_deploy_token
- Cargo docs state crates.io API tokens are secret and should be revoked if
  leaked. GitHub supports `cratesio_api_token` with push protection, GitGuardian
  classifies the key as a prefixed package-registry token, and OSV-SCALIBR gives
  the current `cio` plus 32-alphanumeric detector shape and validation endpoint:
  https://doc.rust-lang.org/cargo/reference/publishing.html
  https://docs.github.com/code-security/secret-scanning/secret-scanning-patterns
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/crates_io_key
  https://raw.githubusercontent.com/google/osv-scalibr/main/veles/secrets/cratesioapitoken/detector.go
- xAI docs confirm API-key authentication for xAI API access, GitHub lists
  `xai_api_key` as a supported secret scanning pattern with push protection, and
  TruffleHog supplies the current `xai-` plus 80-character token shape with an
  API-key validation endpoint:
  https://docs.x.ai/docs/management-api/auth
  https://docs.github.com/code-security/secret-scanning/secret-scanning-patterns
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/xai/xai.go
- Groq docs show `GROQ_API_KEY` in server-side examples and use `gsk_...` for
  API-key placeholders. GitHub lists `groq_api_key` as a supported provider
  pattern, and GitGuardian classifies Groq keys as prefixed AI tokens with
  validity checking:
  https://console.groq.com/docs/production-readiness/security-onboarding
  https://docs.github.com/code-security/secret-scanning/secret-scanning-patterns
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/groq_api_key
- Tavily docs show `TAVILY_API_KEY` and `tvly-...` API-key placeholders in
  server-side and CLI setup examples. GitGuardian classifies Tavily keys as
  prefixed AI tokens with validity checking:
  https://docs.tavily.com/documentation/quickstart
  https://docs.tavily.com/documentation/tavily-cli
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/tavily_api_key
- NVIDIA docs state `NVIDIA_API_KEY` values typically start with `nvapi-`.
  TruffleHog's current NVAPI detector uses `nvapi-` plus a 64-character
  `[A-Za-z0-9_-]` body and `nvapi-` as its prefilter keyword. GitGuardian lists
  NVIDIA API Key as a supported AI credential:
  https://docs.nvidia.com/nemo/retriever/latest/extraction/api-keys/
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/nvapi/nvapi.go
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/supported_credentials
- LangSmith setup docs use `LANGSMITH_API_KEY`/`LANGCHAIN_API_KEY`, LangSmith
  examples show `lsv2_...` API-key placeholders, and older LangSmith docs
  identify personal/service key prefixes as `lsv2_pt_` and `lsv2_sk_`. GitHub
  lists Langchain personal and server API keys as supported secret-scanning
  patterns:
  https://docs.langchain.com/langsmith/setup
  https://docs.langchain.com/langsmith/cli
  https://docs.smith.langchain.com/old/cookbook/tracing-examples/manage-spend
  https://docs.github.com/code-security/secret-scanning/secret-scanning-patterns
- Jina's current API reference says valid Jina API keys are 65 characters and
  start with `jina_`; GitGuardian classifies Jina API keys as prefixed AI
  tokens with validity checking:
  https://api.jina.ai/redoc
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/jina_api_key
- Langfuse docs show `LANGFUSE_SECRET_KEY="sk-lf-..."` and
  `LANGFUSE_PUBLIC_KEY="pk-lf-..."` examples, while Public API docs use
  public key as username and secret key as password. GitGuardian classifies
  Langfuse credentials as a credential detector with validity checking:
  https://langfuse.com/docs/api-and-data-platform/features/cli
  https://langfuse.com/docs/api-and-data-platform/features/public-api
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/langfuse_credentials
- Pinecone docs require API keys for API access, Pinecone CLI docs and SDK
  release examples show the current `pcsk_...` key shape, GitHub lists
  `pinecone_api_key`, and GitGuardian tracks Pinecone API key/v2 detectors with
  validity checking:
  https://docs.pinecone.io/guides/get-started/authentication
  https://pinecone.mintlify.app/reference/cli/command-reference
  https://github.com/pinecone-io/pinecone-python-client/releases
  https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/pinecone_api_key
- Ssemble authentication docs state API keys are prefixed with `sk_ssemble_`,
  should be kept secret, and can be passed through `X-API-Key` or Bearer auth:
  https://www.ssemble.com/docs/authentication
- Firecrawl docs use Bearer authentication with `fc-` API-key examples, and
  Firecrawl source normalizes `fc-` plus a dashless UUID into UUID form:
  https://docs.firecrawl.dev/api-reference/v2-introduction
  https://raw.githubusercontent.com/firecrawl/firecrawl/main/apps/api/src/lib/parseApi.ts
- Cursor official docs confirm API keys and Bearer authentication for automation
  APIs but do not publish the concrete key shape. DX integration docs state
  Cursor API keys start with `crsr_`, and GitGuardian tracks Cursor API Key as a
  current detector. ASG detects only the observed `crsr_` shape rather than
  claiming complete Cursor key coverage:
  https://docs.cursor.com/en/background-agent/api/overview
  https://docs.cursor.com/en/cli/reference/authentication
  https://docs.getdx.com/connectors/cursor/
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/cursor_apikey
- Open VSX source generates access-token values from a configured prefix plus a
  UUID. Its bundled custom secret-detection rule matches `ovsxat`/`ovsxp`
  tokens with `_` or `-` separators and a UUID body. GitGuardian tracks Open VSX
  Access Token as a current prefixed detector:
  https://raw.githubusercontent.com/eclipse-openvsx/openvsx/main/server/src/main/java/org/eclipse/openvsx/accesstoken/AccessTokenService.java
  https://raw.githubusercontent.com/eclipse-openvsx/openvsx/main/server/src/main/resources/scanning/secret-detection-custom-rules.yaml
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/ovsx_access_token
  https://docs.gitguardian.com/releases/detection-engine
- Pagar.me docs state encryption keys start with `ek_`, followed by the
  environment marker `live` or `test`, then random characters generated by the
  API. GitGuardian tracks Pagar.me Encryption Key as a current detector:
  https://docs.pagar.me/v4/docs/api-key-e-encryption-key
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/pagar_me_encryption_key
  https://docs.gitguardian.com/releases/detection-engine
- HCP Terraform docs require API requests to authenticate with a bearer token
  and classify user, team, organization, and audit-trail token types.
  GitGuardian tracks Terraform Cloud Token as a prefixed, high-recall detector,
  and Trivy's built-in rule uses the `atlasv1.` keyword plus a
  `14 + .atlasv1. + 60-70` credential shape:
  https://developer.hashicorp.com/terraform/cloud-docs/api-docs
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/terraform_cloud_token
  https://fossies.org/linux/trivy/pkg/fanal/secret/builtin-rules.go
- Qdrant Cloud docs state granular database API keys can be recognized by
  starting with `eyJhb` and are sent through `api-key` or Bearer auth headers:
  https://qdrant.tech/documentation/cloud/authentication/
- Databento docs confirm API-key authentication and state each API key is a
  32-character string starting with `db-`. GitHub's secret-scanning changelog
  lists DataBento `databento_api_key` among detectors with validity checking:
  https://databento.com/docs/quickstart/new-user-guides
  https://databento.com/docs/api-reference-live/basics
  https://github.blog/changelog/2025-07-22-secret-scanning-adds-validity-checks-for-over-40-secret-detectors/
- Azure OpenAI REST docs require an `api-key` request header for key-based
  authentication, Microsoft Purview defines Azure Cognitive Service keys as
  32-character letter/digit credentials that require supporting context, and
  GitGuardian tracks Azure Open AI API key as a current AI detector:
  https://learn.microsoft.com/en-us/azure/ai-foundry/openai/latest
  https://learn.microsoft.com/en-us/purview/sit-defn-azure-cognitive-service-key
  https://www.gitguardian.com/detectors
  https://docs.gitguardian.com/releases/detection-engine
- Unkey docs classify root keys as secret administrative credentials for Unkey
  API requests. Unkey's GitHub secret-scanning RFC says root keys use the
  `unkey_` prefix with an alphanumeric body, and GitHub's changelog lists
  `unkey_root_key` among detectors with validity checking:
  https://www.unkey.com/docs/security/root-keys
  https://engineering.unkey.com/docs/rfcs/0002-github-secret-scanning
  https://github.blog/changelog/2025-07-22-secret-scanning-adds-validity-checks-for-over-40-secret-detectors/
- GitHub's 2026 App installation token format notice:
  https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens
- GitHub's token-format update documents token prefixes and the `[A-Za-z0-9_]`
  character set; fine-grained PAT GA confirms the token family is now generally
  available:
  https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
  https://github.blog/changelog/2025-03-18-fine-grained-pats-are-now-generally-available/
- Grafana service-account tokens, including GitHub Secret Scanning integration:
  https://grafana.com/docs/grafana/latest/administration/service-accounts/
  https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/secret-scan/
- Doppler service and API tokens:
  https://docs.doppler.com/docs/service-tokens
  https://docs.doppler.com/docs/multiple-workplaces
  https://docs.doppler.com/docs/service-accounts
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/pkg/detectors/doppler/doppler.go
- 1Password service-account tokens use the `ops_` prefix and authenticate via
  `OP_SERVICE_ACCOUNT_TOKEN` for CLI automation:
  https://developer.1password.com/docs/service-accounts/security/
  https://developer.1password.com/docs/service-accounts/get-started/
- SonarQube Cloud scoped organization tokens use the `sqco_` prefix and are
  passed to analysis through `sonar.token`:
  https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/managing-organization/scoped-organization-tokens
- Fly.io access tokens are used through `FLY_API_TOKEN`; Fly docs show generated
  deploy tokens with `FlyV1` plus an `fm2_` token body, and Gitleaks covers
  additional Fly token body prefixes:
  https://fly.io/docs/security/tokens/
  https://fly.io/docs/launch/continuous-deployment-with-github-actions/
  https://fly.io/docs/monitoring/metrics/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Tailscale key prefixes and secret-scanning scope for API keys, auth keys,
  OAuth client secrets, SCIM keys, and webhook keys:
  https://tailscale.com/docs/reference/key-prefixes
  https://tailscale.com/kb/1301/secret-scanning
  https://tailscale.com/changelog/#2023-09-21-developer
- DigitalOcean access-token prefixes for personal access tokens, OAuth access
  tokens, and OAuth refresh tokens, with exact 64-hex body rules from Gitleaks:
  https://docs.digitalocean.com/reference/api/reference/security/
  https://www.digitalocean.com/blog/updated-api-tokens-new-management-features
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Netlify authentication tokens have identifiable `nf*` prefixes and a 40
  character storage requirement; Netlify API docs confirm personal access token
  bearer usage, and Gitleaks supplies broader Netlify context methodology:
  https://answers.netlify.com/t/change-to-the-netlify-authentication-token-format/106146
  https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
- Buildkite token security docs publish supported token prefixes for API/user
  access, agent session/job/registration, cluster, package registry, portal
  access, and portal secret tokens:
  https://buildkite.com/docs/platform/security/tokens
- CircleCI's 2023 token-format changelog documents new personal and project API
  token prefixes plus the base58-UUID and 40-hex tail structure; CircleCI API
  docs confirm token-based API authentication:
  https://circleci.com/changelog/new-format-for-api-access-tokens/
  https://circleci.com/docs/guides/toolkit/managing-api-tokens/
  https://circleci.com/docs/guides/toolkit/api-developers-guide/
- Bitrise docs confirm Workspace API tokens authenticate Bitrise API calls for
  one workspace and Bitrise's GitHub token-scanning docs confirm Workspace API
  tokens use a recognized leak-scanning format; GitGuardian documents the
  concrete `bitwat_` workspace-token signal. ASG intentionally scopes this
  detector to workspace tokens, not undocumented Bitrise personal-access-token
  shapes:
  https://devcenter.bitrise.io/en/workspaces/workspace-api-token.html
  https://docs.bitrise.io/en/bitrise-platform/accounts/github-token-scanning.html
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/bitrise_workspace_api_token
- Inngest API docs confirm API-key bearer authentication with `sk-inn-api-`
  examples and signing-key bearer authentication with `signkey-` examples;
  Inngest signing-key and event-key docs classify both as secrets. ASG detects
  the concrete API/signing prefixes and keeps event-key placeholders
  non-blocking until a concrete public event-key shape is available:
  https://api-docs.inngest.com/authentication
  https://www.inngest.com/docs/platform/signing-keys
  https://www.inngest.com/docs/events/creating-an-event-key
- Pulumi docs confirm access tokens authenticate Pulumi Cloud CLI/API usage and
  `PULUMI_ACCESS_TOKEN` runtime injection; Gitleaks supplies the narrow `pul-`
  plus 40-hex token structure, and GitGuardian classifies Pulumi access tokens
  as prefixed:
  https://www.pulumi.com/docs/administration/access-identity/access-tokens/
  https://www.pulumi.com/docs/iac/cli/environment-variables/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/pulumi_access_token
- Atlassian docs confirm API tokens authenticate Jira and Confluence REST API
  calls and are not recoverable after creation; Gitleaks and scanner references
  provide the narrow `ATATT3...` structured token form used for deterministic
  matching:
  https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account
  https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  https://detectors.xygeni.io/xydocs/secrets/detectors/jira_token.html
- age identity files contain age secret keys with `AGE-SECRET-KEY-1...`; the
  same documentation names post-quantum identities with
  `AGE-SECRET-KEY-PQ-1...`:
  https://github.com/FiloSottile/age
- Postman API keys and Postman/GitHub/GitLab secret-scanner handling:
  https://learning.postman.com/docs/administration/managing-your-team/secret-scanner/how-secret-scanner-works/
- RFC 9580 defines the OpenPGP private-key armor header used by exported
  OpenPGP secret keys:
  https://www.rfc-editor.org/rfc/rfc9580
- GitHub's provider-pattern guidance: push protection is for token versions
  that can be identified with confidence, to avoid unnecessary blocking:
  https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns
- Amazon Bedrock API keys are bearer tokens with distinct short-term and
  long-term structural prefixes:
  https://docs.aws.amazon.com/en_us/bedrock/latest/userguide/api-keys.html
  https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-use.html
  https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/
- Microsoft documents PowerShell `-EncodedCommand` as UTF-16LE base64, so ASG
  decodes both UTF-8 and UTF-16 base64 when the decoded text is scanner-relevant:
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe

Source-backed command-denial additions are limited to commands documented to
emit secret payloads or bearer/password tokens:

- AWS STS role/session commands and AWS SSO role-credential commands return
  temporary access-key, secret-key, and session-token material:
  https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html
  https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html
  https://docs.aws.amazon.com/cli/latest/reference/sso/get-role-credentials.html
- AWS `configure export-credentials` displays resolved AWS credentials in JSON,
  shell, PowerShell, cmd, or Fish formats:
  https://docs.aws.amazon.com/cli/latest/reference/configure/export-credentials.html
- AWS IAM access-key and service-specific credential creation/reset commands
  return one-time secret access keys, passwords, or credential secrets:
  https://docs.aws.amazon.com/cli/latest/reference/iam/create-access-key.html
  https://docs.aws.amazon.com/cli/latest/reference/iam/create-service-specific-credential.html
  https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/reset-service-specific-credential.html
- AWS ECR `get-login-password` displays a registry password, and
  `get-authorization-token` returns registry authorization data:
  https://docs.aws.amazon.com/cli/latest/reference/ecr/get-login-password.html
  https://docs.aws.amazon.com/cli/latest/reference/ecr/get-authorization-token.html
- AWS CodeArtifact `get-authorization-token` returns repository authorization
  tokens:
  https://docs.aws.amazon.com/cli/latest/reference/codeartifact/get-authorization-token.html
- Google Cloud `gcloud auth print-access-token` and
  `gcloud auth print-identity-token` print bearer/identity tokens, support
  gcloud-wide flags, and have alpha/beta variants:
  https://docs.cloud.google.com/sdk/gcloud/reference/auth/print-access-token
  https://docs.cloud.google.com/sdk/gcloud/reference/auth/print-identity-token
- Google Cloud `gcloud secrets versions access` accesses secret version data and
  writes secret data to stdout unless `--out-file` is used:
  https://docs.cloud.google.com/sdk/gcloud/reference/secrets/versions/access
- Google Cloud `gcloud iam service-accounts keys create` writes the private
  portion of a service-account key to a local file and has alpha/beta variants:
  https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/create
- Azure Key Vault docs use `az keyvault secret show --query value` to view a
  secret value as plain text:
  https://learn.microsoft.com/en-us/azure/key-vault/secrets/quick-create-cli
- Azure CLI `az account get-access-token` gets a token for utilities to access
  Azure:
  https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest
- Azure Container Registry `az acr login --expose-token` returns/displays an
  access token; ACR credential/token commands expose registry passwords:
  https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication
  https://learn.microsoft.com/en-us/cli/azure/acr/credential?view=azure-cli-lts
  https://learn.microsoft.com/en-us/cli/azure/acr/token/credential?view=azure-cli-latest
- Azure Storage account key and connection-string commands expose access-key
  material:
  https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list-keys?view=rest-storagerp-2024-01-01
  https://learn.microsoft.com/en-us/cli/azure/storage?view=azure-cli-latest
- Azure Web App and Function App publishing credential/profile commands expose
  deployment credentials:
  https://learn.microsoft.com/en-us/cli/azure/webapp/deployment?view=azure-cli-latest
  https://learn.microsoft.com/en-us/cli/azure/functionapp/deployment?view=azure-cli-latest
- Azure service-principal/app creation and credential reset commands emit
  passwords, credentials, or private-key certificate locations:
  https://learn.microsoft.com/en-us/cli/azure/azure-cli-sp-tutorial-1?view=azure-cli-latest
  https://learn.microsoft.com/en-us/cli/azure/azure-cli-sp-tutorial-7?view=azure-cli-latest
  https://learn.microsoft.com/en-us/cli/azure/ad/app/credential?view=azure-cli-latest
