# ci-triage-agent

Security scan triage tool that ingests SAST/SCA scanner output (Trivy, Semgrep) and produces a human-readable PR comment separating real vulnerabilities from noise.

## Architecture

LangGraph **supervisor-worker** pattern (mirrors [african-stores-agent](https://github.com)):

```
START → supervisor → Parser → supervisor
                   → Classifier → supervisor
                   → Reporter → supervisor
                   → END
```

| Agent | Role |
|-------|------|
| **Parser** | Normalizes Trivy/Semgrep JSON into a shared `Finding` schema |
| **Classifier** | Calls AWS Bedrock for verdict (`true_positive` / `false_positive` / `needs_review`) |
| **Reporter** | Renders `TriageResults` into markdown PR comment |

The **Supervisor** routes Parser → Classifier → Reporter. If the Reporter flags missing or malformed triage data, it loops back to the Classifier once (same conditional-edge pattern as the reference supervisor).

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
cp .env.example .env
```

Configure AWS Bedrock credentials (standard boto3 chain: env vars, `~/.aws/credentials`, IAM role).

## Usage

Local run (prints markdown to stdout):

```bash
python -m src.cli \
  --trivy-file tests/fixtures/trivy_sample.json \
  --semgrep-file tests/fixtures/semgrep_sample.json
```

Post to a PR:

```bash
python -m src.cli \
  --trivy-file trivy-results.json \
  --semgrep-file semgrep-results.json \
  --pr-number 123
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `LLM_PROVIDER` | `bedrock` (default) or `ollama` |
| `AWS_REGION` | AWS region for Bedrock (default `us-east-1`) |
| `BEDROCK_MODEL_ID` | Bedrock inference profile ID |
| `BEDROCK_MAX_TOKENS` | Max tokens (default `4096`) |
| `GITHUB_TOKEN` | Required when posting PR comments |
| `GITHUB_REPOSITORY` | `owner/repo` for PR comments |

## Tests

```bash
pytest
```

All tests use fixtures and mock Bedrock — no live API calls in CI.

## GitHub Actions

### Using this in a different repo (recommended)

This repo is itself a reusable composite [GitHub Action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) — `action.yml` at the repo root. Any other repo can call it without copying any source code:

```yaml
# .github/workflows/triage.yml  (in the OTHER repo)
name: Security Scan Triage

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write   # required — this action posts a PR comment

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: kere-ekpenyong/Ci-mvp@v1   # replace with your actual owner/repo
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          # everything below is optional — shown with its default value
          # aws-region: us-east-1
          # bedrock-model-id: us.anthropic.claude-haiku-4-5-20251001-v1:0
          # semgrep-config: p/ci
          # trivy-severity: CRITICAL,HIGH,MEDIUM
```

Pin to `@v1` (a moving tag that always points at the latest `v1.x.y`), not `@main` — `@main` picks up every commit immediately, including anything mid-iteration. See [Releasing a new version](#releasing-a-new-version) below for how tags are cut.

**Requirements for the calling repo:**
- `permissions: pull-requests: write` at the job or workflow level — composite actions can't set their own permissions, this must come from the caller.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` added as repo (or org) secrets, with Bedrock model access enabled for the target model in that AWS account/region.
- `actions/checkout@v4` must run *before* this action, since it scans whatever is already checked out at `$GITHUB_WORKSPACE`.

If triggered outside a `pull_request` event (e.g. a manual run or a push), the action still runs the full scan-and-triage pipeline and prints the markdown comment to the job log — it just skips posting to a PR, since there isn't one.

### Self-scan (this repo)

`.github/workflows/triage.yml` calls the action locally (`uses: ./`) to scan Ci-mvp's own code on every PR — a working example of the pattern above. Local `./` references always use whatever is currently checked out, so version pinning doesn't apply to the self-scan.

### Releasing a new version

Tags follow [semver](https://semver.org/) (see `CHANGELOG.md`). Every release also moves a floating major-version tag (`v1`, `v2`, ...) so consumers pinned to `@v1` get non-breaking fixes automatically, without re-pinning.

```bash
# 1. Update CHANGELOG.md with what changed, commit it.

# 2. Tag the exact release (immutable, full semver)
git tag -a v1.0.0 -m "v1.0.0: initial reusable action"
git push origin v1.0.0

# 3. Move the floating major tag to point at this release
git tag -f v1 v1.0.0
git push origin v1 --force
```

For the next non-breaking change (bug fix or backwards-compatible addition):

```bash
git tag -a v1.1.0 -m "v1.1.0: <what changed>"
git push origin v1.1.0
git tag -f v1 v1.1.0
git push origin v1 --force
```

**Only bump the major version (`v2.0.0`) when you make a breaking change** to `action.yml` — renaming/removing an input, changing required-vs-optional status, or altering behavior a caller would reasonably depend on. Cut a new `v2` floating tag alongside `v1` rather than replacing it, so repos still pinned to `@v1` keep working unchanged:

```bash
git tag -a v2.0.0 -m "v2.0.0: <breaking change description>"
git push origin v2.0.0
git tag -f v2 v2.0.0
git push origin v2 --force
# v1 stays exactly where it was — do not move it
```

## Non-goals (this pass)

- Auto-generated fix PRs (stub only)
- Policy-as-code translation
- CD/rollback logic
