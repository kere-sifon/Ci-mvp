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

This repo is itself a reusable composite [GitHub Action](https://docs.github.com/en/actions/creating-actions/creating-a-composite-action) — `action.yml` at the repo root. Any other repo can call it without copying any source code.

**Recommended: OIDC role assumption (no long-lived AWS keys stored anywhere).**

One-time AWS setup (per AWS account — only needs doing once, even if you call this action from many repos):

```bash
# 1. Create the GitHub OIDC identity provider (skip if one already exists in this account)
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

Then create an IAM role trusted by that provider, scoped to your specific repos (replace `ACCOUNT_ID` and `GITHUB_OWNER`):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" },
      "StringLike": { "token.actions.githubusercontent.com:sub": "repo:GITHUB_OWNER/*:*" }
    }
  }]
}
```

Attach a least-privilege permissions policy. Cross-region inference profiles (the `us.` prefix on the model ID) need **two** grants, not one: access to the inference-profile ARN itself (which, unlike a foundation-model ARN, includes your account ID), *and* access to the underlying foundation-model ARN in every region the profile can route to. Don't guess the region list — ask Bedrock directly, since AWS can add regions to a profile over time:

```bash
aws bedrock get-inference-profile \
  --inference-profile-identifier us.anthropic.claude-haiku-4-5-20251001-v1:0 \
  --region us-east-1
```

That returns a `models` array with the exact underlying ARNs to use below:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeInferenceProfile",
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "arn:aws:bedrock:us-east-1:ACCOUNT_ID:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0"
    },
    {
      "Sid": "InvokeUnderlyingFoundationModel",
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": [
        "arn:aws:bedrock:REGION_1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:REGION_2::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0"
      ]
    }
  ]
}
```

(Replace `REGION_1`/`REGION_2`/etc. with whatever `get-inference-profile` actually returned — granting only the inference-profile ARN and omitting the foundation-model grant is a common mistake that fails with `AccessDeniedException` on the first real invoke.)

Then, in each calling repo:

```yaml
# .github/workflows/triage.yml  (in the OTHER repo)
name: Security Scan Triage

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write   # required — this action posts a PR comment
  id-token: write        # required for OIDC role assumption

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: kere-sifon/Ci-mvp@v1
        with:
          aws-role-to-assume: arn:aws:iam::ACCOUNT_ID:role/your-role-name
          # everything below is optional — shown with its default value
          # aws-region: us-east-1
          # bedrock-model-id: us.anthropic.claude-haiku-4-5-20251001-v1:0
          # semgrep-config: p/ci
          # trivy-severity: CRITICAL,HIGH,MEDIUM
```

Pin to `@v1` (a moving tag that always points at the latest `v1.x.y`), not `@main` — `@main` picks up every commit immediately, including anything mid-iteration. See [Releasing a new version](#releasing-a-new-version) below for how tags are cut.

The role ARN isn't sensitive (it's not a credential — the trust policy is what actually restricts access), so it's fine to store it as a repo **variable** rather than a secret, e.g. `${{ vars.CI_TRIAGE_AWS_ROLE_ARN }}`, if you'd rather not hardcode it in the workflow file.

**Fallback: static access keys.** If OIDC setup isn't practical (e.g. a restricted/shared AWS account you don't control IAM on), pass `aws-access-key-id` / `aws-secret-access-key` instead of `aws-role-to-assume` — the action falls back to that automatically:

```yaml
      - uses: kere-sifon/Ci-mvp@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

This is simpler to set up but means a long-lived credential sits in GitHub Secrets indefinitely — prefer OIDC when you can.

**Requirements for the calling repo either way:**
- `permissions: pull-requests: write` — composite actions can't set their own permissions, this must come from the caller.
- `permissions: id-token: write` — only needed for the OIDC path.
- `actions/checkout@v4` must run *before* this action, since it scans whatever is already checked out at `$GITHUB_WORKSPACE`.

If triggered outside a `pull_request` event (e.g. a manual run or a push), the action still runs the full scan-and-triage pipeline and prints the markdown comment to the job log — it just skips posting to a PR, since there isn't one.

### Self-scan (this repo)

`.github/workflows/triage.yml` calls the action locally (`uses: ./`) using OIDC, to scan Ci-mvp's own code on every PR — a working example of the pattern above. Local `./` references always use whatever is currently checked out, so version pinning doesn't apply to the self-scan.

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
< test PR to verify OIDC + Bedrock wiring -->
