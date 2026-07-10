# Changelog

All notable changes to this project are documented here. Versioning follows
[Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

- **MAJOR** — breaking change to `action.yml`'s inputs/outputs, or a change
  that alters existing behavior consumers depend on.
- **MINOR** — new input, new capability, backwards-compatible.
- **PATCH** — bug fix, no interface change.

## [v1.1.1] — 2026-07-10

### Fixed
- `trivy-action` was pinned to `@0.28.0`, a tag that no longer exists,
  causing every workflow run to fail at "Prepare all required actions."
  Replaced with a commit-SHA pin (not a version tag) to the exact release
  the aquasecurity maintainers confirmed was **not** affected by the
  March 2026 supply-chain compromise, in which attackers force-pushed
  malicious code onto 75 of the repository's 76 version tags. Pinning by
  tag would not have prevented that attack even for a correct version
  number, since the tags themselves were rewritten.
- Removed the pip cache from the `Set up Python` step. `github.action_path`
  resolves with a trailing `/.` segment for local `uses: ./` references
  (this repo's own self-scan), which `actions/setup-python`'s
  cache-dependency-path glob validator rejects outright — caching wasn't
  essential here, so it was simplest to drop rather than normalize the path.

## [v1.1.0] — 2026-07-10

### Added
- OIDC role assumption (`aws-role-to-assume`) as the recommended AWS auth
  path — no long-lived AWS keys need to be stored as GitHub secrets.
  Existing callers using `aws-access-key-id`/`aws-secret-access-key` are
  unaffected; that path still works as a documented fallback.
- Validation step that fails fast with a clear error if neither auth method
  is configured, instead of a confusing downstream credentials error.

## [v1.0.0] — 2026-07-10

Initial reusable-action release.

### Added
- LangGraph supervisor-worker pipeline: Parser → Classifier → Reporter agents.
- Trivy + Semgrep ingestion, normalized into a shared `Finding` schema.
- AWS Bedrock (Claude Haiku 4.5) classifier with cluster-based triage
  (`true_positive` / `false_positive` / `needs_review`).
- Composite `action.yml` — usable by any repo via `uses: <owner>/Ci-mvp@v1`.

### Fixed (pre-release hardening)
- Cluster verdicts now fan out to every finding in a cluster, not just the
  representative — previously non-representative findings in a multi-item
  cluster were silently dropped from the report.
- Reporter now correctly renders a valid "no findings" comment for a
  genuinely clean scan, instead of the supervisor falling through to a
  dead-end `END` with no output.
- Semgrep severity mapping now recognizes both the execution-severity scale
  (`ERROR`/`WARNING`/`INFO`) and the risk-severity scale
  (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) some curated rule families write
  directly — previously the latter fell through to `UNKNOWN`.
- Duplicate/clustered findings now render as one grouped entry with all
  locations listed, instead of repeating the same rationale once per
  raw finding.
- Classifier prompt now explicitly states it only receives rule metadata,
  not the matched code — reducing confident-sounding but ungrounded
  speculation about code it never saw.
- Fixed a config bug where Bedrock's temperature silently inherited the
  Ollama provider's temperature setting.
