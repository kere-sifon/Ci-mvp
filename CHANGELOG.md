# Changelog

All notable changes to this project are documented here. Versioning follows
[Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

- **MAJOR** — breaking change to `action.yml`'s inputs/outputs, or a change
  that alters existing behavior consumers depend on.
- **MINOR** — new input, new capability, backwards-compatible.
- **PATCH** — bug fix, no interface change.

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
