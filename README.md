# REACHABLE For GitHub Marketplace

Repository: `reach-testbed-github-marketplace`

REACHABLE GitHub Marketplace distribution repo.

This repo is the public Marketplace distribution surface for REACHABLE on
GitHub. Use it for code exploitability analysis and risk posture reduction in
GitHub Actions. It uses the reusable
[`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github)
toolkit and defaults to the Codex remediation lane while still allowing the
user to switch AI modes.

The repository also exposes a root GitHub Action metadata file,
[`action.yml`](action.yml), so GitHub can list REACHABLE in the Actions
Marketplace. That Marketplace action delegates to
`sthenos-security/reach-ci-github@v1`, which is the GitHub equivalent of the
GitLab catalog repo importing `reach-ci-gitlab`.

> Do not deploy this application. The vulnerabilities are deliberate synthetic
> fixtures for scanner validation and controlled demos only.

![Reachable CI remediation flow](docs/remediation-flow.svg)

## Repo Role

| Repo | Role |
|------|------|
| [`Reachable Security Scan and Remediation`](https://github.com/marketplace/actions/reachable-security-scan-and-remediation) | GitHub Marketplace action for customer installation |
| [`reachable` GitLab Catalog component](https://gitlab.com/explore/catalog/sthenos-security-public/reach-testbed-gitlab-catalog) | GitLab Catalog component for customer installation |
| `reach-testbed-github-marketplace` | GitHub Marketplace distribution repo plus the configurable root action |
| `reach-ci-github` | Reusable GitHub remediation toolkit |
| `reach-testbed-github-go` | Public GitHub demo repo with explicit provider workflows and scan-only mode |

The full GitHub and GitLab repo map is in [REPOSITORIES.md](REPOSITORIES.md).

## Marketplace And Catalog

Use the public entrypoint for your CI/CD platform:

| Platform | Entrypoint | Purpose |
|----------|------------|---------|
| GitHub Actions | [Reachable Security Scan and Remediation](https://github.com/marketplace/actions/reachable-security-scan-and-remediation) | Marketplace action for code exploitability analysis and risk posture reduction in GitHub Actions |
| GitLab CI/CD | [`reachable` Catalog component](https://gitlab.com/explore/catalog/sthenos-security-public/reach-testbed-gitlab-catalog) | Catalog component for code exploitability analysis and risk posture reduction in GitLab CI/CD |

## GitHub Marketplace Action

GitHub Marketplace publishes the single root action from this repo. The action
defaults to `openai-codex` and exposes the provider switch through `ai-mode`,
so one Marketplace listing can serve both Codex and Claude lanes.

Use it like this:

```yaml
name: Reachable Security

on:
  workflow_dispatch:

permissions:
  contents: write
  security-events: write

jobs:
  reachable:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Scan with Reachable
        uses: sthenos-security/reach-testbed-github-marketplace@v1
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          MCP_GITHUB_TOKEN: ${{ secrets.MCP_GITHUB_TOKEN }}
        with:
          ai-mode: openai-codex
          remediate: "true"
          create-pr: "true"
          fail-on: exploitable
          publish-report: "true"

      - name: Upload Reachable artifacts
        if: always()
        uses: actions/upload-artifact@v5
        with:
          name: reachable-ci-artifacts
          path: .reachable/ci-artifacts/**
          if-no-files-found: ignore
```

If you want the toolkit directly without the Marketplace shim, call
[`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github)
instead:

```yaml
jobs:
  reachable:
    uses: sthenos-security/reach-ci-github/.github/workflows/auto-remediate.yml@v1
    with:
      target_branch: main
      remediate: true
      create_pr: true
      ai_mode: openai-codex
      fail_on: exploitable
      proof_fail_on: exploitable
    secrets: inherit
```

GitHub Marketplace indexes actions from a public repository's root
`action.yml`. This repo does not need separate public demo workflows because
the runnable Codex and Claude demos live in
[`reach-testbed-github-go`](https://github.com/sthenos-security/reach-testbed-github-go).

## CI/CD Demo Examples

Use the demo repositories when you want to inspect or run the public sample flow
before wiring REACHABLE into another project:

| Platform | Demo |
|----------|------|
| GitHub Actions | [`reach-testbed-github-go`](https://github.com/sthenos-security/reach-testbed-github-go) |
| GitLab CI/CD | [`reach-testbed-gitlab-go`](https://gitlab.com/sthenos-security-public/reach-testbed-gitlab-go) |

Each demo shows the toolkit-backed full remediation path and a scan-only mode
with remediation disabled.

## CI/CD Toolkits

Use the toolkit repositories when Marketplace or Catalog defaults are not enough:

| Platform | Toolkit | Use it to change |
|----------|---------|------------------|
| GitHub Actions | [`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github) | Branch policy, PR creation, artifacts, Pages proof output, AI lane, or proof thresholds |
| GitLab CI/CD | [`reach-ci-gitlab`](https://gitlab.com/sthenos-security-public/reach-ci-gitlab) | Branch push, MR creation, artifacts, Pages proof output, AI lane, or proof thresholds |

Contact [Sthenos Security](mailto:info@sthenosec.com?subject=Custom%20CI%2FCD%20integration)
for custom CI/CD integration.

## Configure The Pipeline

Use these links when you need options beyond the default Marketplace snippet:

| Need | Link |
|------|------|
| Sthenos Security landing page | [sthenosec.com](https://sthenosec.com/) |
| Public guide and provider map | [CI auto-remediation on sthenosec.com](https://sthenosec.com/resources/auto-remediation) |
| Input defaults | [Defaults](#defaults) |
| AI provider and coding-agent lanes | [AI Modes](#ai-modes) |
| Required GitHub Actions secrets | [Token Setup](#token-setup) |
| Reusable workflow without the Marketplace shim | [`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github) |
| Public GitHub demo repo | [`reach-testbed-github-go`](https://github.com/sthenos-security/reach-testbed-github-go) |

The Marketplace action is the easiest entrypoint. The toolkit repo is the
implementation reference when you need to change branch policy, PR creation,
artifact publication, Pages output, AI lane, or proof thresholds.

## Token Setup

**An AI key must be configured before using Reachable.** Use one public lane
selector, `ai-mode`, and one matching GitHub Actions secret. The same key is
used for Reachable scan AI and the selected remediation coding-agent
integration.

For customer-facing Marketplace runs, configure `MCP_GITHUB_TOKEN` as well. It
materially improves clone/source/package access and should be treated as part
of the expected higher-data-quality setup. Reachable uses this token for
GitHub-hosted source reads, MCP GitHub cloning, and the explicit plain git
clone source path when MCP cannot fetch a package source directly.

| Lane | Secret |
|------|--------|
| `openai-codex` | `OPENAI_API_KEY` |
| `openai-gpt` | `OPENAI_API_KEY` |
| `anthropic-claude` | `ANTHROPIC_API_KEY` |
| Faster clone/source/package context | `MCP_GITHUB_TOKEN` |

Create `MCP_GITHUB_TOKEN` as a fine-grained PAT at
<https://github.com/settings/personal-access-tokens/new>. Select the GitHub
**Resource owner** that owns the source repos Reachable may inspect. Use **Only
select repositories** for a fixed repo set, or **All repositories** when CI must
read any current/future repo for that owner; **Public repositories** is enough
only for public source repos. Grant **Repository permissions -> Contents:
Read-only**; GitHub adds **Metadata: Read-only** automatically. Do not add write,
pull request, workflow, administration, or secret permissions.

GitHub Actions provides the built-in `GITHUB_TOKEN` for checkout, branch push,
artifact upload, Pages publication, SARIF upload, and pull request creation. If
GitHub rejects automatic PR creation, the toolkit keeps the pushed remediation
branch and prints a manual PR path instead of hiding the auth failure.
`MCP_GITHUB_TOKEN` is a read-only source token, not a CI control or remediation
write token.

The GitHub equivalent of the catalog repo's publish path is therefore simpler:
the built-in `GITHUB_TOKEN` is the write path for remediation branches, PRs,
artifacts, and Pages, while `MCP_GITHUB_TOKEN` stays read-only source context.

## Defaults

The Marketplace action defaults to the remediation path:

| Workflow input | Default | Purpose |
|----------------|---------|---------|
| `ai-mode` | `openai-codex` | Default OpenAI + Codex remediation lane. |
| `remediate` | `true` | Run code-changing remediation by default. |
| `rescan-only` | `false` | Run the full baseline, remediation, proof-scan flow. |
| `fail-on` | `exploitable` | Customer-facing scan/proof threshold. |
| `proof-fail-on` | `fail-on` when empty | Post-remediation proof threshold. |
| `create-pr` | `true` | Open a remediation PR after the branch is pushed. |
| `publish-report` | `true` | Build the proof page and structured exports. |
| `publish-pages` | `false` | Leave Pages off unless the caller explicitly wants deployment. |

## AI Modes

| `ai-mode` | Required key | Reachable scan provider | Remediation coding agent |
|-----------|--------------|-------------------------|--------------------------|
| `openai-gpt` | `OPENAI_API_KEY` | OpenAI | Not allowed when remediation is enabled |
| `openai-codex` | `OPENAI_API_KEY` | OpenAI | Codex |
| `anthropic-claude` | `ANTHROPIC_API_KEY` | Anthropic / Claude | Claude Code |

The Marketplace action delegates to `reach-ci-github@v1`, which sanitizes the
inputs before invoking `reachctl`. Scan jobs derive exactly one provider
argument from `ai-mode`: `--ai-provider openai` for `openai-gpt` and
`openai-codex`, or `--ai-provider claude` for `anthropic-claude`. When
`remediate=true`, `openai-gpt` fails fast with a clear scan-only error.

## Expected Result

When a customer calls this Marketplace action from their own workflow, it
creates a `reachable-remediate-*` branch when remediation is enabled, runs the
selected coding agent with bounded instructions, rescans that branch, publishes
sanitized proof artifacts, and opens a pull request when GitHub allows
automatic PR creation.

The scan database is the source of truth for the demo verdict. SARIF is
generated for platform compatibility, but it is only an export report.

## Public Evidence

The Marketplace action produces the same sanitized artifacts as
`reach-ci-github@v1` in the caller repository:

| Artifact | Purpose |
|----------|---------|
| `reachable.sarif` | Compatibility export for GitHub Code Scanning. |
| `reachable-after-final.sarif` | Post-remediation proof scan export. |
| `release-proof/index.html` | Reachable proof page with branch, commit, run, PR, release blockers, defended items, and evidence summaries. |
| `reachable-report.json` | Structured Reachable findings export when available. |
| `reachable-summary.txt` | Plain-text Reachable summary when available. |

The action must not publish raw remediation bundles, prompt text, generated
rule packs, agent transcripts, raw witnesses, or local databases.

## Local Validation

Run the lightweight local checks before publishing changes:

```bash
go test ./...
python3 ci/smoke-db-remediation-proof.py
python3 ci/smoke-pages-summary.py
```

After a Reachable scan has produced `repo.db` and SARIF artifacts, validate the
scanner output against the golden baseline:

```bash
python3 ci/validate-expected-results.py \
  --db path/to/repo.db \
  --scan-id 1 \
  --sarif path/to/reachable.sarif
```
