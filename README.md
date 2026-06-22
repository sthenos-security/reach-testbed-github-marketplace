# ΣREACHABLE For GitHub Marketplace

Repository: `reach-testbed-github-marketplace`

ΣREACHABLE GitHub Marketplace distribution repo.

Made by Sthenos Security.

This repo is the public Marketplace distribution surface for REACHABLE on
GitHub. Use it for proof-backed risk exposure reduction in GitHub Actions. It
uses the reusable
[`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github)
toolkit and defaults to the Codex remediation lane while still allowing the
user to switch AI modes.

The verified Copilot remediation campaign is being packaged after the rebuilt
beta is promoted. Until that beta is the Marketplace source, the runnable
Copilot proof remains in the public Go demo repo and the Marketplace action
should be advertised as the Codex/Claude remediation install surface.

`ΣREACHABLE` is the visual brand mark. The searchable Marketplace action name
is `REACHABLE Risk Exposure Reduction`, and configuration examples
use `REACHABLE` / `reachable` names so users can find and install the action
without typing the sigma character.

The repository also exposes a root GitHub Action metadata file,
[`action.yml`](action.yml), so GitHub can list REACHABLE in the Actions
Marketplace. That Marketplace action delegates to
`sthenos-security/reach-ci-github@v1`, which is the GitHub equivalent of the
GitLab catalog repo importing `reach-ci-gitlab`.

> Do not deploy this application. The vulnerabilities are deliberate synthetic
> fixtures for REACHABLE validation and controlled demos only.

![Reachable CI remediation flow](docs/remediation-flow.svg)

## Repo Role

| Repo | Role |
|------|------|
| [`REACHABLE Risk Exposure Reduction`](https://github.com/marketplace/actions/reachable-risk-exposure-reduction) | GitHub Marketplace action for customer installation |
| [`reachable` GitLab Catalog component](https://gitlab.com/explore/catalog/sthenos-security-public/reach-testbed-gitlab-catalog) | GitLab Catalog component for customer installation |
| `reach-testbed-github-marketplace` | GitHub Marketplace distribution repo plus the configurable root action |
| `reach-ci-github` | Reusable GitHub remediation toolkit |
| `reach-testbed-github-go` | Public GitHub demo repo with explicit provider workflows and scan-only mode |

The full GitHub and GitLab repo map is in [REPOSITORIES.md](REPOSITORIES.md).

## Marketplace And Catalog

Use the public entrypoint for your CI/CD platform:

| Platform | Entrypoint | Purpose |
|----------|------------|---------|
| GitHub Actions | [REACHABLE Risk Exposure Reduction](https://github.com/marketplace/actions/reachable-risk-exposure-reduction) | Marketplace action for proof-backed risk exposure reduction in GitHub Actions |
| GitLab CI/CD | [`reachable` Catalog component](https://gitlab.com/explore/catalog/sthenos-security-public/reach-testbed-gitlab-catalog) | Catalog component for proof-backed risk exposure reduction in GitLab CI/CD |

## GitHub Marketplace Action

GitHub Marketplace publishes the single root action from this repo. The action
defaults to `openai-codex` and exposes the provider switch through `ai-mode`,
so one Marketplace listing can serve Codex and Claude lanes now, then the
hosted Copilot campaign lane after the rebuilt beta is promoted.

Use it like this:

```yaml
name: REACHABLE Risk Exposure Reduction

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

      - name: Reduce risk exposure with REACHABLE
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
the runnable Codex, Claude, and Copilot campaign demos live in
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
| `copilot-github` | `REACHABLE_COPILOT_USER_TOKEN` | None for local scan AI | Hosted GitHub Copilot campaign; post-beta Marketplace packaging |

The Marketplace action delegates to `reach-ci-github@v1`, which sanitizes the
inputs before invoking `reachctl`. Scan jobs derive exactly one provider
argument from `ai-mode`: `--ai-provider openai` for `openai-gpt` and
`openai-codex`, or `--ai-provider claude` for `anthropic-claude`. When
`remediate=true`, `openai-gpt` fails fast with a clear scan-only error. The
`copilot-github` lane is different from the synchronous Codex and Claude lanes:
it dispatches bounded hosted Copilot tasks from REACHABLE evidence, can create
multiple PRs, and relies on separate PR verification plus aggregate campaign
parity proof. It should not be advertised from the Marketplace package until the
rebuilt beta carrying that flow is promoted.

## Copilot Campaign Lane

The Copilot integration is a hosted GitHub Copilot campaign, not a local coding
agent loop. REACHABLE shards the remediation queue by priority and remediation
affinity, dispatches one bounded Copilot task per shard, and expects one
reviewable PR per task.

The campaign acceptance gate is the same product bar as Codex and Claude:

- every Copilot PR has a REACHABLE verification pass
- the aggregate campaign parity check reports no unresolved release-blocking
  signals
- no branch is auto-merged by the Marketplace action

Auto-merge is a roadmap option for customers who request it and accept the
extra repository policy work. The default Marketplace behavior remains
reviewable PRs plus proof artifacts.

## Expected Result

When a customer calls this Marketplace action from their own workflow, it
identifies the exposure that matters, creates a `reachable-remediate-*` branch
when remediation is enabled, runs the selected coding agent with bounded
instructions, rescans that branch for proof, publishes sanitized evidence, and
opens a pull request when GitHub allows automatic PR creation.

The REACHABLE evidence database is the source of truth for the demo verdict.
SARIF is generated for platform compatibility, but it is only an export report.

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

After REACHABLE has produced `repo.db` and SARIF artifacts, validate the
evidence output against the golden baseline:

```bash
python3 ci/validate-expected-results.py \
  --db path/to/repo.db \
  --scan-id 1 \
  --sarif path/to/reachable.sarif
```
