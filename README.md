# reach-testbed-github-marketplace

REACHABLE GitHub marketplace remediation demo.

This repo is the public marketplace-facing full remediation example. It uses
the reusable [`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github)
toolkit, keeps the Go sample app and proof-page workflow, and defaults to the
Codex remediation lane while still allowing the user to switch AI modes.

> Do not deploy this application. The vulnerabilities are deliberate synthetic
> fixtures for scanner validation and controlled demos only.

![Reachable CI remediation flow](docs/remediation-flow.svg)

## Repo Role

| Repo | Role |
|------|------|
| `reach-testbed-github` | Standalone GitHub scan and Marketplace action demo |
| `reach-testbed-github-marketplace` | Full GitHub marketplace/remediation example |
| `reach-ci-github` | Reusable GitHub remediation toolkit |

## Token Setup

**An AI key must be configured before using Reachable.** Use one public lane
selector, `ai_mode`, and one matching GitHub Actions secret. The same key is
used for Reachable scan AI and the selected remediation coding-agent
integration.

For customer-facing marketplace runs, configure `MCP_GITHUB_TOKEN` as well. It
materially improves clone/source/package context and should be treated as part
of the expected higher-data-quality setup. Reachable uses this token for GitHub
MCP source context and for plain git clone fallback when MCP cannot fetch a
package source directly.

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

## Defaults

The marketplace demo defaults to the strongest remediation path:

| Workflow input | Default | Purpose |
|----------------|---------|---------|
| `ai_mode` | `openai-codex` | Default OpenAI + Codex remediation lane. |
| `remediate` | `true` | Run code-changing remediation by default in the marketplace demo. |
| `rescan_only` | `false` | Run the full baseline, remediation, proof-scan flow. |
| `fail_on` | `exploitable` | Customer-facing scan/proof threshold. |
| `proof_fail_on` | `exploitable` | Explicit post-remediation proof threshold. |
| `fresh_scan` | `true` | Prove a clean public install and scan path. |

## AI Modes

| `ai_mode` | Required key | Reachable scan provider | Remediation coding agent |
|-----------|--------------|-------------------------|--------------------------|
| `openai-gpt` | `OPENAI_API_KEY` | OpenAI | Not allowed when remediation is enabled |
| `openai-codex` | `OPENAI_API_KEY` | OpenAI | Codex |
| `anthropic-claude` | `ANTHROPIC_API_KEY` | Anthropic / Claude | Claude Code |

The toolkit sanitizes inputs before invoking `reachctl`. Scan jobs derive
exactly one provider argument from `ai_mode`: `--ai-provider openai` for
`openai-gpt` and `openai-codex`, or `--ai-provider claude` for
`anthropic-claude`. When `remediate=true`, `openai-gpt` fails fast with a clear
scan-only error.

## Workflows

| Workflow | Purpose |
|----------|---------|
| `Run Demo (Codex)` | Full marketplace remediation demo using `openai-codex`. |
| `Run Demo (Claude)` | Same full demo using `anthropic-claude`. |
| `Reset Demo` | Deletes old `reachable-remediate-*` demo branches before a fresh run. |

The workflow wrappers are intentionally small:

- [.github/workflows/reachable-remediate.yml](.github/workflows/reachable-remediate.yml)
- [.github/workflows/reachable-remediate-claude.yml](.github/workflows/reachable-remediate-claude.yml)

Both call:

```yaml
uses: sthenos-security/reach-ci-github/.github/workflows/auto-remediate.yml@v1
```

## Expected Result

A successful full run creates a `reachable-remediate-*` branch, runs the
selected coding agent with bounded instructions, rescans that branch, publishes
sanitized proof artifacts, and opens a pull request when GitHub allows
automatic PR creation.

The scan database is the source of truth for the demo verdict. SARIF is
generated for platform compatibility, but it is only an export report.

## Public Evidence

The workflow publishes sanitized evidence only:

| Artifact | Purpose |
|----------|---------|
| `reachable.sarif` | Compatibility export for GitHub Code Scanning. |
| `reachable-after-final.sarif` | Post-remediation proof scan export. |
| `release-proof/index.html` | Reachable proof page with branch, commit, run, PR, release blockers, defended items, and evidence summaries. |
| `reachable-report.json` | Structured Reachable findings export when available. |
| `reachable-summary.txt` | Plain-text Reachable summary when available. |

The workflow must not publish raw remediation bundles, prompt text, generated
rule packs, agent transcripts, raw witnesses, or local databases.

## Local Validation

Run the lightweight checks before publishing changes:

```bash
go test ./...
python3 ci/smoke-db-remediation-proof.py
python3 ci/validate-expected-results.py
python3 ci/smoke-pages-summary.py
```
