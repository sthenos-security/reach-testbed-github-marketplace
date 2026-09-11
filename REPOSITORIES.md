# REACHABLE GitHub And GitLab Repositories

> **Canonical public grid:** [sthenos-security/.github/REACHABLE-REPOSITORIES.md](https://github.com/sthenos-security/.github/blob/main/REACHABLE-REPOSITORIES.md) (public surfaces only).


This file explains the public CI/CD repository layout. The GitHub and GitLab
sets are intentionally symmetrical: each ecosystem has a user-facing
distribution surface, a reusable toolkit, and a Go demo repo that covers both
full remediation and scan-only runs with remediation disabled.

## GitHub Repositories

| Surface | Primary role | Use this when |
|---|---|---|
| [`REACHABLE Risk Exposure Reduction`](https://github.com/marketplace/actions/reachable-risk-exposure-reduction) | GitHub Marketplace action for customer installation. | You want the Marketplace entrypoint for proof-backed risk exposure reduction in GitHub Actions. |
| [`reach-testbed-github-marketplace`](https://github.com/sthenos-security/reach-testbed-github-marketplace) | GitHub Marketplace distribution repo plus the configurable root action. | You need the README, action metadata, or implementation wrapper behind the Marketplace listing. |
| [`reach-ci-github`](https://github.com/sthenos-security/reach-ci-github) | Reusable GitHub Actions toolkit for production auto-remediation. | You want the recommended customer workflow with branch creation, proof scan, optional PR, artifacts, and Pages proof. |
| [`reach-testbed-github-go`](https://github.com/sthenos-security/reach-testbed-github-go) | Public GitHub demo repo. | You want runnable Codex and Claude demos, public source cloning, MCP GitHub cloning, git clone fallback, post-remediation proof, or a scan-only sample with remediation disabled. |

## GitLab Repositories

| Surface | Primary role | GitHub equivalent |
|---|---|---|
| [`REACHABLE Risk Exposure Reduction` Catalog component](https://gitlab.com/explore/catalog/sthenos-security-public/reachable-risk-exposure-reduction) | GitLab Catalog component for customer installation. | GitHub Marketplace action |
| [`reachable-risk-exposure-reduction`](https://gitlab.com/sthenos-security-public/reachable-risk-exposure-reduction) | GitLab CI/CD Catalog repo plus the Catalog component source. | `reach-testbed-github-marketplace` |
| [`reach-ci-gitlab`](https://gitlab.com/sthenos-security-public/reach-ci-gitlab) | Reusable GitLab remediation toolkit. | `reach-ci-github` |
| [`reach-testbed-gitlab-go`](https://gitlab.com/sthenos-security-public/reach-testbed-gitlab-go) | Public GitLab demo repo. | `reach-testbed-github-go` |

## Architecture

```text
Distribution surface
  GitHub Marketplace action / GitLab Catalog component
        |
        v
Distribution repo
  reach-testbed-github-marketplace / reachable-risk-exposure-reduction
        |
        v
Reusable toolkit
  reach-ci-github / reach-ci-gitlab
        |
        v
Demo repo
  reach-testbed-github-go / reach-testbed-gitlab-go
        |
        v
REACHABLE
  install latest beta, scan, build remediation bundle, run selected coding
  agent, rescan, publish sanitized proof
```

The Marketplace action and Catalog component are the discovery and onboarding
surfaces. The Marketplace/Catalog repositories hold their source and README
docs. The toolkit repositories contain the reusable CI implementation. The Go
demo repositories are the public runnable examples and validation targets.

## Token Model

Both ecosystems use one AI provider key plus platform-specific source/control
tokens:

| Purpose | GitHub | GitLab |
|---|---|---|
| OpenAI/Codex lane | `OPENAI_API_KEY` | `OPENAI_API_KEY` |
| Claude lane | `ANTHROPIC_API_KEY` | `ANTHROPIC_API_KEY` |
| Read-only source/package context | `MCP_GITHUB_TOKEN` with Contents read-only | GitLab token only where private source access requires it |
| CI branch/PR/MR control | Built-in `GITHUB_TOKEN` | Prefer `CI_JOB_TOKEN` branch push; use `REACHABLE_GITLAB_TOKEN` only for automatic MR creation |

`MCP_GITHUB_TOKEN` is read-only source context. It is not the token that pushes
remediation branches or opens pull requests.

## Recommended Customer Path

Use the distribution surface first:

- GitHub: Marketplace action for discovery and install, `reach-ci-github` for
  direct toolkit use, and `reach-testbed-github-go` for runnable demos.
- GitLab: Catalog component for the full pipeline, `reach-ci-gitlab` for direct
  toolkit use, and `reach-testbed-gitlab-go` for runnable demos.

For scan-only examples, use the same toolkit-backed Go demo repos with
remediation disabled. The older standalone scan demos are obsolete and are not
part of the supported public onboarding path.
