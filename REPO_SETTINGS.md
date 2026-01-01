# GitHub repo presentation cheatsheet

Things that improve the repo's public face but can't be committed —
they live in GitHub's UI under **Settings** for the repo. Paste the
suggested values verbatim.

## Settings → General → About

**Description** (≤350 chars, shows under the repo name):

> Cross-platform endpoint forensics suite. Runs locally. Codified
> ethics (10 principles enforced in code). Dual SHA-256+SHA3-256
> hash-chained, ML-DSA-65-signed evidence. 28 detectors including a
> defensive mirror of every offensive kill-chain phase. 15 live intel
> feeds. Local-LLM triage under IC tradecraft. 18 compliance frameworks.

**Website:**

> https://pq-cybarg.github.io/digger/

**Topics** (click the gear icon next to About, then click in the
topics field — these are searchable tags):

```
forensics
incident-response
threat-detection
endpoint-security
endpoint-detection
sigma
mitre-attack
yara
post-quantum-cryptography
ml-dsa
local-llm
compliance
nist-800-53
soc2
iso-27037
fips-140-3
chain-of-custody
threat-intelligence
counter-offensive
decepticon
shai-hulud
firewall-audit
browser-forensics
ethics
opsec
chromium-security
cross-platform
python
macos
linux
windows
```

(GitHub allows up to 20; pick the most relevant 20. The list above is
sorted roughly by relevance.)

## Settings → General → Features

| Feature | Recommended | Why |
|---|---|---|
| Wikis | ✅ Enable | Required to publish `wiki/*.md` |
| Issues | ✅ Enable | Bug reports + feature requests |
| Discussions | ✅ Enable | Questions / community help (separate from issues) |
| Projects | optional | Use if you want a roadmap board |
| Sponsorships | optional | If you want GitHub Sponsors |
| Preserve this repository | ✅ Enable | Arctic Code Vault opt-in |
| Table of contents | ✅ Enable | Auto-TOC for long markdown files |

Under **Pull requests**:

| Setting | Recommended |
|---|---|
| Allow merge commits | ❌ off (rebase / squash only — keeps history linear) |
| Allow squash merging | ✅ on |
| Allow rebase merging | ✅ on |
| Always suggest updating PR branches | ✅ on |
| Automatically delete head branches | ✅ on (cleaner branch list) |

## Settings → Pages

| Setting | Value |
|---|---|
| Source | Deploy from a branch |
| Branch | `gh-pages` / `/` (root) |
| Custom domain | (leave blank unless you have one) |

After enabling, the site goes live at
**https://pq-cybarg.github.io/digger/** within a couple of minutes.

## Settings → Security → Code security and analysis

| Feature | Recommended |
|---|---|
| Private vulnerability reporting | ✅ Enable (required for the workflow in SECURITY.md) |
| Dependency graph | ✅ Enable |
| Dependabot alerts | ✅ Enable |
| Dependabot security updates | ✅ Enable |
| Dependabot version updates | optional |
| Secret scanning | ✅ Enable |
| Push protection | ✅ Enable (refuses pushes containing detected secrets) |
| Code scanning (CodeQL) | ✅ Enable on default branch |

## Settings → Branches → Branch protection rules

Protect `main`:

- ✅ Require a pull request before merging
  - ✅ Require approvals (1 minimum if you have collaborators; can
    skip for solo development)
- ✅ Require status checks to pass before merging
  - Add: any CI job names you set up
- ✅ Require linear history
- ✅ Require signed commits (since the project ships PQC signing, this
  is symbolically consistent — but only useful if you actually GPG-sign)
- ✅ Include administrators (don't exempt yourself)
- ❌ Allow force pushes
- ❌ Allow deletions

Protect `gh-pages`:

- ✅ Restrict pushes that create matching refs (only you / specific
  users can push — prevents accidental gh-pages corruption)
- ✅ Allow force pushes (the sync script appends but force-push may
  be needed for cleanup)

## Settings → Actions → General

| Setting | Value |
|---|---|
| Workflow permissions | Read repository contents and packages permissions (minimum) |
| Allow GitHub Actions to create and approve pull requests | ❌ off (unless you intentionally want bot PRs) |

## Custom social preview image

Settings → General → Social preview → Upload an image (1280×640 px
recommended). digger's logo at `docs/logo.svg` is a starting point;
ImageMagick can rasterize it to a sized PNG:

```bash
brew install librsvg
rsvg-convert -w 1280 -h 640 -a docs/logo.svg > social.png
# Then upload social.png in GitHub UI.
```

If you don't have one, GitHub auto-generates a card from the repo
name + first paragraph of the README.

## Open Graph metadata

Already in `docs/index.html` if you've added it. (Optional polish for
when someone shares the docs site in Slack/Twitter; the gh-pages
content controls the link preview, not the repo page itself.)

## What I can't do for you

These settings all live in the GitHub UI, behind your `pq-cybarg`
login. The repo-settings cheatsheet above is the full set — work
through it once, takes about 15 minutes total.
