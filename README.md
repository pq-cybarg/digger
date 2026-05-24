# digger — published documentation site

This is the **`gh-pages`** branch of the [digger](https://github.com/pq-cybarg/digger)
project. It serves the documentation site at:

→  **https://pq-cybarg.github.io/digger/**

The branch is an orphan (no shared history with `main`); it contains
only the rendered, static HTML/CSS/JS that GitHub Pages serves.

## How it gets regenerated

The site source lives under `docs/` on the `main` branch. To regenerate
this branch from the latest `docs/` contents, run from a checkout of
`main`:

```bash
./sync-gh-pages.sh
```

That script:
1. Stashes any in-progress work on your current branch
2. Switches to `gh-pages`
3. Wipes the working tree
4. Copies `docs/*` (minus `_build_sample_report.py`) to the root
5. Adds `.nojekyll` so Pages doesn't run Jekyll
6. Commits the result
7. Switches you back

After it succeeds, push:

```bash
git push origin gh-pages
```

(Force-push isn't typically required — the script appends a normal
commit rather than rewriting history.)

## Enabling Pages

In the repo's Settings → Pages on GitHub:
- **Source:** Deploy from a branch
- **Branch:** `gh-pages` / `/` (root)

Save. First deploy takes a minute or two; subsequent deploys are
near-instant after each push to `gh-pages`.
