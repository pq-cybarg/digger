# Wiki source files

This directory holds the markdown source for the GitHub wiki at:
**https://github.com/pq-cybarg/digger/wiki**

The wiki is a separate git repo (`pq-cybarg/digger.wiki.git`) — these
files are kept here in the main repo so they live in version control
alongside the code they describe, and so PR review covers
documentation drift.

## How to publish

1. Enable the wiki for the repo (one-time):
   - Settings → Features → check **Wikis**

2. Clone the wiki repo:
   ```bash
   git clone git@github-pq-cybarg:pq-cybarg/digger.wiki.git
   cd digger.wiki
   ```

3. Copy the wiki source files in:
   ```bash
   cp ../digger/wiki/*.md ./
   git add .
   git commit -m "wiki: initial publish from main repo's wiki/"
   git push origin master
   ```

4. The wiki lives at `Home.md`; GitHub auto-renders any other `.md`
   file in the repo as `https://github.com/pq-cybarg/digger/wiki/<Page-Name>`.

## How to update

After editing any `wiki/*.md` file in the main repo, re-run step 3.

A future improvement: extend `sync-gh-pages.sh` into a generic
`sync-published.sh` that mirrors both gh-pages AND the wiki on push.
For now they're separate.

## Why both gh-pages and wiki?

- **gh-pages** (the docs site) — long-form, structured documentation
  with the shared chrome/sidebar/search. Authoritative reference.
- **wiki** — quick-reference cheatsheets, FAQ, glossary, community
  edits. Lower bar, less polish, faster to update.

They complement each other. Wiki pages link back to gh-pages for
depth; gh-pages doesn't link to the wiki to avoid coupling.
