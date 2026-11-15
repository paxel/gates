# Issue tracker: GitHub

Issues for this repo live as GitHub issues in `paxel/gates`. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`.
- **List issues**: `gh issue list --state open --json number,title,labels` with `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v`; `gh` does this automatically inside a clone. This repo's
remote is `git@github.com:paxel/gates.git`.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Audit issues

The weekly audit opens one issue per drifting repository in that repository, titled
`Drift from the paxel/gates standard`, and updates it on every run. Those issues live in the
audited repositories, not here.
