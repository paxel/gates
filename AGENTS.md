# gates

The one security and quality standard for every active paxel repository, and the shared
pieces that carry it out. The decisions behind it are in
[docs/adr/0001-one-standard.md](docs/adr/0001-one-standard.md); the standard itself, in a
form the audit reads, is [`standard.toml`](standard.toml).

## Agent skills

### Issue tracker

Issues live as GitHub issues in `paxel/gates`, managed with the `gh` CLI. See
`docs/agents/issue-tracker.md`.

### Triage labels

See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` plus `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Ticket IDs

Prefix `gate`, see `docs/agents/ticket-ids.md`.

## Layout

| Path                 | Holds                                                                                  |
|----------------------|----------------------------------------------------------------------------------------|
| `standard.toml`      | The standard: checks, the stacks they apply to, badges, licences, settings              |
| `.github/workflows/` | The shared workflows other repos call, and gates' own CI, Security, Scorecard, audit    |
| `actions/`           | Composite actions with the gate logic; the shared workflows only wrap them              |
| `scripts/`           | The Python gate scripts and the audit (standard library only)                           |
| `tests/`             | `unittest` tests of the scripts                                                         |
| `configs/`           | The strict lint configs per stack                                                       |
| `templates/`         | What a repo copies: the thin caller workflows, the Scorecard copy, Dependabot, badges   |
| `fixtures/`          | One small project per stack, each run clean (must pass) and with a planted finding (must fail) |

## How a shared workflow finds its scripts

A shared workflow checks gates out at `job.workflow_sha` into `.gates` and runs
`./.gates/actions/<name>`. The scripts are therefore always the ones of the commit the caller
pinned; there is no second version to keep in step.

## Rules

- Every repository has every check of the standard, unless it has nothing for that check to
  look at. "We have no time" or "it is red" is not such a reason.
- A gate that has never been seen red proves nothing: every gate has a fixture with a planted
  finding, and the self-test fails unless that case fails.
- A gate never passes on what it could not read. A missing token, an empty scan or a stack
  without a lockfile is a failure, not a pass.
- An accepted finding carries a reason and a date in the repo's ignore file; the date passing
  makes the gate fail again. Nothing is dismissed in GitHub.
- Scripts use the Python 3.12 standard library only (`.python-version`); the jobs use the
  runner's Python and fail when it differs from the pin.
- Every action is pinned to a full commit SHA with its version in a trailing comment. Every
  workflow starts with `permissions: contents: read`; a job that writes widens it itself.
- A change to the standard is a change to `standard.toml`, the ADR and the CHANGELOG in the
  same commit. Releases are semver tags; callers pin `@<sha> # vX.Y.Z` and Dependabot proposes
  the bump.
- Python is formatted and linted with ruff and checked with `mypy --strict`, like every
  Python repo of the standard.
