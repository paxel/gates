# Templates

What a repository copies to meet the standard. Replace `GATES_SHA # GATES_VERSION` with the
commit and the tag of the latest gates release; Dependabot moves both from then on. The audit
compares `scorecard.yml` byte for byte and checks the rest for the calls and files the standard
names.

| Template                            | Goes to                               | Edit                                                  |
|-------------------------------------|---------------------------------------|-------------------------------------------------------|
| `workflows/ci.yml`                  | `.github/workflows/ci.yml`            | keep the jobs of the repo's stacks, delete the rest   |
| `workflows/security.yml`            | `.github/workflows/security.yml`      | nothing                                               |
| `workflows/codeql.yml`              | `.github/workflows/codeql.yml`        | the languages                                         |
| `workflows/fuzz.yml`                | `.github/workflows/fuzz.yml`          | the stack and the targets                             |
| `workflows/release.yml`             | `.github/workflows/release.yml`       | the build jobs                                        |
| `workflows/scorecard.yml`           | `.github/workflows/scorecard.yml`     | nothing; it must stay identical                       |
| `workflows/content-ci.yml`          | `.github/workflows/ci.yml`            | for a repo without app code: kind and paths           |
| `dependabot.yml`                    | `.github/dependabot.yml`              | keep the repo's ecosystems                            |
| `code-scanning-ignores.toml`        | `code-scanning-ignores.toml`          | add accepted findings with reason and date            |
| `osv-scanner.toml`                  | `osv-scanner.toml`                    | add accepted advisories and licence exceptions        |
| `coverage-floors.toml`              | `coverage-floors.toml`                | one part per measured package, floors from a first run |
| `badges.md`                         | top of `README.md`                    | the repo's name, Rust or not, distribution badges     |

Secrets every repository sets: `GATES_ALERTS_TOKEN` (fine-grained, Secret scanning alerts: read)
and `SONAR_TOKEN`.
