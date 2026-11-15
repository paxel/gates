# Security policy

## Supported versions

Only the latest release gets security fixes. A caller pinned to an older release gets the fix
through Dependabot's bump of the pin.

## Reporting a vulnerability

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/paxel/gates/security/advisories/new)
(the repository's **Security** tab, **Report a vulnerability**). Do not open a public issue,
pull request or discussion for it.

Describe what an attacker gains: a gate that can be made to pass on a finding, a script that
runs input as code, a token that leaks. The report and its fix are discussed in that advisory,
which stays private until a release with the fix is out.

## What is already checked

gates is held to its own standard: CodeQL, OpenSSF Scorecard, SonarQube Cloud, the OSV gate,
the alert gate, the coverage ratchet and a self-test that runs the OSV, stack, content,
ratchet and alert gates on clean fixtures (must pass) and planted findings (must fail).
Every release carries a build provenance attestation, its Sigstore bundle and an SBOM.
