<!--
Thank you for contributing! Please read CONTRIBUTING.md first.
The PR title becomes the squash-merge commit, so it must follow Conventional Commits:

  Good:  fix(tls): handle certificates with no notAfter field
  Good:  feat(owasp): detect directory listing (CWE-548)
  Bad:   Update stuff
  Bad:   fixed bug
-->

## What does this change?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Why?

<!-- The problem this solves, or the decision behind the approach. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature or detection check
- [ ] Documentation or tests only
- [ ] Refactor, CI or tooling (no behaviour change)
- [ ] Breaking change (API, scoring, finding types, configuration)

## How was it tested?

<!-- Commands run and results, e.g. `make check` -> all tests passed. For a new check, name the test that covers it. -->

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] Every commit is signed off (`git commit -s`), see [DCO](../DCO)
- [ ] `make check` passes locally (lint and tests)
- [ ] New behaviour has tests, including a negative case, and the tests run **offline**
- [ ] Docs updated (`docs/checks.md` for new finding types, `docs/api.md` for API changes)
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` for user-visible changes
- [ ] No secrets, real targets or real vulnerability data in the diff
- [ ] If this adds a check: it is non-destructive, bounded, and contacts only the target ([safety rules](../CONTRIBUTING.md#safety-rules-for-checks))

## Notes for the reviewer

<!-- Anything non-obvious: trade-offs, follow-ups, areas where you want a closer look. Delete if none. -->
