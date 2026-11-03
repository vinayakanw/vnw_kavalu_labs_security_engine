# Contributing to Kavalu Security Engine

Thank you for helping! Whether it is a typo, a bug report, a new detection check or a better test, it is welcome.
This guide tells you exactly what a good contribution looks like so your time is not wasted.

**Contents**
[Ways to contribute](#ways-to-contribute) ·
[Ground rules](#ground-rules) ·
[Safety rules for checks](#safety-rules-for-checks) ·
[Set up your environment](#set-up-your-environment) ·
[The workflow](#the-workflow) ·
[Commit messages](#commit-messages) ·
[Developer Certificate of Origin](#developer-certificate-of-origin-sign-your-work) ·
[Pull request rules](#pull-request-rules) ·
[Code standards](#code-standards) ·
[Testing](#testing) ·
[Documentation](#documentation) ·
[AI-assisted contributions](#ai-assisted-contributions) ·
[Pro tips](#pro-tips)

## Ways to contribute

| You want to… | Start here |
|---|---|
| Report a bug | [Open a bug report](https://github.com/vinayakanw/vnw_kavalu_security_engine/issues/new/choose) |
| Suggest a feature | Open a feature request, then wait for feedback **before** writing code |
| Propose a new detection check | Open a *new check* proposal; see [docs/extending.md](docs/extending.md) |
| Find something to work on | Issues labelled [`good first issue`](https://github.com/vinayakanw/vnw_kavalu_security_engine/labels/good%20first%20issue) and the [ROADMAP](ROADMAP.md) |
| Improve docs or tests | Just open a pull request |
| Ask a question | [GitHub Discussions](https://github.com/vinayakanw/vnw_kavalu_security_engine/discussions) (see [SUPPORT.md](SUPPORT.md)) |
| Report a **security vulnerability** | **Not here.** Follow [SECURITY.md](SECURITY.md) |

## Ground rules

1. **Be kind.** Everyone must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
2. **Discuss big changes first.** For anything beyond a small fix (new module, new dependency, API change, refactor), open an issue and agree on the approach. It saves you from a rejected pull request.
3. **One logical change per pull request.** A bug fix and an unrelated clean-up are two pull requests. (The Linux kernel calls this "one patch, one idea"; it makes review fast and reverts safe.)
4. **No new runtime dependencies without discussion.** The dependency list is small on purpose, and every package is an attack surface for a security tool.
5. **Never submit secrets, real targets or real vulnerability data.** Not in code, tests, fixtures, screenshots or issue text.

## Safety rules for checks

This tool sends real payloads at real systems, so detection code is held to a stricter bar than ordinary code.
A new check **will be rejected** if it:

- Is destructive: deletes, overwrites or irreversibly changes data, or creates large amounts of it
- Attempts to gain persistent access, exfiltrate data, or execute anything beyond harmless read-only probes (`whoami`/`id`-style)
- Floods the target: it must use bounded request counts and always set a `timeout=`
- Contacts any host other than the target (new third-party calls need an issue and a [SECURITY.md](SECURITY.md#data-sent-to-third-parties) update)
- Crawls beyond the supplied page without an explicit, bounded design discussed in an issue

A good check is deterministic, explainable (a reader can see *why* it fired) and covered by an offline test.

## Set up your environment

You need **Python 3.10 or newer** and Git. (Python 3.11+ is needed only for the optional `pre-commit` hooks.)

```bash
# 1. Fork the repo on GitHub, then clone YOUR fork
git clone https://github.com/<your-username>/vnw_kavalu_security_engine.git
cd vnw_kavalu_security_engine
git remote add upstream https://github.com/vinayakanw/vnw_kavalu_security_engine.git

# 2. Create an isolated environment and install everything
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
make dev                             # runtime + dev dependencies + git hooks

# 3. Prove the baseline is green BEFORE you change anything
make check                           # ruff + the full test suite (~3 s, fully offline)

# 4. Run it
make run                             # http://127.0.0.1:5000
```

No `make` (Windows)? Run the underlying commands: `pip install -r requirements-dev.txt`, `ruff check .`, `python -m pytest`,
`flask --app app run --host 127.0.0.1 --port 5000`. `make help` lists every target.

## The workflow

```bash
git fetch upstream
git checkout -b fix/xss-false-positive upstream/main      # branch from the latest main
# ... edit, test ...
make check                                                 # must pass
git add -A
git commit -s -m "fix(owasp): ignore reflected payloads inside <textarea>"
git push -u origin fix/xss-false-positive
# then open a pull request against vinayakanw/vnw_kavalu_security_engine:main
```

**Branch names:** `<type>/<short-description>`, lowercase with hyphens, using the same types as commits
(`feat/`, `fix/`, `docs/`, `test/`, `chore/`, `refactor/`, `ci/`).

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/). Because pull requests are **squash-merged**, your
**PR title** becomes the commit on `main`, so it must follow the format too.

```text
<type>(<scope>): <summary in the imperative, lower case, no trailing period>

<optional body: WHY this change is needed, and anything non-obvious>
```

| Type | Use for |
|---|---|
| `feat` | A user-visible feature or a new detection check |
| `fix` | A bug fix (including false positives/negatives) |
| `docs` | Documentation only |
| `test` | Adding or fixing tests |
| `refactor` | Code change that alters no behaviour |
| `perf` | Performance improvement |
| `ci` / `build` | Workflows, Docker, packaging |
| `chore` | Maintenance, dependency bumps |
| `security` | A security fix (after coordinated disclosure) |

**Scopes:** `scanner`, `owasp`, `tls`, `recon`, `browser`, `burp`, `report`, `api`, `ui`, `scoring`, `docker`, `ci`, `docs`, `deps`.

| Good | Bad |
|---|---|
| `feat(owasp): detect directory listing (CWE-548)` | `Added new check` |
| `fix(tls): handle certificates with no notAfter field` | `fixed bug` |
| `docs(api): document the SSE timeout event` | `Update api.md` |
| `test(report): assert HTML output escapes finding titles` | `tests` |

Describe **why**, not just what. A reviewer reading `git log` in two years should understand the decision.

## Developer Certificate of Origin (sign your work)

Every commit must carry a `Signed-off-by:` line. This is the same lightweight process the Linux kernel uses
instead of a contributor licence agreement. It is your statement that you wrote the change (or have the right
to submit it) under this project's [MIT licence](LICENSE). Read the short [DCO](DCO) text once.

Signing is one flag:

```bash
git commit -s -m "fix(owasp): ..."        # adds: Signed-off-by: Your Name <you@example.com>
```

Use your **real name**; anonymous and pseudonymous sign-offs are not accepted. Forgot? Fix it:

```bash
git commit --amend -s --no-edit           # the latest commit
git rebase --signoff upstream/main        # every commit on your branch
git push --force-with-lease               # update the pull request
```

CI runs `scripts/check_dco.py` on every pull request and tells you which commits are missing the line.
Merge commits and bot commits (Dependabot) are exempt.

## Pull request rules

The pull request template contains this checklist; please tick it honestly.

- [ ] The PR title follows Conventional Commits (it becomes the squash commit)
- [ ] Every commit is signed off (`git commit -s`)
- [ ] `make check` passes locally (lint, formatting and tests)
- [ ] New behaviour has tests, **including a negative case**, and the tests run **offline**
- [ ] Docs are updated (`docs/checks.md` for any new finding type, `docs/api.md` for API changes)
- [ ] `CHANGELOG.md` has a line under `## [Unreleased]` for any user-visible change
- [ ] No secrets, real targets or real vulnerability data anywhere in the diff
- [ ] If it adds a check: it meets the [safety rules](#safety-rules-for-checks)

How review works:

- A maintainer aims to respond within **7 days**. This is a volunteer project; a polite ping after that is welcome.
- Keep your branch up to date with `main` and respond to review comments with commits (we squash on merge, so no need to squash yourself).
- Small, focused pull requests are reviewed first.
- Pull requests that stay inactive for 30 days after a review may be closed; you can always reopen.

## Code standards

- **Python 3.10+** compatible. CI runs 3.10, 3.11 and 3.12.
- **Lint and format:** `ruff check .` and `ruff format --check .` must both pass. `make fix` repairs most problems and formats the code. The line length limit is 120 and is enforced.
- **Style:** follow the surrounding code. Add type hints to new public functions and a docstring explaining *why*, not just *what*.
- **Findings** are plain dicts following the [schema](docs/extending.md#1-the-finding-schema). Never set `owasp`/`cwe` yourself; add the type to `TYPE_TO_OWASP`.
- **Errors:** a probe that fails means "no finding", never an unhandled exception.
- **Whitespace:** `.editorconfig` is honoured by most editors; the `pre-commit` hooks fix the rest.
- **Do not reformat code you are not otherwise changing.** It makes review impossible.

## Dashboard changes

The dashboard is three small files: `index.html`, `static/style.css` and `static/app.js`. The rules are strict because
the page shows data from websites we scan:

- Load nothing from other websites: no CDN, no web fonts, no analytics. System fonts only.
- No inline `<script>`, `<style>`, `style="..."` or `onclick="..."`. The page is served with a strict Content-Security-Policy that would block them.
- **Never** insert scan data as HTML. In `app.js`, build elements with the `h()` helper (text nodes only). `innerHTML` is not allowed.
- Keep text readable: every text colour must have at least 4.5:1 contrast. The test suite checks the palette.
- Keep the wording plain and true to what the engine really does.

`tests/test_dashboard.py` checks these rules on every run. `make test-ui` goes further: it loads the real page in a simulated
browser (jsdom), runs a real scan against the practice target and checks the results. It needs Node.js 22.22.2 or newer; the
application itself does not. Optional: `npx prettier --write static` formats the script and stylesheet (configuration in `.prettierrc.json`).

## Testing

- The suite is **offline by design**. A test must never contact the public internet. The recon module's IP lookup is stubbed in `tests/test_end_to_end.py`; follow that pattern.
- Detection logic is tested against the local, deliberately vulnerable server in [`tests/vulnerable_server.py`](tests/vulnerable_server.py). Extend it rather than scanning a real site.
- Tests must not write into the real `reports/` or `logs/` (an autouse fixture redirects them).
- Every bug fix needs a regression test that **fails without the fix**.
- Run one file with `python -m pytest tests/test_owasp_mapping.py -q`; coverage with `make cov`; the browser-level dashboard test with `make test-ui`.

## Documentation

If your change affects what users see, update the docs in the same pull request. Docs are checked by CI:
every finding type must appear in [docs/checks.md](docs/checks.md#finding-types), and relative links must resolve.

## AI-assisted contributions

Using AI tools is fine, but **you** are the author and are responsible for every line.
Understand what you submit, run it, test it, and mention substantial AI assistance in the PR description.
Large unreviewed AI-generated changes will be closed.

## Pro tips

- **Start small.** A first PR that fixes a typo or adds a test teaches you the workflow at low risk.
- **Sync your fork** before starting work: `git fetch upstream && git checkout main && git merge --ff-only upstream/main`.
- **Reproduce first.** For bug fixes, write the failing test, then the fix.
- **Use the fixture, not the internet.** If you need a new behaviour to detect, add a route to the local test server.
- **Ask early.** An issue titled "I'd like to work on X, is this the right approach?" is always welcome.

## Recognition

Contributors are credited in release notes and in the repository's contributor graph.

Thank you for contributing.
