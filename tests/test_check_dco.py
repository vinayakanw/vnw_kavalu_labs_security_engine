"""scripts/check_dco.py, tested against a real throw-away git repository."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_dco.py"
ENV = {
    "GIT_AUTHOR_NAME": "Ada Lovelace",
    "GIT_AUTHOR_EMAIL": "ada@example.org",
    "GIT_COMMITTER_NAME": "Ada Lovelace",
    "GIT_COMMITTER_EMAIL": "ada@example.org",
}


def git(repo, *args, env=None):
    import os

    full_env = {**os.environ, **ENV, **(env or {})}
    return subprocess.run(["git", *args], cwd=repo, env=full_env, check=True, capture_output=True, text=True).stdout


@pytest.fixture()
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "f.txt").write_text("base\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base commit")
    return tmp_path


def commit(repo, message, *, sign=False, name=None):
    (repo / "f.txt").write_text(message + "\n", encoding="utf-8")
    git(repo, "add", "-A")
    args = ["commit", "-q", "-m", message] + (["-s"] if sign else [])
    env = {"GIT_AUTHOR_NAME": name} if name else None
    git(repo, *args, env=env)


def run_check(repo):
    return subprocess.run([sys.executable, str(SCRIPT), "main", "HEAD"], cwd=repo, capture_output=True, text=True)


def start_branch(repo):
    git(repo, "checkout", "-q", "-b", "feature")


def test_signed_commits_pass(repo):
    start_branch(repo)
    commit(repo, "feat: first", sign=True)
    commit(repo, "fix: second", sign=True)
    result = run_check(repo)
    assert result.returncode == 0, result.stdout
    assert "2 commit(s) checked" in result.stdout


def test_unsigned_commit_fails_and_names_the_commit_and_the_fix(repo):
    start_branch(repo)
    commit(repo, "feat: signed", sign=True)
    commit(repo, "fix: forgot to sign")
    result = run_check(repo)
    assert result.returncode == 1
    assert "fix: forgot to sign" in result.stdout
    assert "feat: signed" not in result.stdout
    assert "git commit --amend -s" in result.stdout


def test_bot_commits_are_exempt(repo):
    start_branch(repo)
    commit(repo, "chore(deps): bump something", name="dependabot[bot]")
    assert run_check(repo).returncode == 0


def test_merge_commits_are_exempt(repo):
    start_branch(repo)
    commit(repo, "feat: on branch", sign=True)
    git(repo, "checkout", "-q", "main")
    (repo / "g.txt").write_text("other\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "main moved on")
    git(repo, "checkout", "-q", "feature")
    git(repo, "merge", "-q", "--no-ff", "-m", "Merge main into feature", "main")
    # Range is main..HEAD: only the feature commit counts; the merge commit itself must not.
    assert run_check(repo).returncode == 0


def test_trailer_must_look_like_a_real_name_and_email(repo):
    start_branch(repo)
    (repo / "f.txt").write_text("x\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "fix: bogus\n\nSigned-off-by: nobody")
    assert run_check(repo).returncode == 1


def test_bad_ref_is_a_usage_error_not_a_pass(repo):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "no-such-ref", "HEAD"], cwd=repo, capture_output=True, text=True
    )
    assert result.returncode == 2


def test_wrong_argument_count_prints_usage(repo):
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=repo, capture_output=True, text=True)
    assert result.returncode == 2
