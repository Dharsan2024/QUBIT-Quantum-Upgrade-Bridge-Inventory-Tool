"""`QUBIT_SCAN_ROOTS` is the operator-level boundary a project cannot widen -- `validate_targets`'s
own docstring: "fine for the desktop app, wrong for anything shared." A scan target must be
inside it, with one carve-out: a genuine git URL is cloned fresh by the handler, so it never
existed on this filesystem for the allowlist to have an opinion about.

`is_git_url` decides which branch a target takes, and its check was `startswith(remote schemes)
OR endswith(".git")`. The `endswith(".git")` half is unconditional -- it does not care whether
the string in front of it is a URL at all. A LOCAL path that happens to end in `.git` (a bare
repo, a directory someone named that way, a `../../../elsewhere/target.git` traversal) takes the
git-URL branch, skips the allowlist entirely, and is handed to `git clone` -- which clones a
local path just as readily as a remote one.

Traced end to end (not just at this boundary): `services.py:validate_targets` (router
pre-check) and `handlers.py`'s own re-check both call the same `is_git_url`, and
`_clone_into_workspace` performs no allowlist check of its own -- it trusts the caller
completely. So the bypass reaches `git clone` for real, not merely past a single guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException
from qubit_api.services import is_git_url, validate_targets
from qubit_core.db import ProjectRow


def _project(root_path: str | None = None) -> ProjectRow:
    return ProjectRow(name="t", slug="t", root_path=root_path)


class TestIsGitUrl:
    """The classifier itself, isolated from the allowlist it feeds."""

    def test_a_real_https_url_is_a_git_url(self) -> None:
        assert is_git_url("https://github.com/o/r.git") is True

    def test_a_real_ssh_url_is_a_git_url(self) -> None:
        assert is_git_url("ssh://git@example.com/o/r.git") is True

    def test_an_scp_like_url_is_a_git_url(self) -> None:
        assert is_git_url("git@github.com:o/r.git") is True

    def test_a_local_posix_path_ending_in_dot_git_is_not_a_git_url(self) -> None:
        assert is_git_url("/home/victim/private.git") is False

    def test_a_local_windows_path_ending_in_dot_git_is_not_a_git_url(self) -> None:
        assert is_git_url(r"C:\Users\victim\secrets.git") is False

    def test_a_traversal_ending_in_dot_git_is_not_a_git_url(self) -> None:
        assert is_git_url("../../../victim/repo.git") is False

    def test_an_ordinary_local_path_is_not_a_git_url(self) -> None:
        assert is_git_url("/home/victim/private") is False


class TestValidateTargetsEnforcesTheAllowlistOnEveryLocalPath:
    """The consequence: a local path outside `scan_roots` is refused, REGARDLESS of what it's
    named -- the allowlist must not have a name-based escape hatch."""

    def test_an_ordinary_path_outside_the_allowlist_is_refused(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        with pytest.raises(HTTPException) as exc:
            validate_targets(_project(), [str(outside)], scan_roots=[allowed])

        assert exc.value.status_code == 403

    def test_a_local_path_named_like_a_repo_does_not_bypass_the_allowlist(
        self, tmp_path: Path
    ) -> None:
        """The bug. A path ending in `.git` is still a LOCAL path when it was never cloned from
        anywhere -- naming it that way must not be a way to skip the check above."""
        outside = tmp_path / "outside" / "secret.git"
        outside.parent.mkdir(parents=True)
        outside.mkdir()
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        with pytest.raises(HTTPException) as exc:
            validate_targets(_project(), [str(outside)], scan_roots=[allowed])

        assert exc.value.status_code == 403

    def test_a_local_path_inside_the_allowlist_still_works(self, tmp_path: Path) -> None:
        """The guard against over-correcting: a normal in-bounds target must still pass."""
        inside = tmp_path / "allowed" / "project"
        inside.mkdir(parents=True)

        result = validate_targets(_project(), [str(inside)], scan_roots=[tmp_path / "allowed"])

        assert result == [inside.resolve()]

    def test_a_local_path_inside_the_allowlist_named_like_a_repo_still_works(
        self, tmp_path: Path
    ) -> None:
        """Same near-miss guard, for the `.git`-suffixed case: an IN-bounds target named that
        way must not be refused just because it looks like a URL."""
        inside = tmp_path / "allowed" / "project.git"
        inside.mkdir(parents=True)

        result = validate_targets(_project(), [str(inside)], scan_roots=[tmp_path / "allowed"])

        assert result == [inside.resolve()]

    def test_a_genuine_remote_url_still_bypasses_the_local_existence_check(self) -> None:
        """Not a regression target for this fix: a real URL was never checkable against the
        local filesystem and correctly passes straight through to the handler, which clones it."""
        result = validate_targets(_project(), ["https://github.com/o/r.git"], scan_roots=None)

        assert result == [Path("https://github.com/o/r.git")]
