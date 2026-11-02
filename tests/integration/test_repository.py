from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixture_repo import create_fixture_repo
from vulnmirage.errors import RepositoryError
from vulnmirage.ingest.base import build_oracle
from vulnmirage.paths import safe_join
from vulnmirage.repository.cache import RepositoryCache, normalize_repository_url
from vulnmirage.repository.git import (
    git_output,
    run_git,
    status_porcelain,
    tree_hash,
    worktree_digest,
)
from vulnmirage.repository.location_remap import (
    remap_location,
    remap_oracle,
    resolve_oracle_locations,
    verify_oracle_code,
)
from vulnmirage.repository.patch import apply_patch, generate_patch
from vulnmirage.repository.worktree import create_worktree, remove_worktree
from vulnmirage.config import NetworkConfig


@pytest.fixture(scope="module")
def fixture(tmp_path_factory) -> object:
    return create_fixture_repo(tmp_path_factory.mktemp("fixture"))


@pytest.fixture
def network() -> NetworkConfig:
    return NetworkConfig(allowed_clone_domains=["github.com"], allow_local_repositories=True)


def test_local_cache_and_worktree(fixture, tmp_path, network) -> None:
    cache = RepositoryCache(tmp_path / "cache", network)
    repo, cache_path = cache.ensure(fixture.repo_url)
    assert repo.kind == "local"
    assert cache_path.is_dir()
    cache.verify_commit(cache_path, fixture.vulnerable_commit)

    worktree = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "VM-1" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    assert git_output(["rev-parse", "HEAD"], cwd=worktree) == fixture.vulnerable_commit
    assert status_porcelain(worktree) == []
    assert tree_hash(worktree) == git_output(["rev-parse", "HEAD^{tree}"], cwd=worktree)
    digest = worktree_digest(worktree)
    assert len(digest) == 64
    assert worktree_digest(worktree) == digest

    remove_worktree(cache_path, worktree, worktrees_root=tmp_path / "worktrees")
    assert not worktree.exists()


def test_patch_round_trip(fixture, tmp_path, network) -> None:
    cache = RepositoryCache(tmp_path / "cache", network)
    _, cache_path = cache.ensure(fixture.repo_url)
    source = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "src" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    target = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "dst" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    (source / "SECURITY.md").write_text(
        (source / "SECURITY.md").read_text(encoding="utf-8") + "\nThe issue is fixed.\n",
        encoding="utf-8",
        newline="\n",
    )
    (source / "docs" / "new.md").write_text("# New document\n", encoding="utf-8", newline="\n")
    patch_file = source.parent.parent / "patch.diff"
    artifact = generate_patch(source, patch_file)
    assert artifact.patch_sha256
    assert sorted(item.path for item in artifact.files_changed) == ["SECURITY.md", "docs/new.md"]
    assert status_porcelain(target) == []
    apply_patch(target, patch_file)
    assert (target / "docs" / "new.md").read_text(encoding="utf-8") == "# New document\n"
    assert "The issue is fixed." in (target / "SECURITY.md").read_text(encoding="utf-8")


def test_remap_after_comment_insertion(fixture, tmp_path, network) -> None:
    cache = RepositoryCache(tmp_path / "cache", network)
    _, cache_path = cache.ensure(fixture.repo_url)
    clean = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "clean" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    variant = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "variant" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    loc = fixture.entry_locations["E1"]
    ep = loc["ep"]
    co = loc["co"]
    oracle = build_oracle(
        {
            "report_id": "R1",
            "repo_url": fixture.repo_url,
            "commit": fixture.vulnerable_commit,
            "title": "SQL injection",
            "verify": 1,
            "severity": "high",
        },
        [
            {
                "entry_id": "E1",
                "file": ep["file"],
                "line": ep["line"],
                "entry_point": ep,
                "critical_operation": co,
                "trace": [],
                "verify": 1,
            }
        ],
    )
    aligned, _ = resolve_oracle_locations(oracle, clean)
    storage = variant / "app" / "storage.py"
    storage.write_text(
        "# audit note\n# another audit note\n" + storage.read_text(encoding="utf-8"),
        encoding="utf-8",
        newline="\n",
    )
    result = remap_oracle(aligned, clean, variant)
    assert result.report.all_resolved
    path = result.oracle.vulnerabilities[0].paths[0]
    assert path.critical_operation.start_line == aligned.vulnerabilities[0].paths[0].critical_operation.start_line + 2
    assert verify_oracle_code(result.oracle, variant) == []


def test_remap_reports_missing_code(fixture, tmp_path, network) -> None:
    cache = RepositoryCache(tmp_path / "cache", network)
    _, cache_path = cache.ensure(fixture.repo_url)
    clean = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "clean2" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    variant = create_worktree(
        cache_path,
        fixture.vulnerable_commit,
        tmp_path / "worktrees" / "variant2" / "repo",
        worktrees_root=tmp_path / "worktrees",
    )
    from vulnmirage.models import CodeLocation

    location = CodeLocation(file="app/storage.py", start_line=1, end_line=1)
    (variant / "app" / "storage.py").write_text("# replaced\n", encoding="utf-8", newline="\n")
    updated, detail = remap_location(location, clean, variant)
    assert detail.resolved is False
    assert updated.file == "app/storage.py"


def test_cache_rejects_remote_write_commands(fixture, tmp_path, network) -> None:
    cache = RepositoryCache(tmp_path / "cache", network)
    _, cache_path = cache.ensure(fixture.repo_url)
    with pytest.raises(RepositoryError):
        run_git(["push", "origin", "main"], cwd=cache_path)
    with pytest.raises(RepositoryError):
        run_git(["remote", "set-url", "origin", "https://example.com/x.git"], cwd=cache_path)
    with pytest.raises(RepositoryError):
        run_git(["send-email", "HEAD"], cwd=cache_path)


def test_domain_allowlist(network) -> None:
    normalized = normalize_repository_url("https://github.com/acme/demo.git", network)
    assert normalized.host == "github.com"
    with pytest.raises(RepositoryError):
        normalize_repository_url("https://evil.example.com/acme/demo", network)
    with pytest.raises(RepositoryError):
        normalize_repository_url("http://github.com/acme/demo", network)
    with pytest.raises(RepositoryError):
        normalize_repository_url("git@github.com:acme/demo.git", network)


def test_worktree_cannot_escape_root(fixture, tmp_path, network) -> None:
    cache = RepositoryCache(tmp_path / "cache", network)
    _, cache_path = cache.ensure(fixture.repo_url)
    with pytest.raises(Exception):
        create_worktree(
            cache_path,
            fixture.vulnerable_commit,
            tmp_path / "outside" / "repo",
            worktrees_root=tmp_path / "worktrees",
        )


def test_safe_join_operator_path(fixture) -> None:
    with pytest.raises(Exception):
        safe_join(fixture.path, "../escape.txt")

