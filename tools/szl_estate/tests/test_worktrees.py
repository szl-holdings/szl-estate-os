"""Synthetic metadata-only checkout discovery tests.

These fixtures never invoke Git or inspect an existing checkout. Git process
responses are in-memory streams, and all filesystem fixtures are temporary.
"""

from __future__ import annotations

import builtins
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import szl_estate.worktrees as wt


OID_A = "a" * 40
OID_B = "b" * 40
REPO_NAME = "github:szl-holdings/engine"
REMOTE_URL = "https://github.com/szl-holdings/engine.git"
OBSERVED_AT = "2026-09-30T12:00:00Z"


def make_checkout(root: Path, *, head: str = OID_A) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git_dir = root / ".git"
    (git_dir / "objects").mkdir(parents=True)
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "HEAD").write_text(head + "\n", encoding="ascii")
    (git_dir / "config").write_text(
        '[core]\nrepositoryformatversion = 0\n'
        '[remote "origin"]\nurl = ' + REMOTE_URL + "\n",
        encoding="ascii",
    )
    return git_dir


class _InputBuffer(io.BytesIO):
    """Keep the bytes available after a subprocess writer closes stdin."""

    def close(self) -> None:
        self.was_closed = True


class _OutputBuffer(io.BytesIO):
    def __init__(self, output: bytes):
        super().__init__(output)
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)


class _FakeProcess:
    def __init__(self, output: bytes, *, returncode: int = 0, timeout: bool = False):
        self.stdin = _InputBuffer()
        self.stdout = _OutputBuffer(output)
        self.returncode = returncode
        self.timeout = timeout
        self.killed = False
        self.wait_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("synthetic-git", timeout)
        return self.returncode

    def poll(self) -> int | None:
        return None if self.timeout and not self.killed else self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def terminate(self) -> None:
        self.kill()

    def __enter__(self) -> "_FakeProcess":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class WorktreeMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        # Windows' default temp root contains AppData, an intentionally denied
        # discovery ancestor. Keep only synthetic fixtures beside this test.
        self.temporary = tempfile.TemporaryDirectory(
            prefix="szl-worktree-test-", dir=Path(__file__).absolute().parent
        )
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def collect(self, *roots: Path):
        with mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")):
            return wt.collect_worktrees(roots, observed_at_utc=OBSERVED_AT)

    def test_empty_default_performs_no_home_scan_or_process_launch(self) -> None:
        forbidden = AssertionError("default inventory must not discover personal paths")
        with (
            mock.patch.object(Path, "home", side_effect=forbidden),
            mock.patch("os.scandir", side_effect=forbidden),
            mock.patch("builtins.open", side_effect=forbidden),
            mock.patch("io.open", side_effect=forbidden),
            mock.patch("subprocess.Popen", side_effect=forbidden),
            mock.patch("subprocess.run", side_effect=forbidden),
        ):
            inventory = wt.collect_worktrees(observed_at_utc=OBSERVED_AT)
        self.assertEqual(inventory.observations, ())
        self.assertEqual(inventory.counts["roots_requested"], 0)
        self.assertFalse(inventory.to_dict()["estate_ready"])

    def test_detached_head_is_read_from_metadata(self) -> None:
        git_dir = make_checkout(self.base / "checkout")
        head, code = wt._head_oid(git_dir, git_dir, (self.base,))
        self.assertEqual(head, OID_A)
        self.assertIsInstance(code, str)

    def test_symbolic_head_resolves_one_loose_ref(self) -> None:
        git_dir = make_checkout(self.base / "checkout", head="ref: refs/heads/main")
        (git_dir / "refs" / "heads" / "main").write_text(OID_B + "\n", encoding="ascii")
        head, _ = wt._head_oid(git_dir, git_dir, (self.base,))
        self.assertEqual(head, OID_B)

    def test_symbolic_head_resolves_packed_ref_without_objects(self) -> None:
        git_dir = make_checkout(self.base / "checkout", head="ref: refs/heads/main")
        (git_dir / "packed-refs").write_text(
            "# pack-refs with: peeled fully-peeled sorted\n"
            + OID_A + " refs/heads/other\n"
            + OID_B + " refs/heads/main\n",
            encoding="ascii",
        )
        head, _ = wt._head_oid(git_dir, git_dir, (self.base,))
        self.assertEqual(head, OID_B)

    def test_sha256_detached_head_is_supported(self) -> None:
        oid = "c" * 64
        git_dir = make_checkout(self.base / "checkout", head=oid)
        head, _ = wt._head_oid(git_dir, git_dir, (self.base,))
        self.assertEqual(head, oid)

    def test_duplicate_packed_refs_and_symbolic_ref_loops_are_unknown(self) -> None:
        git_dir = make_checkout(self.base / "checkout", head="ref: refs/heads/main")
        (git_dir / "packed-refs").write_text(
            OID_A + " refs/heads/main\n" + OID_B + " refs/heads/main\n",
            encoding="ascii",
        )
        head, _ = wt._head_oid(git_dir, git_dir, (self.base,))
        self.assertIsNone(head)
        (git_dir / "refs" / "heads" / "main").write_text(
            "ref: refs/heads/main\n", encoding="ascii"
        )
        head, _ = wt._head_oid(git_dir, git_dir, (self.base,))
        self.assertIsNone(head)

    def test_malformed_head_and_ref_escape_remain_unknown(self) -> None:
        git_dir = make_checkout(self.base / "checkout")
        for value in (
            "not-an-object-id",
            "ref: ../../private-data",
            "ref: refs/heads/../../private-data",
            "ref: /private-data",
            "ref: refs/heads/main\n" + OID_A,
        ):
            with self.subTest(value=value):
                (git_dir / "HEAD").write_text(value + "\n", encoding="ascii")
                head, _ = wt._head_oid(git_dir, git_dir, (self.base,))
                self.assertIsNone(head)

    def test_observation_never_claims_dirty_state_or_estate_readiness(self) -> None:
        checkout = self.base / "checkout"
        make_checkout(checkout)
        inventory = self.collect(checkout)
        self.assertEqual(len(inventory.observations), 1)
        observation = inventory.observations[0]
        self.assertEqual(observation.checkout_id, "checkout-0001")
        self.assertEqual(observation.root_index, 0)
        self.assertEqual(observation.head, OID_A)
        self.assertEqual(observation.repo_name, REPO_NAME)
        self.assertIsNone(observation.dirty)
        self.assertEqual(observation.dirty_status, wt.EvidenceStatus.UNKNOWN)
        self.assertEqual(observation.status, wt.EvidenceStatus.PARTIAL)
        self.assertFalse(inventory.to_dict()["estate_ready"])
        self.assertNotIn(str(self.base), str(inventory.to_dict()))

    def test_linked_gitfile_and_commondir_stay_within_explicit_root(self) -> None:
        root = self.base / "estate"
        checkout = root / "linked"
        checkout.mkdir(parents=True)
        common = root / "control"
        git_dir = common / "worktrees" / "linked"
        git_dir.mkdir(parents=True)
        (common / "objects").mkdir()
        (common / "refs" / "heads").mkdir(parents=True)
        (common / "refs" / "heads" / "main").write_text(OID_B + "\n", encoding="ascii")
        (common / "config").write_text(
            '[remote "origin"]\nurl = ' + REMOTE_URL + "\n", encoding="ascii"
        )
        (checkout / ".git").write_text("gitdir: ../control/worktrees/linked\n", encoding="ascii")
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
        (git_dir / "commondir").write_text("../..\n", encoding="ascii")
        with mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")) as query:
            inventory = wt.collect_worktrees((root,), observed_at_utc=OBSERVED_AT)
        self.assertEqual(len(inventory.observations), 1)
        self.assertEqual(inventory.observations[0].head, OID_B)
        self.assertEqual(inventory.observations[0].repo_name, REPO_NAME)
        self.assertEqual(Path(query.call_args.args[0]), common / "config")

    def test_gitfile_escape_does_not_inspect_target_or_query_origin(self) -> None:
        allowed = self.base / "allowed"
        allowed.mkdir()
        outside = make_checkout(self.base / "outside")
        (allowed / ".git").write_text("gitdir: " + str(outside) + "\n", encoding="utf-8")
        original_open = os.open

        def bounded_open(path, *args, **kwargs):
            self.assertTrue(Path(path).is_relative_to(allowed), "outside metadata opened")
            return original_open(path, *args, **kwargs)

        with (
            mock.patch("os.open", side_effect=bounded_open),
            mock.patch.object(wt, "_query_origin", side_effect=AssertionError("escaped config")),
        ):
            inventory = wt.collect_worktrees((allowed,), observed_at_utc=OBSERVED_AT)
        self.assertTrue(all(item.head is None and item.repo_name is None for item in inventory.observations))
        self.assertNotIn(str(outside), str(inventory.to_dict()))

    def test_contained_gitfile_target_without_git_layout_does_not_open_working_files(self) -> None:
        root = self.base / "estate"
        checkout = root / "checkout"
        ordinary = root / "ordinary"
        checkout.mkdir(parents=True)
        ordinary.mkdir()
        marker = checkout / ".git"
        marker.write_text("gitdir: ../ordinary\n", encoding="ascii")
        (ordinary / "HEAD").write_text(OID_B + "\n", encoding="ascii")
        (ordinary / "config").write_text(
            '[remote "origin"]\nurl = ' + REMOTE_URL + "\n", encoding="ascii"
        )
        (ordinary / "payload.txt").write_text("ordinary working content", encoding="ascii")
        original_open = os.open

        def marker_only_open(path, *args, **kwargs):
            self.assertEqual(Path(path), marker, "ordinary pointed files must not be opened")
            return original_open(path, *args, **kwargs)

        with (
            mock.patch("os.open", side_effect=marker_only_open),
            mock.patch.object(wt, "_query_origin", side_effect=AssertionError("ordinary config queried")) as query,
        ):
            inventory = wt.collect_worktrees((root,), observed_at_utc=OBSERVED_AT)
        query.assert_not_called()
        self.assertEqual(len(inventory.observations), 1)
        self.assertIsNone(inventory.observations[0].head)
        self.assertIsNone(inventory.observations[0].repo_name)

    def test_commondir_escape_does_not_query_external_config(self) -> None:
        allowed = self.base / "allowed"
        git_dir = make_checkout(allowed, head="ref: refs/heads/main")
        outside = make_checkout(self.base / "outside")
        (outside / "refs" / "heads" / "main").write_text(OID_B + "\n", encoding="ascii")
        (git_dir / "commondir").write_text(str(outside) + "\n", encoding="utf-8")
        original_open = os.open

        def bounded_open(path, *args, **kwargs):
            self.assertTrue(Path(path).is_relative_to(allowed), "outside metadata opened")
            return original_open(path, *args, **kwargs)

        with (
            mock.patch("os.open", side_effect=bounded_open),
            mock.patch.object(wt, "_query_origin", side_effect=AssertionError("escaped config")),
        ):
            inventory = wt.collect_worktrees((allowed,), observed_at_utc=OBSERVED_AT)
        self.assertTrue(all(item.head is None and item.repo_name is None for item in inventory.observations))

    def test_windows_reparse_metadata_is_rejected_without_privileged_symlink_creation(self) -> None:
        checkout = self.base / "checkout"
        git_dir = make_checkout(checkout)
        original_stat, original_lstat = os.stat, os.lstat

        target = git_dir

        def marked(result, path):
            if Path(path) != target:
                return result
            attributes = {name: getattr(result, name) for name in dir(result) if name.startswith("st_")}
            attributes["st_file_attributes"] = attributes.get("st_file_attributes", 0) | 0x400
            return SimpleNamespace(**attributes)

        def fake_stat(path, *args, **kwargs):
            return marked(original_stat(path, *args, **kwargs), path)

        def fake_lstat(path, *args, **kwargs):
            return marked(original_lstat(path, *args, **kwargs), path)

        for target in (git_dir, checkout):
            with (
                self.subTest(component=target.name),
                mock.patch("os.stat", side_effect=fake_stat),
                mock.patch("os.lstat", side_effect=fake_lstat),
                mock.patch.object(wt, "_query_origin", side_effect=AssertionError("reparse config")),
            ):
                inventory = wt.collect_worktrees((checkout,), observed_at_utc=OBSERVED_AT)
            self.assertTrue(all(item.head is None and item.repo_name is None for item in inventory.observations))

    def test_symlink_mode_metadata_is_rejected_without_following_it(self) -> None:
        checkout = self.base / "checkout"
        git_dir = make_checkout(checkout)
        original_lstat = Path.lstat

        def fake_lstat(path, *args, **kwargs):
            result = original_lstat(path, *args, **kwargs)
            if Path(path) != git_dir:
                return result
            attributes = {name: getattr(result, name) for name in dir(result) if name.startswith("st_")}
            attributes["st_mode"] = stat.S_IFLNK | 0o777
            return SimpleNamespace(**attributes)

        with (
            mock.patch.object(Path, "lstat", new=fake_lstat),
            mock.patch.object(wt, "_query_origin", side_effect=AssertionError("symlink config")),
        ):
            inventory = wt.collect_worktrees((checkout,), observed_at_utc=OBSERVED_AT)
        self.assertTrue(all(item.head is None and item.repo_name is None for item in inventory.observations))

    def test_working_file_contents_are_never_opened(self) -> None:
        checkout = self.base / "checkout"
        git_dir = make_checkout(checkout)
        (checkout / "README.md").write_text("synthetic working content", encoding="ascii")
        (checkout / ".env").write_text("SYNTHETIC_SECRET=never-read", encoding="ascii")
        (checkout / "script.py").write_text("raise RuntimeError('never execute')", encoding="ascii")
        permitted = {git_dir / "HEAD", git_dir / "config"}
        original_open, original_io_open, original_os_open = builtins.open, io.open, os.open

        def check(path):
            if isinstance(path, int):
                return
            if Path(os.fspath(path)) not in permitted:
                raise AssertionError("unexpected content read: " + str(path))

        def guarded_open(path, *args, **kwargs):
            check(path)
            return original_open(path, *args, **kwargs)

        def guarded_io_open(path, *args, **kwargs):
            check(path)
            return original_io_open(path, *args, **kwargs)

        def guarded_os_open(path, flags, *args, **kwargs):
            check(path)
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT), 0)
            return original_os_open(path, flags, *args, **kwargs)

        with (
            mock.patch("builtins.open", side_effect=guarded_open),
            mock.patch("io.open", side_effect=guarded_io_open),
            mock.patch("os.open", side_effect=guarded_os_open),
            mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")),
        ):
            inventory = wt.collect_worktrees((checkout,), observed_at_utc=OBSERVED_AT)
        self.assertEqual(inventory.observations[0].head, OID_A)

    def test_denied_directories_are_not_descended(self) -> None:
        checkout = self.base / "checkout"
        make_checkout(checkout)
        denied_names = (
            "node_modules", ".ssh", ".aws", ".codex", ".agents", "sessions",
            "AppData", ".venv", "venv", "env", "__pycache__", "lfs",
            "weights", "checkpoints", "datasets", "dataset_rows", "cache",
            "caches", ".env.backup",
        )
        denied = {checkout / name for name in denied_names}
        for path in denied:
            path.mkdir()
            (path / "sentinel").write_text("do not inspect", encoding="ascii")
        denied_files = ("model.safetensors", "weights.bin", "data.parquet", "rows.jsonl", "archive.tar.gz")
        for name in denied_files:
            (checkout / name).write_text("do not inspect", encoding="ascii")
        scanned: list[Path] = []
        original_scandir = os.scandir

        def recording_scandir(path):
            scanned.append(Path(path))
            return original_scandir(path)

        with (
            mock.patch("os.scandir", side_effect=recording_scandir),
            mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")),
        ):
            inventory = wt.collect_worktrees((checkout,), observed_at_utc=OBSERVED_AT)
        self.assertFalse(denied.intersection(scanned))
        self.assertGreaterEqual(inventory.counts["excluded_paths"], len(denied_names) + len(denied_files))

    def test_discovery_and_checkout_counts_respect_caps(self) -> None:
        root = self.base / "estate"
        for name in ("a", "b", "c", "d"):
            make_checkout(root / name)
        with (
            mock.patch.object(wt, "MAX_DISCOVERY_DIRS", 3),
            mock.patch.object(wt, "MAX_CHECKOUTS", 2),
            mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")),
        ):
            inventory = wt.collect_worktrees((root,), observed_at_utc=OBSERVED_AT)
        self.assertLessEqual(inventory.counts["candidate_dirs_examined"], 3)
        self.assertLessEqual(len(inventory.observations), 2)
        self.assertFalse(inventory.to_dict()["discovery_complete"])

    def test_secret_and_session_paths_are_excluded_from_walks_and_explicit_roots(self) -> None:
        checkout = self.base / "checkout"
        git_dir = make_checkout(checkout)
        denied_directories = (
            "credential", "credentials", "secret", "secrets", "token", "tokens",
            "session", "sessionlogs", "password", "passwords", "auth",
            "authentication", "oauth", "apikey", "api-key", "api_key",
            "api.key", "API KEY", "api__key", ".config", ".azure",
        )
        for name in denied_directories:
            child = checkout / name
            make_checkout(child)
            (child / "sentinel.txt").write_text("synthetic secret; never read", encoding="ascii")
        denied_files = (
            ".netrc", ".git-credentials", ".npmrc", ".pypirc", "id_rsa",
            "id_ed25519", "certificate.pem", "private.key", "client.p12",
            "bundle.pfx", "store.keystore",
        )
        for name in denied_files:
            (checkout / name).write_text("synthetic secret; never read", encoding="ascii")
        permitted_metadata = {git_dir / "HEAD", git_dir / "config"}
        original_open, original_scandir = os.open, os.scandir

        def metadata_only_open(path, *args, **kwargs):
            self.assertIn(Path(path), permitted_metadata, "secret or session content opened")
            return original_open(path, *args, **kwargs)

        def checkout_only_scandir(path):
            self.assertEqual(Path(path), checkout, "secret or session directory descended")
            return original_scandir(path)

        with (
            mock.patch("os.open", side_effect=metadata_only_open),
            mock.patch("os.scandir", side_effect=checkout_only_scandir),
            mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")) as query,
        ):
            inventory = wt.collect_worktrees((checkout,), observed_at_utc=OBSERVED_AT)
            self.assertEqual(len(inventory.observations), 1)
            self.assertEqual(inventory.observations[0].head, OID_A)
            self.assertEqual(query.call_count, 1)
            self.assertGreaterEqual(
                inventory.counts["excluded_paths"], len(denied_directories) + len(denied_files)
            )
            query.reset_mock()
            denied_roots = tuple(checkout / name for name in denied_directories)
            denied_inventory = wt.collect_worktrees(denied_roots, observed_at_utc=OBSERVED_AT)
            self.assertEqual(denied_inventory.observations, ())
            self.assertEqual(denied_inventory.counts["roots_accessible"], 0)
            self.assertGreaterEqual(denied_inventory.counts["excluded_paths"], len(denied_roots))
            query.assert_not_called()

    def test_checkout_walk_respects_path_budget(self) -> None:
        checkout = self.base / "checkout"
        make_checkout(checkout)
        for number in range(10):
            (checkout / ("file-" + str(number))).touch()
        with (
            mock.patch.object(wt, "MAX_CHECKOUT_PATHS", 3),
            mock.patch.object(wt, "MAX_TOTAL_PATHS", 3),
            mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")),
        ):
            inventory = wt.collect_worktrees((checkout,), observed_at_utc=OBSERVED_AT)
        self.assertLessEqual(inventory.counts["paths_counted"], 3)
        self.assertLessEqual(inventory.observations[0].counts["paths_counted"], 3)
        self.assertFalse(inventory.to_dict()["discovery_complete"])

    def test_discovery_depth_cap_remains_partial(self) -> None:
        root = self.base / "estate"
        make_checkout(root / "one" / "two")
        with (
            mock.patch.object(wt, "MAX_DISCOVERY_DEPTH", 1),
            mock.patch.object(wt, "_query_origin", side_effect=AssertionError("too deep checkout")),
        ):
            inventory = wt.collect_worktrees((root,), observed_at_utc=OBSERVED_AT)
        self.assertEqual(inventory.observations, ())
        self.assertFalse(inventory.to_dict()["discovery_complete"])

    def test_discovery_and_checkout_walk_share_the_total_path_budget(self) -> None:
        root = self.base / "estate"
        for name in ("a", "b"):
            checkout = root / name
            make_checkout(checkout)
            (checkout / "one.txt").touch()
            (checkout / "two.txt").touch()
        with (
            mock.patch.object(wt, "MAX_TOTAL_PATHS", 4),
            mock.patch.object(wt, "_query_origin", return_value=(REPO_NAME, "NONE")),
        ):
            inventory = wt.collect_worktrees((root,), observed_at_utc=OBSERVED_AT)
        self.assertLessEqual(
            inventory.counts["paths_counted"] + inventory.counts["discovery_entries_examined"],
            4,
        )
        self.assertFalse(inventory.to_dict()["discovery_complete"])

    def test_directory_entry_cap_remains_partial(self) -> None:
        root = self.base / "estate-cap"
        root.mkdir()
        for name in ("a", "b", "c"):
            (root / name).mkdir()
        with (
            mock.patch.object(wt, "MAX_DIRECTORY_ENTRIES", 2),
            mock.patch.object(wt, "_query_origin", side_effect=AssertionError("unbounded directory")),
        ):
            inventory = wt.collect_worktrees((root,), observed_at_utc=OBSERVED_AT)
        self.assertEqual(inventory.observations, ())
        self.assertFalse(inventory.to_dict()["discovery_complete"])


class RemoteIdentityTests(unittest.TestCase):
    def test_supported_origins_are_normalized_to_namespace_identity(self) -> None:
        cases = {
            "https://github.com/SZL-HOLDINGS/engine.git": REPO_NAME,
            "git@github.com:szl-holdings/engine.git": REPO_NAME,
            "https://huggingface.co/SZLHOLDINGS/model": "hf:SZLHOLDINGS/model",
            "https://huggingface.co/datasets/SZLHOLDINGS/data": "hf:SZLHOLDINGS/data",
            "https://huggingface.co/spaces/SZLHOLDINGS/demo": "hf:SZLHOLDINGS/demo",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(wt._sanitize_remote(raw), expected)

    def test_foreign_hosts_owners_and_extra_path_components_are_unknown(self) -> None:
        for raw in (
            "", "https://github.com/other/engine.git",
            "https://github.com.evil.example/szl-holdings/engine.git",
            "https://example.test/szl-holdings/engine.git",
            "https://huggingface.co/OTHER/model",
            "https://github.com/szl-holdings/engine/extra",
        ):
            with self.subTest(raw=raw):
                self.assertIsNone(wt._sanitize_remote(raw))

    def test_credentials_are_removed_and_query_or_fragment_secrets_are_rejected(self) -> None:
        credential_url = "https://synthetic-user:synthetic-secret@github.com/szl-holdings/engine.git"
        sanitized = wt._sanitize_remote(credential_url)
        self.assertEqual(sanitized, REPO_NAME)
        self.assertNotIn("synthetic", sanitized)
        self.assertIsNone(wt._sanitize_remote(REMOTE_URL + "?token=synthetic-secret"))
        self.assertIsNone(wt._sanitize_remote(REMOTE_URL + "#synthetic-secret"))


class GitConfigQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="szl-config-test-", dir=Path(__file__).absolute().parent
        )
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.git_dir = make_checkout(self.base / "checkout")
        self.config = self.git_dir / "config"
        self.git_executable = self.base / "trusted-git.exe"
        self.git_executable.write_bytes(b"synthetic executable; never run")

    def test_environment_drops_inherited_git_controls_and_uses_parent_ceiling(self) -> None:
        cwd = self.base / "private-empty"
        cwd.mkdir()
        inherited = {
            "GIT_DIR": "synthetic-private-repo", "GIT_WORK_TREE": "synthetic-tree",
            "GIT_COMMON_DIR": "synthetic-common", "GIT_INDEX_FILE": "synthetic-index",
            "GIT_OBJECT_DIRECTORY": "synthetic-objects", "GIT_EXEC_PATH": "synthetic-bin",
            "GIT_TRACE": "synthetic-trace", "GIT_TRACE2": "synthetic-trace2",
            "GIT_TRACE2_CONFIG_PARAMS": "*", "GIT_CONFIG_PARAMETERS": "'include.path=synthetic-secret'",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "include.path",
            "GIT_CONFIG_VALUE_0": "synthetic-secret", "GIT_CONFIG": "synthetic-config",
        }
        with mock.patch.dict(os.environ, inherited):
            environment = wt._safe_git_environment(cwd)
        for name in inherited:
            if name == "GIT_CONFIG_COUNT":
                self.assertIn(environment.get(name), (None, "0"))
            else:
                self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(Path(environment["GIT_CEILING_DIRECTORIES"]), cwd.parent)
        self.assertNotEqual(Path(environment["GIT_CEILING_DIRECTORIES"]), cwd)

    def test_query_launches_only_config_with_snapshot_in_private_empty_cwd(self) -> None:
        process = _FakeProcess((REMOTE_URL + "\0").encode("ascii"))
        launches = []

        def fake_popen(argv, **kwargs):
            launches.append((argv, kwargs))
            cwd = Path(kwargs["cwd"])
            self.assertTrue(cwd.is_absolute())
            self.assertTrue(cwd.is_dir())
            self.assertEqual(list(cwd.iterdir()), [])
            self.assertEqual(Path(kwargs["env"]["GIT_CEILING_DIRECTORIES"]), cwd.parent)
            return process

        snapshot = self.config.read_bytes()
        with mock.patch("subprocess.Popen", side_effect=fake_popen):
            repo_name, code = wt._query_origin(self.config, self.git_executable)
        self.assertEqual((repo_name, code), (REPO_NAME, "NONE"))
        self.assertEqual(len(launches), 1)
        argv, options = launches[0]
        self.assertEqual(Path(argv[0]), self.git_executable)
        self.assertIn("--no-pager", argv)
        self.assertIn("--no-optional-locks", argv)
        self.assertIn("config", argv)
        self.assertIn("--no-includes", argv)
        self.assertIn("--null", argv)
        self.assertEqual(argv[argv.index("--file") + 1], "-")
        self.assertEqual(argv[-2:], ["--get-all", "remote.origin.url"])
        self.assertNotIn(str(self.config), argv)
        self.assertFalse(options["shell"])
        self.assertEqual(options["stdin"], subprocess.PIPE)
        self.assertEqual(options["stdout"], subprocess.PIPE)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(process.stdin.getvalue(), snapshot)
        self.assertTrue(process.stdout.read_sizes)
        self.assertTrue(all(0 < size <= 8193 for size in process.stdout.read_sizes))

    def test_duplicate_origin_urls_remain_unknown_even_when_identical(self) -> None:
        process = _FakeProcess(((REMOTE_URL + "\0") * 2).encode("ascii"))
        with mock.patch("subprocess.Popen", return_value=process):
            repo_name, code = wt._query_origin(self.config, self.git_executable)
        self.assertIsNone(repo_name)
        self.assertNotEqual(code, "NONE")

    def test_output_larger_than_bound_is_unknown(self) -> None:
        process = _FakeProcess(b"x" * 8193 + b"\0")
        with mock.patch("subprocess.Popen", return_value=process):
            repo_name, code = wt._query_origin(self.config, self.git_executable)
        self.assertIsNone(repo_name)
        self.assertNotEqual(code, "NONE")

    def test_timeout_kills_synthetic_process_and_remains_unknown(self) -> None:
        process = _FakeProcess(b"", timeout=True)
        with mock.patch("subprocess.Popen", return_value=process):
            repo_name, code = wt._query_origin(self.config, self.git_executable)
        self.assertIsNone(repo_name)
        self.assertNotEqual(code, "NONE")
        self.assertTrue(process.killed)
        self.assertGreaterEqual(process.wait_calls, 2)

    def test_query_failure_does_not_return_child_output_or_secrets(self) -> None:
        process = _FakeProcess(b"synthetic-secret-child-output\0", returncode=2)
        with mock.patch("subprocess.Popen", return_value=process):
            repo_name, code = wt._query_origin(self.config, self.git_executable)
        self.assertIsNone(repo_name)
        self.assertRegex(code, r"^[A-Z_]+$")
        self.assertNotIn("synthetic", code)

    def test_relative_executable_never_launches_a_process(self) -> None:
        with mock.patch("subprocess.Popen", side_effect=AssertionError("relative executable launched")):
            repo_name, code = wt._query_origin(self.config, Path("git.exe"))
        self.assertIsNone(repo_name)
        self.assertNotEqual(code, "NONE")

    def test_oversized_config_snapshot_never_launches_a_process(self) -> None:
        self.config.write_bytes(b"#" * (64 * 1024 + 1))
        with mock.patch("subprocess.Popen", side_effect=AssertionError("oversized config launched")):
            repo_name, code = wt._query_origin(self.config, self.git_executable)
        self.assertIsNone(repo_name)
        self.assertNotEqual(code, "NONE")


if __name__ == "__main__":
    unittest.main()
