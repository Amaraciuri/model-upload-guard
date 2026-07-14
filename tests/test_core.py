from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mug.apply import apply_changes, compute_changes
from mug.config import Config, path_matches
from mug.sandbox import inspect_command
from mug.scanner import blocks_export, scan_tree
from mug.snapshot import create_snapshot, restore_snapshot
from mug.utils import MugError, normalize_rel
from mug.workspace import create_pack, create_workspace


class PathTests(unittest.TestCase):
    def test_normalize_keeps_leading_dot(self) -> None:
        self.assertEqual(normalize_rel("./.env"), ".env")
        self.assertEqual(normalize_rel("foo/.env.local"), "foo/.env.local")

    def test_excluded_dotenv(self) -> None:
        self.assertTrue(path_matches(".env", [".env", ".env.*"]))
        self.assertTrue(path_matches("apps/api/.env.production", [".env.*"]))
        self.assertFalse(path_matches("env.example", [".env", ".env.*"]))


class ScanAndPackTests(unittest.TestCase):
    def test_pack_excludes_sensitive_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (root / ".env").write_text("SECRET=hidden\n", encoding="utf-8")
            output = Path(tmp) / "out.zip"
            create_pack(root, output, Config())
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
            self.assertIn("project/app.py", names)
            self.assertNotIn("project/.env", names)

    def test_secret_content_blocks_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.js").write_text(
                "const token = '" + "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890" + "';\n",
                encoding="utf-8",
            )
            findings = scan_tree(root, Config())
            self.assertTrue(blocks_export(findings, "high"))


class WorkspaceApplyTests(unittest.TestCase):
    def _state_patch(self, state: Path):
        return patch("mug.utils.state_dir", return_value=state)

    def test_apply_requires_confirmation_and_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            workspace = base / "workspace"
            state = base / "state"
            source.mkdir()
            (source / "hello.txt").write_text("before\n", encoding="utf-8")

            with patch("mug.workspace.state_dir", return_value=state), patch(
                "mug.snapshot.state_dir", return_value=state
            ), patch("mug.utils.state_dir", return_value=state):
                create_workspace(source, workspace, Config())
                (workspace / "hello.txt").write_text("after\n", encoding="utf-8")
                original, changes, _ = compute_changes(workspace, Config())
                self.assertEqual(original, source.resolve())
                self.assertEqual(changes[0].action, "modify")
                with self.assertRaises(MugError):
                    apply_changes(workspace, Config(), yes=False, allow_delete=False, force=False)
                result = apply_changes(workspace, Config(), yes=True, allow_delete=False, force=False)
                self.assertEqual((source / "hello.txt").read_text(encoding="utf-8"), "after\n")
                self.assertTrue(Path(str(result["snapshot"])).exists())

    def test_delete_is_blocked_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            workspace = base / "workspace"
            state = base / "state"
            source.mkdir()
            (source / "a.txt").write_text("a\n", encoding="utf-8")
            with patch("mug.workspace.state_dir", return_value=state), patch(
                "mug.snapshot.state_dir", return_value=state
            ), patch("mug.utils.state_dir", return_value=state):
                create_workspace(source, workspace, Config())
                (workspace / "a.txt").unlink()
                with self.assertRaises(MugError):
                    apply_changes(workspace, Config(), yes=True, allow_delete=False, force=False)

    def test_original_change_creates_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            workspace = base / "workspace"
            state = base / "state"
            source.mkdir()
            (source / "a.txt").write_text("base\n", encoding="utf-8")
            with patch("mug.workspace.state_dir", return_value=state), patch(
                "mug.snapshot.state_dir", return_value=state
            ), patch("mug.utils.state_dir", return_value=state):
                create_workspace(source, workspace, Config())
                (workspace / "a.txt").write_text("agent\n", encoding="utf-8")
                (source / "a.txt").write_text("user\n", encoding="utf-8")
                _, changes, _ = compute_changes(workspace, Config())
                self.assertEqual(changes[0].action, "blocked")
                self.assertIn("Conflict", changes[0].reason)

    def test_protected_new_file_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            workspace = base / "workspace"
            state = base / "state"
            source.mkdir()
            (source / "a.txt").write_text("a\n", encoding="utf-8")
            with patch("mug.workspace.state_dir", return_value=state), patch(
                "mug.snapshot.state_dir", return_value=state
            ), patch("mug.utils.state_dir", return_value=state):
                create_workspace(source, workspace, Config())
                (workspace / ".env").write_text("SECRET=x\n", encoding="utf-8")
                _, changes, _ = compute_changes(workspace, Config())
                self.assertEqual(changes[0].action, "blocked")


class SnapshotAndGuardTests(unittest.TestCase):
    def test_snapshot_restore_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            target = base / "target"
            state = base / "state"
            source.mkdir()
            (source / ".env").write_text("SECRET=local-only\n", encoding="utf-8")
            (source / "app.txt").write_text("hello\n", encoding="utf-8")
            with patch("mug.snapshot.state_dir", return_value=state):
                archive = create_snapshot(source)
                restore_snapshot(archive, target)
            self.assertEqual((target / ".env").read_text(encoding="utf-8"), "SECRET=local-only\n")
            self.assertEqual((target / "app.txt").read_text(encoding="utf-8"), "hello\n")

    def test_restore_rejects_absolute_tar_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                data = b"bad"
                member = tarfile.TarInfo("/outside.txt")
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            with self.assertRaises(MugError):
                restore_snapshot(archive, base / "target")

    def test_guard_blocks_destructive_root_delete(self) -> None:
        reasons = inspect_command("rm -rf /")
        self.assertTrue(reasons)
        self.assertFalse(inspect_command("rm -rf ./generated"))


if __name__ == "__main__":
    unittest.main()
