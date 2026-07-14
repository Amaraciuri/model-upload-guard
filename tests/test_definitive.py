from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mug.apply import apply_changes
from mug.config import Config
from mug.gitaware import assert_apply_git_safe, git_rev_parse
from mug.scanner import blocks_export, scan_tree
from mug.utils import MugError
from mug.workspace import create_workspace


class ProviderRuleTests(unittest.TestCase):
    def test_new_provider_rules_block(self) -> None:
        samples = {
            "vercel.js": "token = 'vercel_" + ("a" * 32) + "'\n",
            "supabase.env": "KEY=sbp_" + ("b" * 40) + "\n",
            "railway.txt": "railway_" + ("c" * 24) + "\n",
            "do.txt": "dop_v1_" + ("d" * 64) + "\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, body in samples.items():
                (root / name).write_text(body, encoding="utf-8")
            findings = scan_tree(root, Config())
            rules = {f.rule for f in findings}
            self.assertTrue({"vercel-token", "supabase-key", "railway-token", "digitalocean-token"} <= rules)
            self.assertTrue(blocks_export(findings, "high", True))

    def test_fixture_like_uuid_not_high_entropy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests" / "fixtures").mkdir(parents=True)
            # Low-ish mix, many hyphens — should not trip high-entropy heuristics.
            (root / "tests" / "fixtures" / "ids.txt").write_text(
                "id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'\n",
                encoding="utf-8",
            )
            findings = scan_tree(root, Config())
            self.assertFalse(any(f.rule == "high-entropy" and f.severity == "high" for f in findings))


class GitAwareApplyTests(unittest.TestCase):
    def test_dirty_tree_blocks_apply(self) -> None:
        import shutil

        if not shutil.which("git"):
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            workspace = base / "workspace"
            state = base / "state"
            source.mkdir()
            (source / "a.txt").write_text("a\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "t@example.com"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "t"], check=True)
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "init"], check=True)
            with patch("mug.workspace.state_dir", return_value=state), patch(
                "mug.utils.state_dir", return_value=state
            ), patch("mug.snapshot.state_dir", return_value=state):
                create_workspace(source, workspace, Config())
                (workspace / "a.txt").write_text("b\n", encoding="utf-8")
                (source / "noise.txt").write_text("uncommitted\n", encoding="utf-8")
                with self.assertRaises(MugError) as ctx:
                    apply_changes(workspace, Config(), yes=True, allow_delete=False, force=False)
                self.assertIn("uncommitted", str(ctx.exception).lower())

    def test_head_move_blocks_apply(self) -> None:
        import shutil

        if not shutil.which("git"):
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            (root / "a.txt").write_text("1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "config", "user.email", "t@example.com"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "t"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "one"], check=True)
            head1 = git_rev_parse(root)
            (root / "a.txt").write_text("2\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "two"], check=True)
            with self.assertRaises(MugError):
                assert_apply_git_safe(root, head1, force=False)
            warnings = assert_apply_git_safe(root, head1, force=True)
            self.assertTrue(warnings)


if __name__ == "__main__":
    unittest.main()
