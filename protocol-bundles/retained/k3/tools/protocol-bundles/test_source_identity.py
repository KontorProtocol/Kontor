import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zlib

from source_identity import verify_git_tree, verify_registry_tree


class GitIdentity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        self.command("init", "-q")
        (self.root / "lib.rs").write_text("pub const VALUE: u32 = 1;\n")
        (self.root / ".gitignore").write_text("ignored\n")
        self.commit()
        self.revision = self.command("rev-parse", "HEAD").strip()

    def command(self, *args, root=None):
        return subprocess.check_output(["git", "-c", "user.name=Fixture", "-c",
            "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
            "-C", str(root or self.root), *args], text=True, stderr=subprocess.PIPE)

    def commit(self, root=None):
        self.command("add", ".", root=root)
        self.command("commit", "-qm", "Fixture", root=root)

    def test_clean_checkout_and_cargo_marker(self):
        (self.root / ".cargo-ok").write_bytes(b"")
        self.assertEqual(verify_git_tree(self.root, self.revision)["files"], 2)

    def test_preexisting_change_despite_assume_unchanged(self):
        self.command("update-index", "--assume-unchanged", "lib.rs")
        (self.root / "lib.rs").write_text("pub const VALUE: u32 = 2;\n")
        with self.assertRaisesRegex(RuntimeError, "Git source differs"):
            verify_git_tree(self.root, self.revision)

    def test_staged_index_change_with_original_worktree(self):
        original = (self.root / "lib.rs").read_bytes()
        (self.root / "lib.rs").write_bytes(b"changed")
        self.command("add", "lib.rs")
        (self.root / "lib.rs").write_bytes(original)
        with self.assertRaisesRegex(RuntimeError, "Git index differs"):
            verify_git_tree(self.root, self.revision)

    def test_ignored_and_untracked_files_are_rejected(self):
        for name in ("ignored", "extra.rs"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b"extra")
                with self.assertRaisesRegex(RuntimeError, "unexpected source input"):
                    verify_git_tree(self.root, self.revision)
                path.unlink()

    def test_cargo_marker_cannot_be_arbitrary_input(self):
        (self.root / ".cargo-ok").write_bytes(b"extra")
        with self.assertRaisesRegex(RuntimeError, "unexpected source input"):
            verify_git_tree(self.root, self.revision)

    def test_revision_and_file_mode_are_checked(self):
        with self.assertRaisesRegex(RuntimeError, "revision mismatch"):
            verify_git_tree(self.root, "0" * 40)
        (self.root / "lib.rs").chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "Git source differs"):
            verify_git_tree(self.root, self.revision)

    def test_replacement_ref_cannot_change_pinned_contents(self):
        (self.root / "lib.rs").write_text("replacement source")
        self.commit()
        replacement = self.command("rev-parse", "HEAD").strip()
        self.command("replace", self.revision, replacement)
        self.command("reset", "--hard", self.revision)
        self.assertEqual((self.root / "lib.rs").read_text(), "replacement source")
        with self.assertRaisesRegex(RuntimeError, "Git (index|source) differs"):
            verify_git_tree(self.root, self.revision)

    def test_grafts_are_rejected(self):
        (self.root / ".git/info/grafts").write_text(self.revision + "\n")
        with self.assertRaisesRegex(RuntimeError, "grafts are not permitted"):
            verify_git_tree(self.root, self.revision)

    def test_corrupt_tree_object_cannot_relabel_modified_source(self):
        tree = self.command("rev-parse", "HEAD^{tree}").strip()
        blob = self.command("rev-parse", "HEAD:lib.rs").strip()
        (self.root / "lib.rs").write_text("modified source")
        replacement = self.command("hash-object", "-w", "lib.rs").strip()
        self.command("update-index", "--cacheinfo", f"100644,{replacement},lib.rs")
        data = subprocess.check_output(["git", "-C", str(self.root), "cat-file", "tree", tree])
        data = data.replace(bytes.fromhex(blob), bytes.fromhex(replacement))
        path = self.root / ".git/objects" / tree[:2] / tree[2:]
        path.chmod(0o644)
        path.write_bytes(zlib.compress(b"tree " + str(len(data)).encode() + b"\0" + data))
        self.assertEqual((self.root / "lib.rs").read_text(), "modified source")
        with self.assertRaisesRegex(RuntimeError, "Git tree object differs|hash mismatch"):
            verify_git_tree(self.root, self.revision)

    def test_corrupt_commit_object_is_rejected(self):
        data = subprocess.check_output(["git", "-C", str(self.root), "cat-file", "commit", self.revision])
        data += b"modified commit\n"
        path = self.root / ".git/objects" / self.revision[:2] / self.revision[2:]
        path.chmod(0o644)
        path.write_bytes(zlib.compress(b"commit " + str(len(data)).encode() + b"\0" + data))
        with self.assertRaisesRegex(RuntimeError, "Git commit object differs"):
            verify_git_tree(self.root, self.revision)

    def test_symlink_target_is_checked_without_following_it(self):
        link = self.root / "link.rs"
        link.symlink_to("lib.rs")
        self.commit()
        revision = self.command("rev-parse", "HEAD").strip()
        verify_git_tree(self.root, revision)
        link.unlink()
        link.symlink_to("missing.rs")
        with self.assertRaisesRegex(RuntimeError, "Git source differs"):
            verify_git_tree(self.root, revision)

    def test_submodule_content_and_gitlink_are_checked(self):
        child = Path(self.temporary.name) / "child"
        child.mkdir()
        self.command("init", "-q", root=child)
        (child / "child.rs").write_text("original")
        self.commit(root=child)
        self.command("-c", "protocol.file.allow=always", "submodule", "add", str(child), "module")
        self.commit()
        revision = self.command("rev-parse", "HEAD").strip()
        module = self.root / "module"
        (module / ".cargo-ok").write_bytes(b"")
        verify_git_tree(self.root, revision)
        (module / "child.rs").write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "Git source differs"):
            verify_git_tree(self.root, revision)
        self.command("add", "child.rs", root=module)
        self.command("commit", "-qm", "Changed fixture", root=module)
        with self.assertRaisesRegex(RuntimeError, "revision mismatch"):
            verify_git_tree(self.root, revision)


class RegistryIdentity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.directory = root / "src/index/example-1.0.0"
        self.directory.mkdir(parents=True)
        self.archive = root / "cache/index/example-1.0.0.crate"
        self.archive.parent.mkdir(parents=True)
        payload = b"pub const VALUE: u32 = 1;\n"
        with tarfile.open(self.archive, "w:gz") as archive:
            item = tarfile.TarInfo("example-1.0.0/lib.rs")
            item.size = len(payload)
            item.mode = 0o644
            archive.addfile(item, io.BytesIO(payload))
        (self.directory / "lib.rs").write_bytes(payload)
        (self.directory / ".cargo-ok").write_bytes(b'{"v":1}')
        self.checksum = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_locked_archive_and_clean_extraction(self):
        self.assertEqual(verify_registry_tree(self.directory, self.checksum)["files"], 1)

    def test_preexisting_extracted_edit(self):
        (self.directory / "lib.rs").write_bytes(b"changed")
        with self.assertRaisesRegex(RuntimeError, "registry source differs"):
            verify_registry_tree(self.directory, self.checksum)

    def test_archive_edit_cannot_redefine_extracted_identity(self):
        with self.archive.open("ab") as archive:
            archive.write(b"changed")
        with self.assertRaisesRegex(RuntimeError, "archive checksum differs"):
            verify_registry_tree(self.directory, self.checksum)

    def test_extra_source_file(self):
        (self.directory / "extra.rs").write_bytes(b"extra")
        with self.assertRaisesRegex(RuntimeError, "unexpected source input"):
            verify_registry_tree(self.directory, self.checksum)


if __name__ == "__main__":
    unittest.main()
