import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".github" / "workflows" / "scripts"
LOCK_PATH = REPO_ROOT / ".github" / "workflows" / "config" / "dependencies.lock.json"
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "mayfly-gki-build.yml"
PATCHES_DIR = REPO_ROOT / ".github" / "workflows" / "patches"
README_PATH = REPO_ROOT / "README.md"

SUPERPROJECT_CORE_PATHS = (
    "build",
    "common",
    "prebuilts/clang/host/linux-x86",
    "configs",
    "tools/build",
    "tools/mkbootimg",
)


def superproject_core_pins(common_commit):
    return {
        "build": "1111111111111111111111111111111111111111",
        "common": common_commit,
        "prebuilts/clang/host/linux-x86": "2222222222222222222222222222222222222222",
        "configs": "3333333333333333333333333333333333333333",
        "tools/build": "4444444444444444444444444444444444444444",
        "tools/mkbootimg": "5555555555555555555555555555555555555555",
    }


def superproject_ls_tree(common_commit):
    pins = superproject_core_pins(common_commit)
    lines = [f"160000 commit {pins[path]}\t{path}" for path in SUPERPROJECT_CORE_PATHS]
    lines.append("100644 blob 6666666666666666666666666666666666666666\tREADME.md")
    return "\n".join(lines) + "\n"


def dynamic_kernelsu_kbuild():
    return (
        "obj-y += core_hook.o\n"
        "MDIR := $(dir $(lastword $(MAKEFILE_LIST)))\n"
        "KSU_VERSION := $(shell git rev-list --count HEAD)\n"
        "CURL_BIN := $(shell command -v curl)\n"
        "GITHUB_API := https://api.github.com/repos/SukiSU-Ultra/SukiSU-Ultra\n"
        "KSU_VERSION_FULL := $(shell $(CURL_BIN) $(GITHUB_API)/releases/latest)\n"
        "$(shell git fetch --unshallow 2>/dev/null)\n"
        "KSU_TAG_COUNT := $(shell $(CURL_BIN) '$(GITHUB_API)/commits?sha=main')\n"
        "ccflags-y += -DKSU_VERSION=$(KSU_VERSION)\n"
        "ccflags-y += -DKSU_VERSION_FULL=\\\"$(KSU_VERSION_FULL)\\\"\n"
        "\n"
        "ifndef KSU_EXPECTED_SIZE\n"
        "KSU_EXPECTED_SIZE := 0x3e8\n"
        "endif\n"
    )


def write_elf64_x86_64(path, *, size=4096):
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<H", header, 18, 62)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        output.write(header)
        output.truncate(size)
    return {
        "kpm_patch_path": path.parent.name + "/" + path.name,
        "kpm_patch_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "kpm_patch_size": size,
    }


def write_arm64_image(path, *, marker=b"", image_size=8 * 1024 * 1024, actual_size=None):
    actual_size = image_size if actual_size is None else actual_size
    header = bytearray(64)
    struct.pack_into("<Q", header, 0x10, image_size)
    header[0x38:0x3C] = b"ARMd"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        output.write(header)
        if marker:
            output.seek(0x100)
            output.write(marker)
        output.truncate(actual_size)
    return path

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import mayfly_builder as builder


class RecordingRunner:
    def __init__(self, outputs=None, on_run=None):
        self.calls = []
        self.outputs = list(outputs or [])
        self.on_run = on_run

    def run(self, args, **kwargs):
        args = list(args)
        self.calls.append((args, kwargs))
        if self.on_run is not None:
            self.on_run(args, kwargs)
        stdout = self.outputs.pop(0) if kwargs.get("capture_output") and self.outputs else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")


class SourceAndProfileTests(unittest.TestCase):
    def test_source_choices_are_exact_and_fully_pinned(self):
        self.assertEqual(
            set(builder.SOURCE_SPECS),
            {"stock-5.10.226", "security-5.10.236-r1"},
        )

        stock = builder.SOURCE_SPECS["stock-5.10.226"]
        self.assertEqual(stock.manifest_dependency, "android_manifest_2024_11")
        self.assertEqual(stock.manifest_commit, "22d661860f086f1ebc8c84491245c6b13c879e5e")
        self.assertEqual(stock.superproject_dependency, "android_superproject_2024_11")
        self.assertEqual(stock.superproject_commit, "26b4934c64e8a9c04caa51b6b4f0eb4396856df7")
        self.assertEqual(stock.common_ref, "deprecated/android12-5.10-2024-11")
        self.assertEqual(stock.common_commit, "ea4a6f067d3f7ae0ae3d460716449adf06a5ff15")
        self.assertEqual(stock.expected_release_prefix, "5.10.226-android12-9")

        security = builder.SOURCE_SPECS["security-5.10.236-r1"]
        self.assertEqual(security.manifest_dependency, "android_manifest_2025_05")
        self.assertEqual(security.manifest_commit, "b169c4e85157aefd89d56ed2e5fa5fed21965ee3")
        self.assertEqual(security.superproject_dependency, "android_superproject_2025_05")
        self.assertEqual(security.superproject_commit, "03e3311628edfc56454b777d69344e529029cad4")
        self.assertEqual(security.common_dependency, "android_common_2025_05_r1")
        self.assertEqual(security.common_ref, "deprecated/android12-5.10-2025-05")
        self.assertEqual(security.locked_common_ref, "refs/tags/android12-5.10-2025-05_r1")
        self.assertEqual(security.release_tag, "android12-5.10-2025-05_r1")
        self.assertEqual(security.common_commit, "b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e")
        self.assertEqual(security.expected_release_prefix, "5.10.236-android12-9")

    def test_security_source_uses_frozen_r1_and_never_audit_head(self):
        source = builder.SOURCE_SPECS["security-5.10.236-r1"]
        dependencies = builder.dependency_names_for_profile(
            source,
            builder.PROFILE_SPECS["root"],
        )
        self.assertIn("android_common_2025_05_r1", dependencies)
        self.assertIn("android_superproject_2025_05", dependencies)
        self.assertNotIn("android_common_2025_05", dependencies)

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            summary = builder.MayflyBuilder(
                "security-5.10.236-r1",
                "root",
                root / "workspace",
                root / "artifacts",
            ).dry_run()
        self.assertIn("android_common_2025_05_r1", summary["dependencies"])
        self.assertIn("android_superproject_2025_05", summary["dependencies"])
        self.assertNotIn("android_common_2025_05", summary["dependencies"])
        self.assertNotIn("fbb4c9b0aa2909575b240a5404b6a3eaa1d2755d", json.dumps(summary))

    def test_profiles_are_strictly_layered(self):
        expected = {
            "root": (False, False, False, False),
            "root-kpm": (True, False, False, False),
            "balanced": (True, True, True, False),
            "balanced-bbg": (True, True, True, True),
        }
        self.assertEqual(set(builder.PROFILE_SPECS), set(expected))
        for name, flags in expected.items():
            with self.subTest(profile=name):
                profile = builder.PROFILE_SPECS[name]
                self.assertEqual(
                    (profile.kpm, profile.zram_lz4kd, profile.bbr_default, profile.bbg),
                    flags,
                )

    def test_root_has_no_optional_dependencies_or_patches(self):
        dependencies = builder.dependency_names_for_profile(
            builder.SOURCE_SPECS["stock-5.10.226"],
            builder.PROFILE_SPECS["root"],
        )
        self.assertIn("sukisu_ultra", dependencies)
        self.assertIn("susfs4ksu", dependencies)
        self.assertIn("git_repo", dependencies)
        self.assertNotIn("sukisu_patch", dependencies)
        self.assertNotIn("baseband_guard", dependencies)

        patches = builder.planned_patch_paths(builder.PROFILE_SPECS["root"])
        self.assertEqual(
            patches,
            (
                "kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch",
                "patches/sukisu-v4.1.3-susfs-v2.2.0-compat.patch",
                "kernel_patches/50_add_susfs_in_gki-android12-5.10.patch",
            ),
        )

    def test_optional_dependencies_follow_profile_features(self):
        stock = builder.SOURCE_SPECS["stock-5.10.226"]
        root_kpm = builder.dependency_names_for_profile(stock, builder.PROFILE_SPECS["root-kpm"])
        balanced = builder.dependency_names_for_profile(stock, builder.PROFILE_SPECS["balanced"])
        bbg = builder.dependency_names_for_profile(stock, builder.PROFILE_SPECS["balanced-bbg"])
        self.assertIn("sukisu_patch", root_kpm)
        self.assertIn("sukisu_patch", balanced)
        self.assertNotIn("baseband_guard", balanced)
        self.assertIn("baseband_guard", bbg)

    def test_forbidden_hide_patch_is_never_planned(self):
        forbidden = "SukiSU_patch/69_hide_stuff.patch"
        for profile in builder.PROFILE_SPECS.values():
            with self.subTest(profile=profile.name):
                self.assertNotIn(forbidden, builder.planned_patch_paths(profile))
        self.assertIn(forbidden, builder.EXCLUDED_PATCHES)
        self.assertIn("third-party detection bypass", builder.EXCLUDED_PATCHES[forbidden])

    def test_patch_exclusions_are_narrow_and_security_bounded(self):
        self.assertEqual(
            builder.PATCH_EXCLUSIONS,
            {
                "susfs_kernelsu_upstream": (
                    "kernel/core/init.c",
                    "kernel/policy/app_profile.h",
                ),
                "susfs_common": ("fs/proc/task_mmu.c",),
                "lz4kd": ("kernel/module.c",),
            },
        )
        excluded = builder.EXCLUDED_PATCHES
        self.assertIn("SukiSU-Ultra/kernel/feature/uts_spoof.c", excluded)
        self.assertIn("version spoof", excluded["SukiSU-Ultra/kernel/feature/uts_spoof.c"])
        self.assertIn("SukiSU_patch/other/zram/zram_patch/5.10/lz4kd.patch:kernel/module.c", excluded)
        self.assertIn(
            "module version checks",
            excluded["SukiSU_patch/other/zram/zram_patch/5.10/lz4kd.patch:kernel/module.c"],
        )


class CommandRunnerTests(unittest.TestCase):
    def test_runner_uses_list_shell_false_and_check_true(self):
        runner = builder.CommandRunner()
        with mock.patch("mayfly_builder.subprocess.run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
            runner.run(
                ["git", "status"],
                cwd=REPO_ROOT,
                env={"SAFE": "1"},
                capture_output=True,
            )

        run_mock.assert_called_once_with(
            ["git", "status"],
            cwd=REPO_ROOT,
            env={"SAFE": "1"},
            shell=False,
            check=True,
            text=True,
            capture_output=True,
        )

    def test_runner_accepts_tuple_but_rejects_shell_strings(self):
        runner = builder.CommandRunner()
        with mock.patch("mayfly_builder.subprocess.run") as run_mock:
            run_mock.return_value = subprocess.CompletedProcess([], 0)
            runner.run(("git", "status"))
        self.assertEqual(run_mock.call_args.args[0], ["git", "status"])

        with self.assertRaises(TypeError):
            runner.run("git status")
        with self.assertRaises(TypeError):
            runner.run(["git", 123])

    def test_runner_propagates_command_failure(self):
        failure = subprocess.CalledProcessError(7, ["git", "fetch"])
        runner = builder.CommandRunner()
        with mock.patch("mayfly_builder.subprocess.run", side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                runner.run(["git", "fetch"])
        self.assertIs(raised.exception, failure)


class PinnedGitTests(unittest.TestCase):
    def setUp(self):
        self.dependency = {
            "repo_url": "https://example.invalid/repository.git",
            "commit": "0123456789abcdef0123456789abcdef01234567",
        }

    def test_pinned_clone_uses_detached_exact_commit_and_depth_one(self):
        runner = RecordingRunner(outputs=[self.dependency["commit"] + "\n"])
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            destination = Path(temporary_dir) / "dependency"
            builder.clone_pinned_dependency(runner, self.dependency, destination)

        commands = [call[0] for call in runner.calls]
        self.assertEqual(commands[0], ["git", "init", str(destination)])
        self.assertEqual(
            commands[1],
            ["git", "-C", str(destination), "remote", "add", "origin", self.dependency["repo_url"]],
        )
        self.assertEqual(
            commands[2],
            [
                "git",
                "-C",
                str(destination),
                "fetch",
                "--depth=1",
                "origin",
                self.dependency["commit"],
            ],
        )
        self.assertEqual(
            commands[3],
            ["git", "-C", str(destination), "checkout", "--detach", self.dependency["commit"]],
        )
        self.assertEqual(commands[4][-2:], ["rev-parse", "HEAD"])

    def test_bbg_style_clone_is_not_shallow(self):
        runner = RecordingRunner(outputs=[self.dependency["commit"] + "\n"])
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            destination = Path(temporary_dir) / "baseband-guard"
            builder.clone_pinned_dependency(runner, self.dependency, destination, shallow=False)

        fetch_command = [call[0] for call in runner.calls if "fetch" in call[0]][0]
        self.assertNotIn("--depth=1", fetch_command)
        self.assertEqual(fetch_command[-2:], ["origin", self.dependency["commit"]])

    def test_existing_clone_destination_is_rejected(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            with self.assertRaises(FileExistsError):
                builder.clone_pinned_dependency(runner, self.dependency, Path(temporary_dir))
        self.assertEqual(runner.calls, [])

    def test_head_mismatch_stops_clone(self):
        runner = RecordingRunner(outputs=["f" * 40 + "\n"])
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            destination = Path(temporary_dir) / "dependency"
            with self.assertRaisesRegex(RuntimeError, "HEAD"):
                builder.clone_pinned_dependency(runner, self.dependency, destination)


class MayflyLockValidationTests(unittest.TestCase):
    def _write_lock(self, root, payload):
        path = root / "dependencies.lock.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_loader_rejects_unsafe_repo_and_manifest_paths(self):
        original = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        cases = (
            ("git_repo", "path", "../repo"),
            ("android_manifest_2024_11", "path", "/default.xml"),
            ("android_manifest_2025_05", "path", "nested/../default.xml"),
        )
        for dependency, field, value in cases:
            with self.subTest(dependency=dependency, value=value), tempfile.TemporaryDirectory(
                dir=REPO_ROOT
            ) as temporary_dir:
                payload = json.loads(json.dumps(original))
                payload["dependencies"][dependency][field] = value
                lock_path = self._write_lock(Path(temporary_dir), payload)
                with self.assertRaises(ValueError):
                    builder.load_dependencies(lock_path)

    def test_loader_rejects_repo_urls_outside_safe_ascii_set(self):
        original = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        for url in (
            "https://example.invalid/repo&command.git",
            "https://example.invalid/repo(command).git",
            "https://example.invalid/repo%20name.git",
        ):
            with self.subTest(url=url), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                payload = json.loads(json.dumps(original))
                payload["dependencies"]["sukisu_ultra"]["repo_url"] = url
                lock_path = self._write_lock(Path(temporary_dir), payload)
                with self.assertRaises(ValueError):
                    builder.load_dependencies(lock_path)

    def test_loader_rejects_kernelsu_build_version_drift(self):
        original = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        cases = (
            ("version_name", "latest"),
            ("version_code", 40795),
            ("version_code", "40796"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory(
                dir=REPO_ROOT
            ) as temporary_dir:
                payload = json.loads(json.dumps(original))
                payload["dependencies"]["sukisu_ultra"][field] = value
                lock_path = self._write_lock(Path(temporary_dir), payload)
                with self.assertRaises(ValueError):
                    builder.load_dependencies(lock_path)

    def test_loader_rejects_kpm_patcher_identity_drift(self):
        original = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        cases = (
            ("kpm_patch_path", "../patch_linux"),
            (
                "kpm_patch_sha256",
                "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2",
            ),
            ("kpm_patch_sha256", "0" * 64),
            ("kpm_patch_size", 6013319),
            ("kpm_patch_size", "6013320"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory(
                dir=REPO_ROOT
            ) as temporary_dir:
                payload = json.loads(json.dumps(original))
                payload["dependencies"]["sukisu_patch"][field] = value
                lock_path = self._write_lock(Path(temporary_dir), payload)
                with self.assertRaises(ValueError):
                    builder.load_dependencies(lock_path)

    def test_lock_records_local_sukisu_susfs_compat_patch(self):
        dependencies = builder.load_dependencies()
        susfs = dependencies["susfs4ksu"]
        self.assertEqual(
            susfs["mayfly_compat_patch_path"],
            "patches/sukisu-v4.1.3-susfs-v2.2.0-compat.patch",
        )
        self.assertEqual(
            susfs["mayfly_compat_patch_sha256"],
            "8b0493e5485196ac808076906479feb9a6955c1d19abaeeb59509ba8105c09fe",
        )
        patch_path, patch_hash = builder.validate_local_compat_patch(susfs)
        self.assertEqual(patch_path, PATCHES_DIR / "sukisu-v4.1.3-susfs-v2.2.0-compat.patch")
        self.assertEqual(patch_hash, susfs["mayfly_compat_patch_sha256"])

    def test_loader_rejects_local_compat_patch_metadata_drift(self):
        original = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        cases = (
            ("mayfly_compat_patch_path", "../compat.patch"),
            ("mayfly_compat_patch_sha256", "0" * 64),
            ("mayfly_compat_patch_sha256", "8B0493E5485196AC808076906479FEB9A6955C1D19ABAEEB59509BA8105C09FE"),
        )
        for field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                payload = json.loads(json.dumps(original))
                payload["dependencies"]["susfs4ksu"][field] = value
                lock_path = self._write_lock(Path(temporary_dir), payload)
                with self.assertRaises(ValueError):
                    builder.load_dependencies(lock_path)

    def test_builder_records_complete_kpm_patcher_hash(self):
        self.assertEqual(
            builder.KPM_PATCH_SHA256,
            "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2d",
        )
        self.assertEqual(len(builder.KPM_PATCH_SHA256), 64)

    def test_loader_rejects_git_repo_launcher_version_drift(self):
        original = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        for value in (None, "2.16", 2.15):
            with self.subTest(value=value), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                payload = json.loads(json.dumps(original))
                if value is None:
                    payload["dependencies"]["git_repo"].pop("version", None)
                else:
                    payload["dependencies"]["git_repo"]["version"] = value
                lock_path = self._write_lock(Path(temporary_dir), payload)
                with self.assertRaises(ValueError):
                    builder.load_dependencies(lock_path)


class StrictPatchTests(unittest.TestCase):
    def test_patch_runs_dry_run_then_apply_with_zero_fuzz(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            patch_path = root / "change.patch"
            patch_path.write_text("diff --git a/a b/a\n", encoding="utf-8")
            builder.apply_patch_strict(runner, patch_path, root)

        self.assertEqual(len(runner.calls), 2)
        dry_run, apply = (call[0] for call in runner.calls)
        self.assertIn("--dry-run", dry_run)
        self.assertNotIn("--dry-run", apply)
        for command in (dry_run, apply):
            self.assertIn("--batch", command)
            self.assertIn("--forward", command)
            self.assertIn("--fuzz=0", command)
            self.assertIn("-p1", command)
            self.assertEqual(command[0], "patch")

    def test_missing_or_empty_patch_stops_before_command(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            missing = root / "missing.patch"
            with self.assertRaises(FileNotFoundError):
                builder.apply_patch_strict(runner, missing, root)
            empty = root / "empty.patch"
            empty.touch()
            with self.assertRaises(ValueError):
                builder.apply_patch_strict(runner, empty, root)
        self.assertEqual(runner.calls, [])

    def test_git_patch_checks_then_applies_with_exact_exclusions(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            patch_path = root / "change.patch"
            patch_path.write_text("diff --git a/a b/a\n", encoding="utf-8")
            builder.apply_git_patch_strict(
                runner,
                patch_path,
                root,
                excluded_paths=("kernel/module.c",),
                whitespace="nowarn",
            )

        self.assertEqual(len(runner.calls), 2)
        check, apply = (call[0] for call in runner.calls)
        self.assertEqual(check[:4], ["git", "apply", "--check", "--whitespace=nowarn"])
        self.assertEqual(apply[:3], ["git", "apply", "--whitespace=nowarn"])
        for command in (check, apply):
            self.assertIn("--exclude=kernel/module.c", command)
            self.assertEqual(command[-1], str(patch_path.resolve()))
        self.assertEqual(runner.calls[0][1]["cwd"], root)
        self.assertEqual(runner.calls[1][1]["cwd"], root)

    def test_git_patch_rejects_unsafe_exclusions_and_modes_before_command(self):
        cases = (
            (("../module.c",), "nowarn"),
            (("/kernel/module.c",), "nowarn"),
            (("kernel//module.c",), "nowarn"),
            (("kernel/module.c",), "fix"),
        )
        for excluded_paths, whitespace in cases:
            runner = RecordingRunner()
            with self.subTest(excluded_paths=excluded_paths, whitespace=whitespace), tempfile.TemporaryDirectory(
                dir=REPO_ROOT
            ) as temporary_dir:
                root = Path(temporary_dir)
                patch_path = root / "change.patch"
                patch_path.write_text("diff --git a/a b/a\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    builder.apply_git_patch_strict(
                        runner,
                        patch_path,
                        root,
                        excluded_paths=excluded_paths,
                        whitespace=whitespace,
                    )
            self.assertEqual(runner.calls, [])


class ManifestTests(unittest.TestCase):
    def test_common_project_revision_is_rewritten_exactly(self):
        content = (
            '<manifest><project name="kernel/common" path="common" revision="old" />'
            '<project name="kernel/build" path="build" revision="unchanged" /></manifest>'
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            manifest = Path(temporary_dir) / "default.xml"
            manifest.write_text(content, encoding="utf-8")
            builder.rewrite_common_manifest(manifest, "deprecated/android12-5.10-2024-11")
            rewritten = manifest.read_text(encoding="utf-8")

        self.assertIn('revision="deprecated/android12-5.10-2024-11"', rewritten)
        self.assertIn('revision="unchanged"', rewritten)

    def test_missing_or_duplicate_common_project_is_rejected(self):
        invalid_manifests = (
            '<manifest><project name="kernel/build" path="build" /></manifest>',
            (
                '<manifest><project name="kernel/common" path="common" />'
                '<project name="kernel/common" path="common" /></manifest>'
            ),
        )
        for index, content in enumerate(invalid_manifests):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                manifest = Path(temporary_dir) / "default.xml"
                manifest.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "common"):
                    builder.rewrite_common_manifest(manifest, "deprecated/android12-5.10-2024-11")

    def test_superproject_ls_tree_parser_accepts_only_unique_gitlinks(self):
        common_commit = builder.SOURCE_SPECS["stock-5.10.226"].common_commit
        pins = builder.parse_superproject_ls_tree(
            superproject_ls_tree(common_commit),
            expected_common_commit=common_commit,
        )
        self.assertEqual(pins, superproject_core_pins(common_commit))
        self.assertNotIn("README.md", pins)

    def test_superproject_ls_tree_rejects_common_mismatch_empty_duplicate_and_symbolic(self):
        common_commit = builder.SOURCE_SPECS["stock-5.10.226"].common_commit
        invalid_outputs = (
            superproject_ls_tree("a" * 40),
            "100644 blob " + "b" * 40 + "\tREADME.md\n",
            (
                f"160000 commit {common_commit}\tcommon\n"
                f"160000 commit {'c' * 40}\tcommon\n"
            ),
            "160000 commit refs/heads/main\tcommon\n",
        )
        for output in invalid_outputs:
            with self.subTest(output=output):
                with self.assertRaises((ValueError, RuntimeError)):
                    builder.parse_superproject_ls_tree(
                        output,
                        expected_common_commit=common_commit,
                    )

    def test_manifest_projects_are_all_rewritten_from_superproject_pins(self):
        common_commit = builder.SOURCE_SPECS["stock-5.10.226"].common_commit
        pins = superproject_core_pins(common_commit)
        projects = "".join(
            f'<project name="kernel/{index}" path="{path}" revision="symbolic" />'
            for index, path in enumerate(SUPERPROJECT_CORE_PATHS)
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            manifest = Path(temporary_dir) / "default.xml"
            manifest.write_text(f"<manifest>{projects}</manifest>", encoding="utf-8")
            manifest_pins = builder.rewrite_manifest_with_superproject(manifest, pins)
            root = ET.parse(manifest).getroot()
        self.assertEqual(manifest_pins, pins)
        self.assertEqual(
            {project.get("path"): project.get("revision") for project in root.iter("project")},
            pins,
        )

    def test_manifest_rewrite_rejects_missing_mapping_duplicate_path_and_bad_sha(self):
        common_commit = builder.SOURCE_SPECS["stock-5.10.226"].common_commit
        pins = superproject_core_pins(common_commit)
        invalid_cases = (
            ('<manifest><project name="x" path="missing" /></manifest>', pins),
            (
                '<manifest><project name="a" path="common" /><project name="b" path="common" /></manifest>',
                pins,
            ),
            ('<manifest><project name="x" path="common" /></manifest>', {"common": "main"}),
        )
        for content, project_pins in invalid_cases:
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                manifest = Path(temporary_dir) / "default.xml"
                manifest.write_text(content, encoding="utf-8")
                with self.assertRaises((ValueError, RuntimeError)):
                    builder.rewrite_manifest_with_superproject(manifest, project_pins)

    def test_resolved_manifest_requires_all_lowercase_full_shas(self):
        sha_a = "a" * 40
        sha_b = "0123456789abcdef0123456789abcdef01234567"
        content = (
            f'<manifest><project name="kernel/common" path="common" revision="{sha_a}" />'
            f'<project name="kernel/build" path="build" revision="{sha_b}" /></manifest>'
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            manifest = Path(temporary_dir) / "resolved.xml"
            manifest.write_text(content, encoding="utf-8")
            revisions = builder.validate_resolved_manifest(manifest)
        self.assertEqual(revisions, {"common": sha_a, "build": sha_b})

    def test_resolved_manifest_rejects_symbolic_uppercase_or_empty_projects(self):
        invalid_revisions = ("main", "HEAD~1", "A" * 40, "a" * 39)
        for revision in invalid_revisions:
            with self.subTest(revision=revision), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                manifest = Path(temporary_dir) / "resolved.xml"
                manifest.write_text(
                    f'<manifest><project name="kernel/common" path="common" revision="{revision}" /></manifest>',
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    builder.validate_resolved_manifest(manifest)

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            manifest = Path(temporary_dir) / "resolved.xml"
            manifest.write_text("<manifest />", encoding="utf-8")
            with self.assertRaises(ValueError):
                builder.validate_resolved_manifest(manifest)

    def test_resolved_manifest_common_must_match_selected_source(self):
        expected = "a" * 40
        actual = "b" * 40
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            manifest = Path(temporary_dir) / "resolved.xml"
            manifest.write_text(
                f'<manifest><project name="kernel/common" path="common" revision="{actual}" /></manifest>',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "common"):
                builder.validate_resolved_manifest(
                    manifest,
                    expected_common_commit=expected,
                )

    def test_resolved_manifest_must_exactly_match_expected_project_pins(self):
        expected = {
            "build": "1" * 40,
            "common": "2" * 40,
        }
        invalid_contents = (
            f'<manifest><project path="common" revision="{"2" * 40}" /></manifest>',
            (
                f'<manifest><project path="build" revision="{"1" * 40}" />'
                f'<project path="common" revision="{"3" * 40}" /></manifest>'
            ),
            (
                f'<manifest><project path="build" revision="{"1" * 40}" />'
                f'<project path="common" revision="{"2" * 40}" />'
                '<project path="extra" revision="main" /></manifest>'
            ),
        )
        for content in invalid_contents:
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                manifest = Path(temporary_dir) / "resolved.xml"
                manifest.write_text(content, encoding="utf-8")
                with self.assertRaises((ValueError, RuntimeError)):
                    builder.validate_resolved_manifest(manifest, expected_projects=expected)

    def test_repo_commands_pin_both_manifest_and_repo_and_cap_jobs(self):
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]
        source = builder.SOURCE_SPECS["stock-5.10.226"]
        command = builder.repo_init_command(Path("tools/repo"), source, dependencies)
        self.assertIn(source.manifest_commit, command)
        self.assertIn(dependencies["git_repo"]["commit"], command)
        self.assertIn(dependencies["git_repo"]["repo_url"], command)
        self.assertNotIn(source.common_ref, command)

        sync = builder.repo_sync_command(Path("tools/repo"), jobs=4)
        self.assertIn("--fail-fast", sync)
        self.assertIn("--no-manifest-update", sync)
        self.assertIn("-j4", sync)
        with self.assertRaises(ValueError):
            builder.repo_sync_command(Path("tools/repo"), jobs=5)

    def test_both_sources_only_verify_common_head_without_fetch_or_checkout(self):
        stock = builder.SOURCE_SPECS["stock-5.10.226"]
        runner = RecordingRunner(outputs=[stock.common_commit + "\n"])
        builder.verify_common_head(runner, Path("common"), stock)
        commands = [call[0] for call in runner.calls]
        self.assertFalse(any("fetch" in command for command in commands))
        self.assertFalse(any("checkout" in command for command in commands))

        security = builder.SOURCE_SPECS["security-5.10.236-r1"]
        runner = RecordingRunner(outputs=[security.common_commit + "\n"])
        builder.verify_common_head(runner, Path("common"), security)
        commands = [call[0] for call in runner.calls]
        self.assertFalse(any("fetch" in command for command in commands))
        self.assertFalse(any("checkout" in command for command in commands))

    def test_common_revision_mismatch_stops(self):
        runner = RecordingRunner(outputs=["f" * 40 + "\n"])
        with self.assertRaisesRegex(RuntimeError, "common"):
            builder.verify_common_head(
                runner,
                Path("common"),
                builder.SOURCE_SPECS["security-5.10.236-r1"],
            )


class KconfigTests(unittest.TestCase):
    def test_set_kconfig_replaces_duplicates_with_one_exact_value(self):
        original = (
            "CONFIG_ALPHA=y\n"
            "CONFIG_KSU=n\n"
            "# CONFIG_KSU is not set\n"
            "CONFIG_KSU=m\n"
        )
        updated = builder.set_kconfig(original, "CONFIG_KSU", "y")
        self.assertEqual(updated.count("CONFIG_KSU="), 1)
        self.assertNotIn("# CONFIG_KSU is not set", updated)
        self.assertIn("CONFIG_KSU=y\n", updated)
        self.assertIn("CONFIG_ALPHA=y\n", updated)

        disabled = builder.set_kconfig(updated, "CONFIG_KSU", "n")
        self.assertEqual(disabled.count("# CONFIG_KSU is not set"), 1)
        self.assertNotIn("CONFIG_KSU=y", disabled)

    def test_all_profiles_disable_susfs_concealment(self):
        for profile in builder.PROFILE_SPECS.values():
            with self.subTest(profile=profile.name):
                values = builder.profile_kconfig(profile)
                self.assertEqual(values["CONFIG_KSU"], "y")
                self.assertEqual(values["CONFIG_KSU_SUSFS"], "y")
                for symbol in builder.SUSFS_CONCEALMENT_CONFIGS:
                    self.assertEqual(values[symbol], "n")

    def test_kpm_lz4kd_bbr_and_bbg_follow_profile_layers(self):
        root = builder.profile_kconfig(builder.PROFILE_SPECS["root"])
        root_kpm = builder.profile_kconfig(builder.PROFILE_SPECS["root-kpm"])
        balanced = builder.profile_kconfig(builder.PROFILE_SPECS["balanced"])
        bbg = builder.profile_kconfig(
            builder.PROFILE_SPECS["balanced-bbg"],
            existing_lsm="lockdown,yama,integrity",
        )

        self.assertEqual(root["CONFIG_KPM"], "n")
        self.assertEqual(root_kpm["CONFIG_KPM"], "y")
        for symbol in (
            "CONFIG_ZSMALLOC",
            "CONFIG_ZRAM",
            "CONFIG_CRYPTO_LZO",
            "CONFIG_CRYPTO_LZ4K",
            "CONFIG_CRYPTO_LZ4KD",
            "CONFIG_ZRAM_DEF_COMP_LZ4KD",
            "CONFIG_ZRAM_WRITEBACK",
        ):
            self.assertNotIn(symbol, root)
            self.assertNotIn(symbol, root_kpm)
        self.assertEqual(balanced["CONFIG_KPM"], "y")
        self.assertEqual(balanced["CONFIG_CRYPTO_LZ4KD"], "y")
        self.assertEqual(balanced["CONFIG_ZRAM_DEF_COMP_LZ4KD"], "y")
        self.assertEqual(balanced["CONFIG_DEFAULT_TCP_CONG"], '"bbr"')
        self.assertEqual(balanced["CONFIG_DEFAULT_BBR"], "y")
        self.assertEqual(balanced["CONFIG_DEFAULT_CUBIC"], "n")
        self.assertEqual(bbg["CONFIG_BBG"], "y")
        self.assertEqual(bbg["CONFIG_BBG_BLOCK_BOOT"], "n")
        self.assertEqual(bbg["CONFIG_BBG_BLOCK_RECOVERY"], "n")
        self.assertEqual(bbg["CONFIG_LSM"], '"lockdown,yama,integrity,baseband_guard"')
        for symbol in ("CONFIG_BBG", "CONFIG_BBG_BLOCK_BOOT", "CONFIG_BBG_BLOCK_RECOVERY"):
            self.assertNotIn(symbol, root)
            self.assertNotIn(symbol, root_kpm)
            self.assertNotIn(symbol, balanced)

    def test_root_explicitly_disables_bbr_and_keeps_cubic_default(self):
        root = builder.profile_kconfig(builder.PROFILE_SPECS["root"])
        self.assertEqual(root["CONFIG_TCP_CONG_ADVANCED"], "n")
        self.assertEqual(root["CONFIG_TCP_CONG_CUBIC"], "y")
        self.assertEqual(root["CONFIG_DEFAULT_TCP_CONG"], '"cubic"')
        for hidden_symbol in (
            "CONFIG_DEFAULT_BBR",
            "CONFIG_DEFAULT_CUBIC",
            "CONFIG_TCP_CONG_BBR",
        ):
            self.assertNotIn(hidden_symbol, root)

    def test_lsm_append_is_order_preserving_and_idempotent(self):
        value = builder.append_lsm("lockdown,yama,integrity", "baseband_guard")
        self.assertEqual(value, "lockdown,yama,integrity,baseband_guard")
        self.assertEqual(builder.append_lsm(value, "baseband_guard"), value)
        with self.assertRaises(ValueError):
            builder.append_lsm(
                "lockdown,baseband_guard,yama,integrity",
                "baseband_guard",
            )

    def test_kmi_guards_are_verified_but_never_overridden(self):
        self.assertEqual(
            builder.KMI_GUARDS,
            {
                "CONFIG_MODVERSIONS": "y",
                "CONFIG_CFI_CLANG": "y",
                "CONFIG_LTO_CLANG_FULL": "y",
                "CONFIG_ANDROID_VENDOR_HOOKS": "y",
                "CONFIG_TRIM_UNUSED_KSYMS": "y",
            },
        )
        for profile in builder.PROFILE_SPECS.values():
            values = builder.profile_kconfig(profile)
            self.assertTrue(builder.KMI_GUARDS.keys().isdisjoint(values))

    def test_no_profile_adds_ttl_or_hop_limit_bypasses(self):
        forbidden_fragments = ("TTL", "HOPLIMIT", "HL_TARGET", "NETFILTER_XT_TARGET_HL")
        for profile in builder.PROFILE_SPECS.values():
            symbols = "\n".join(builder.profile_kconfig(profile))
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, symbols)

    def _common_final_config_lines(self, kpm_value):
        lines = [
            "CONFIG_KSU=y",
            "# CONFIG_KSU_DEBUG is not set",
            "CONFIG_KSU_MANUAL_SU=y",
            "# CONFIG_KSU_DISABLE_MANAGER is not set",
            "# CONFIG_KSU_DISABLE_POLICY is not set",
            "CONFIG_KSU_SUSFS=y",
        ]
        lines.extend(f"# {symbol} is not set" for symbol in builder.SUSFS_CONCEALMENT_CONFIGS)
        lines.append(
            "# CONFIG_KPM is not set" if kpm_value == "n" else f"CONFIG_KPM={kpm_value}"
        )
        return lines

    def _root_olddefconfig_text(self):
        lines = self._common_final_config_lines("n")
        lines.extend(
            (
                "CONFIG_ZSMALLOC=y",
                "CONFIG_ZRAM=m",
                "CONFIG_CRYPTO_LZO=y",
                "# CONFIG_TCP_CONG_ADVANCED is not set",
                "CONFIG_TCP_CONG_CUBIC=y",
                'CONFIG_DEFAULT_TCP_CONG="cubic"',
            )
        )
        lines.extend(f"{symbol}=y" for symbol in builder.KMI_GUARDS)
        return "\n".join(lines) + "\n"

    def _balanced_bbg_final_config_text(self):
        lines = self._common_final_config_lines("y")
        lines.extend(
            (
                "CONFIG_ZSMALLOC=y",
                "CONFIG_ZRAM=y",
                "CONFIG_CRYPTO_LZO=y",
                "CONFIG_CRYPTO_LZ4K=y",
                "CONFIG_CRYPTO_LZ4KD=y",
                "CONFIG_ZRAM_DEF_COMP_LZ4KD=y",
                "CONFIG_ZRAM_WRITEBACK=y",
                "CONFIG_TCP_CONG_ADVANCED=y",
                "CONFIG_TCP_CONG_BBR=y",
                "CONFIG_NET_SCH_FQ=y",
                "CONFIG_DEFAULT_BBR=y",
                "# CONFIG_DEFAULT_CUBIC is not set",
                'CONFIG_DEFAULT_TCP_CONG="bbr"',
                "CONFIG_BBG=y",
                "# CONFIG_BBG_BLOCK_BOOT is not set",
                "# CONFIG_BBG_BLOCK_RECOVERY is not set",
                'CONFIG_LSM="lockdown,yama,integrity,baseband_guard"',
            )
        )
        lines.extend(f"{symbol}=y" for symbol in builder.KMI_GUARDS)
        return "\n".join(lines) + "\n"

    def test_root_final_config_allows_olddefconfig_to_drop_unintegrated_symbols(self):
        profile = builder.PROFILE_SPECS["root"]
        config_text = self._root_olddefconfig_text()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            config_path = Path(temporary_dir) / ".config"
            config_path.write_text(config_text, encoding="utf-8")
            parsed = builder.validate_final_config(config_path, profile)
        self.assertNotIn("CONFIG_CRYPTO_LZ4KD", parsed)
        self.assertNotIn("CONFIG_ZRAM_DEF_COMP_LZ4KD", parsed)
        self.assertNotIn("CONFIG_BBG", parsed)
        self.assertNotIn("CONFIG_TCP_CONG_BBR", parsed)
        self.assertEqual(parsed["CONFIG_ZRAM"], "m")
        self.assertEqual(parsed["CONFIG_DEFAULT_TCP_CONG"], "cubic")

    def test_root_final_config_rejects_enabled_optional_features(self):
        profile = builder.PROFILE_SPECS["root"]
        optional_symbols = (
            "CONFIG_CRYPTO_LZ4KD",
            "CONFIG_ZRAM_DEF_COMP_LZ4KD",
            "CONFIG_BBG",
            "CONFIG_TCP_CONG_BBR",
        )
        for symbol in optional_symbols:
            for value in ("y", "m"):
                with self.subTest(symbol=symbol, value=value), tempfile.TemporaryDirectory(
                    dir=REPO_ROOT
                ) as temporary_dir:
                    config_path = Path(temporary_dir) / ".config"
                    config_path.write_text(
                        self._root_olddefconfig_text() + f"{symbol}={value}\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(RuntimeError, symbol):
                        builder.validate_final_config(config_path, profile)

    def test_final_config_validation_checks_features_and_kmi_guards(self):
        profile = builder.PROFILE_SPECS["balanced-bbg"]
        config_text = self._balanced_bbg_final_config_text()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            config_path = Path(temporary_dir) / ".config"
            config_path.write_text(config_text, encoding="utf-8")
            parsed = builder.validate_final_config(config_path, profile)
            self.assertEqual(parsed["CONFIG_LSM"], "lockdown,yama,integrity,baseband_guard")

            broken = config_text.replace("CONFIG_MODVERSIONS=y", "# CONFIG_MODVERSIONS is not set")
            config_path.write_text(broken, encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "CONFIG_MODVERSIONS"):
                builder.validate_final_config(config_path, profile)

    def test_final_config_rejects_duplicate_symbols_even_when_values_match(self):
        profile = builder.PROFILE_SPECS["root"]
        config_text = self._root_olddefconfig_text() + "CONFIG_KSU=y\n"
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            config_path = Path(temporary_dir) / ".config"
            config_path.write_text(config_text, encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "重复"):
                builder.validate_final_config(config_path, profile)


class KpmTests(unittest.TestCase):
    def test_kpm_patcher_can_be_prepared_without_a_runner(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            patch_repo = Path(temporary_dir) / "SukiSU_patch"
            patch_linux = patch_repo / "kpm" / "patch_linux"
            dependency = write_elf64_x86_64(patch_linux)
            patch_linux.chmod(0o644)

            prepared, digest = builder.prepare_kpm_patcher(patch_repo, dependency)

            self.assertEqual(prepared, patch_linux.resolve())
            self.assertEqual(digest, dependency["kpm_patch_sha256"])
            self.assertTrue(os.access(prepared, os.X_OK))

    def test_kpm_validates_local_patcher_backs_up_and_replaces_image(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            patch_repo = root / "SukiSU_patch"
            patch_linux = patch_repo / "kpm" / "patch_linux"
            dependency = write_elf64_x86_64(patch_linux)
            patch_linux.chmod(0o644)
            image = root / "dist" / "Image"
            write_arm64_image(image, marker=b"pre-kpm")
            pre_hash = builder.sha256_file(image)

            def create_output(args, kwargs):
                write_arm64_image(Path(kwargs["cwd"], "oImage"), marker=b"post-kpm")

            runner = RecordingRunner(on_run=create_output)
            audit = builder.apply_kpm(runner, patch_repo, image, dependency)

            self.assertEqual(audit["patcher_sha256"], dependency["kpm_patch_sha256"])
            self.assertEqual(audit["pre_image_sha256"], pre_hash)
            self.assertEqual(audit["post_image_sha256"], builder.sha256_file(image))
            self.assertNotEqual(audit["pre_image_sha256"], audit["post_image_sha256"])
            self.assertEqual(builder.sha256_file(image.parent / "Image.pre-kpm"), pre_hash)
            self.assertEqual(runner.calls[0][0], [str(patch_linux.resolve())])
            self.assertEqual(runner.calls[0][1]["cwd"], image.parent)
            self.assertTrue(os.access(patch_linux, os.X_OK))
            if os.name != "nt":
                mode = stat.S_IMODE(patch_linux.stat().st_mode)
                self.assertTrue(mode & stat.S_IXUSR)
                self.assertFalse(mode & (stat.S_IXGRP | stat.S_IXOTH))

    def test_kpm_stops_when_oimage_is_missing_or_empty(self):
        for output in (None, b""):
            with self.subTest(output=output), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                root = Path(temporary_dir)
                patch_repo = root / "SukiSU_patch"
                patch_linux = patch_repo / "kpm" / "patch_linux"
                dependency = write_elf64_x86_64(patch_linux)
                image = root / "Image"
                write_arm64_image(image)

                def maybe_create_output(args, kwargs):
                    if output is not None:
                        Path(kwargs["cwd"], "oImage").write_bytes(output)

                with self.assertRaises(RuntimeError):
                    builder.apply_kpm(
                        RecordingRunner(on_run=maybe_create_output),
                        patch_repo,
                        image,
                        dependency,
                    )

    def test_kpm_rejects_identity_or_elf_mismatch_before_execution(self):
        cases = (
            ("hash", None),
            ("size", None),
            ("class", 1),
            ("data", 2),
            ("machine", 183),
        )
        for field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                root = Path(temporary_dir)
                patch_repo = root / "SukiSU_patch"
                patch_linux = patch_repo / "kpm" / "patch_linux"
                dependency = write_elf64_x86_64(patch_linux)
                if field == "hash":
                    dependency["kpm_patch_sha256"] = "0" * 64
                elif field == "size":
                    dependency["kpm_patch_size"] += 1
                elif field == "class":
                    data = bytearray(patch_linux.read_bytes())
                    data[4] = value
                    patch_linux.write_bytes(data)
                    dependency["kpm_patch_sha256"] = hashlib.sha256(data).hexdigest()
                elif field == "data":
                    data = bytearray(patch_linux.read_bytes())
                    data[5] = value
                    patch_linux.write_bytes(data)
                    dependency["kpm_patch_sha256"] = hashlib.sha256(data).hexdigest()
                else:
                    data = bytearray(patch_linux.read_bytes())
                    struct.pack_into("<H", data, 18, value)
                    patch_linux.write_bytes(data)
                    dependency["kpm_patch_sha256"] = hashlib.sha256(data).hexdigest()
                image = write_arm64_image(root / "Image")
                runner = RecordingRunner()
                with self.assertRaises((ValueError, RuntimeError)):
                    builder.apply_kpm(runner, patch_repo, image, dependency)
                self.assertEqual(runner.calls, [])

    def test_kpm_rejects_unsafe_metadata_path_and_unchanged_image(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            patch_repo = root / "SukiSU_patch"
            patch_linux = patch_repo / "kpm" / "patch_linux"
            dependency = write_elf64_x86_64(patch_linux)
            image = write_arm64_image(root / "Image", marker=b"same")
            unsafe = dict(dependency, kpm_patch_path="../patch_linux")
            with self.assertRaises(ValueError):
                builder.apply_kpm(RecordingRunner(), patch_repo, image, unsafe)

            def copy_unchanged(args, kwargs):
                source = Path(kwargs["cwd"], "Image.pre-kpm")
                shutil.copy2(source, Path(kwargs["cwd"], "oImage"))

            with self.assertRaisesRegex(RuntimeError, "SHA"):
                builder.apply_kpm(RecordingRunner(on_run=copy_unchanged), patch_repo, image, dependency)


class SourceIntegrationTests(unittest.TestCase):
    def _make_common_tree(self, root):
        common = root / "common"
        for directory in (
            common / "drivers",
            common / "security",
            common / "fs",
            common / "include" / "linux",
            common / "arch" / "arm64" / "configs",
        ):
            directory.mkdir(parents=True, exist_ok=True)
        (common / "drivers" / "Makefile").write_text("obj-y += base/\n", encoding="utf-8")
        (common / "drivers" / "Kconfig").write_text('source "drivers/base/Kconfig"\n', encoding="utf-8")
        (common / "security" / "Makefile").write_text("obj-y += commoncap.o\n", encoding="utf-8")
        (common / "security" / "Kconfig").write_text('source "security/selinux/Kconfig"\n', encoding="utf-8")
        return common

    def test_exact_line_insertion_is_idempotent(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            path = Path(temporary_dir) / "Makefile"
            path.write_text("obj-y += base/\n", encoding="utf-8")
            builder.ensure_exact_line(path, "obj-$(CONFIG_KSU) += kernelsu/")
            builder.ensure_exact_line(path, "obj-$(CONFIG_KSU) += kernelsu/")
            text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count("obj-$(CONFIG_KSU) += kernelsu/"), 1)

    def test_kernelsu_is_integrated_by_relative_symlink_and_exact_lines(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            ksu = root / "work" / "KernelSU"
            (ksu / "kernel").mkdir(parents=True)
            (ksu / "kernel" / "Kconfig").write_text("config KSU\n", encoding="utf-8")
            (ksu / "kernel" / "Makefile").write_text("obj-y += core.o\n", encoding="utf-8")
            link = common / "drivers" / "kernelsu"
            expected_target = os.path.relpath(ksu / "kernel", link.parent)
            with mock.patch("mayfly_builder.os.symlink") as symlink_mock:
                builder.integrate_kernelsu(common, ksu)
            symlink_mock.assert_called_once_with(expected_target, link, target_is_directory=True)
            self.assertIn(
                "obj-$(CONFIG_KSU) += kernelsu/",
                (common / "drivers" / "Makefile").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'source "drivers/kernelsu/Kconfig"',
                (common / "drivers" / "Kconfig").read_text(encoding="utf-8"),
            )

    def test_kernelsu_missing_build_files_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            ksu = root / "KernelSU"
            (ksu / "kernel").mkdir(parents=True)
            with self.assertRaises(FileNotFoundError):
                builder.integrate_kernelsu(common, ksu)

    def test_susfs_copy_and_both_strict_patches_are_required(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            ksu = root / "work" / "KernelSU"
            ksu.mkdir(parents=True)
            susfs = root / "work" / "susfs4ksu" / "kernel_patches"
            (susfs / "KernelSU").mkdir(parents=True)
            (susfs / "fs").mkdir()
            (susfs / "include" / "linux").mkdir(parents=True)
            (susfs / "KernelSU" / "10_enable_susfs_for_ksu.patch").write_text("patch ksu\n", encoding="utf-8")
            (susfs / "50_add_susfs_in_gki-android12-5.10.patch").write_text("patch common\n", encoding="utf-8")
            (susfs / "fs" / "susfs.c").write_text("source\n", encoding="utf-8")
            (susfs / "include" / "linux" / "susfs.h").write_text("header\n", encoding="utf-8")
            kbuild = ksu / "kernel" / "Kbuild"
            kbuild.parent.mkdir()
            kbuild.write_text(dynamic_kernelsu_kbuild(), encoding="utf-8")

            builder.integrate_susfs(
                runner,
                common,
                ksu,
                susfs.parent,
                {
                    "commit": "278d822a4ebd214bcfd774b7910cb11cdc560bb9",
                    "version_name": "4.1.3",
                    "version_code": 40796,
                },
                json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]["susfs4ksu"],
            )

            self.assertEqual((common / "fs" / "susfs.c").read_text(encoding="utf-8"), "source\n")
            self.assertEqual((common / "include" / "linux" / "susfs.h").read_text(encoding="utf-8"), "header\n")
            pinned_kbuild = kbuild.read_text(encoding="utf-8")
            self.assertIn("KSU_VERSION := 40796", pinned_kbuild)
            self.assertIn("KSU_VERSION_FULL := v4.1.3-278d822a@pinned", pinned_kbuild)
        self.assertEqual(len(runner.calls), 6)
        self.assertEqual(runner.calls[0][1]["cwd"], ksu)
        self.assertIn("--exclude=kernel/core/init.c", runner.calls[0][0])
        self.assertIn("--exclude=kernel/policy/app_profile.h", runner.calls[0][0])
        self.assertEqual(runner.calls[2][1]["cwd"], ksu)
        self.assertEqual(runner.calls[2][0][-1], str(PATCHES_DIR / "sukisu-v4.1.3-susfs-v2.2.0-compat.patch"))
        self.assertEqual(runner.calls[4][1]["cwd"], common)
        self.assertIn("--exclude=fs/proc/task_mmu.c", runner.calls[4][0])

    def test_kernelsu_kbuild_dynamic_version_block_is_replaced_exactly(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            kbuild = Path(temporary_dir) / "Kbuild"
            kbuild.write_text(dynamic_kernelsu_kbuild(), encoding="utf-8")
            version = builder.pin_kernelsu_kbuild(
                kbuild,
                version_name="4.1.3",
                version_code=40796,
                commit="278d822a4ebd214bcfd774b7910cb11cdc560bb9",
            )
            content = kbuild.read_text(encoding="utf-8")

        self.assertEqual(
            version,
            {
                "version_name": "4.1.3",
                "version_code": 40796,
                "version_full": "v4.1.3-278d822a@pinned",
            },
        )
        self.assertIn("obj-y += core_hook.o", content)
        self.assertIn("KSU_VERSION := 40796", content)
        self.assertIn("KSU_VERSION_FULL := v4.1.3-278d822a@pinned", content)
        self.assertEqual(content.count("ccflags-y += -DKSU_VERSION=$(KSU_VERSION)"), 1)
        self.assertEqual(content.count('ccflags-y += -DKSU_VERSION_FULL=\\"$(KSU_VERSION_FULL)\\"'), 1)
        self.assertIn("ifndef KSU_EXPECTED_SIZE", content)
        for forbidden in (
            "CURL_BIN",
            "GITHUB_API",
            "fetch --unshallow",
            "releases/latest",
            "commits?sha",
            "git rev-list --count",
        ):
            self.assertNotIn(forbidden, content)

    def test_kernelsu_kbuild_requires_unique_ordered_anchors(self):
        invalid_contents = (
            "ifndef KSU_EXPECTED_SIZE\n",
            dynamic_kernelsu_kbuild() + "MDIR := duplicate\n",
            dynamic_kernelsu_kbuild() + "ifndef KSU_EXPECTED_SIZE\n",
            "ifndef KSU_EXPECTED_SIZE\nMDIR := too-late\n",
        )
        for content in invalid_contents:
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                kbuild = Path(temporary_dir) / "Kbuild"
                kbuild.write_text(content, encoding="utf-8")
                with self.assertRaises(RuntimeError):
                    builder.pin_kernelsu_kbuild(
                        kbuild,
                        version_name="4.1.3",
                        version_code=40796,
                        commit="278d822a4ebd214bcfd774b7910cb11cdc560bb9",
                    )

    def test_lz4kd_copies_only_allowed_trees_and_one_patch(self):
        runner = RecordingRunner()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            (common / "lib").mkdir()
            (common / "crypto").mkdir()
            patch_repo = root / "SukiSU_patch"
            sources = {
                patch_repo / "other" / "zram" / "lz4k" / "include" / "linux" / "lz4kd.h": "header",
                patch_repo / "other" / "zram" / "lz4k" / "lib" / "lz4kd.c": "lib",
                patch_repo / "other" / "zram" / "lz4k" / "crypto" / "crypto_lz4kd.c": "crypto",
                patch_repo / "other" / "zram" / "lz4k_oplus" / "forbidden.c": "forbidden",
            }
            for path, content in sources.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            patch = patch_repo / "other" / "zram" / "zram_patch" / "5.10" / "lz4kd.patch"
            patch.parent.mkdir(parents=True)
            patch.write_text("patch\n", encoding="utf-8")

            builder.integrate_lz4kd(runner, common, patch_repo)

            self.assertTrue((common / "include" / "linux" / "lz4kd.h").is_file())
            self.assertTrue((common / "lib" / "lz4kd.c").is_file())
            self.assertTrue((common / "crypto" / "crypto_lz4kd.c").is_file())
            self.assertFalse(any(path.name == "forbidden.c" for path in common.rglob("*")))
        self.assertEqual(len(runner.calls), 2)
        for command, kwargs in runner.calls:
            self.assertEqual(command[0:2], ["git", "apply"])
            self.assertIn("--exclude=kernel/module.c", command)
            self.assertEqual(kwargs["cwd"], common)

    def test_integrated_kernelsu_rejects_compiled_uts_spoof_paths(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            kernel = Path(temporary_dir) / "kernel"
            (kernel / "core").mkdir(parents=True)
            (kernel / "policy").mkdir()
            (kernel / "supercall").mkdir()
            files = {
                kernel / "Kbuild": "kernelsu-objs += core/init.o\n",
                kernel / "core" / "init.c": (
                    "void init(void) {\n"
                    "    susfs_init();\n"
                    "    ksu_sucompat_init();\n"
                    "    ksu_setuid_hook_init();\n"
                    "}\n"
                ),
                kernel / "policy" / "app_profile.h": (
                    "int escape_to_root_for_init(void);\n"
                    "void escape_to_root_for_cmd_su(uid_t target_uid, pid_t target_pid);\n"
                ),
                kernel / "supercall" / "dispatch.c": "static int dispatch(void) { return 0; }\n",
            }
            for path, content in files.items():
                path.write_text(content, encoding="utf-8")

            builder.validate_kernelsu_hardening(kernel.parent)

            forbidden_cases = (
                (kernel / "Kbuild", "kernelsu-objs += feature/uts_spoof.o\n"),
                (kernel / "core" / "init.c", "ksu_spoof_version(NULL, NULL);\n"),
                (kernel / "supercall" / "dispatch.c", "KSU_IOCTL_SET_SPOOF_VERSION\n"),
            )
            for path, forbidden in forbidden_cases:
                with self.subTest(path=path.name):
                    original = path.read_text(encoding="utf-8")
                    path.write_text(original + forbidden, encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "UTS"):
                        builder.validate_kernelsu_hardening(kernel.parent)
                    path.write_text(original, encoding="utf-8")

    def test_bbg_is_non_destructively_integrated_and_blocks_stay_disabled(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            bbg = root / "work" / "Baseband-guard"
            bbg.mkdir(parents=True)
            (bbg / "Kconfig").write_text("config BBG\n", encoding="utf-8")
            (bbg / "Makefile").write_text("obj-y += bbg.o\n", encoding="utf-8")
            link = common / "security" / "baseband-guard"
            expected_target = os.path.relpath(bbg, link.parent)
            with mock.patch("mayfly_builder.os.symlink") as symlink_mock:
                builder.integrate_bbg(common, bbg)
            symlink_mock.assert_called_once_with(expected_target, link, target_is_directory=True)
            self.assertIn(
                "obj-$(CONFIG_BBG) += baseband-guard/",
                (common / "security" / "Makefile").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'source "security/baseband-guard/Kconfig"',
                (common / "security" / "Kconfig").read_text(encoding="utf-8"),
            )

    def test_bbg_missing_build_files_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            bbg = root / "Baseband-guard"
            bbg.mkdir()
            with self.assertRaises(FileNotFoundError):
                builder.integrate_bbg(common, bbg)

    def test_profile_defconfig_and_check_defconfig_change_are_exact(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            common = self._make_common_tree(root)
            defconfig = common / "arch" / "arm64" / "configs" / "gki_defconfig"
            defconfig.write_text(
                'CONFIG_LSM="lockdown,yama,integrity"\nCONFIG_KSU=n\nCONFIG_KSU=n\n',
                encoding="utf-8",
            )
            build_config = common / "build.config.gki"
            original_guard_lines = (
                "KMI_SYMBOL_LIST_STRICT_MODE=1\n"
                "TRIM_NONLISTED_KMI=1\n"
                "KMI_ENFORCED=1\n"
            )
            build_config.write_text(
                'POST_DEFCONFIG_CMDS="check_defconfig"\n' + original_guard_lines,
                encoding="utf-8",
            )

            result = builder.configure_profile_defconfig(
                common,
                builder.PROFILE_SPECS["balanced-bbg"],
            )

            configured = defconfig.read_text(encoding="utf-8")
            self.assertEqual(configured.count("CONFIG_KSU=y"), 1)
            self.assertIn("# CONFIG_KSU_SUSFS_SUS_MAP is not set", configured)
            self.assertIn("# CONFIG_BBG_BLOCK_BOOT is not set", configured)
            self.assertIn("# CONFIG_BBG_BLOCK_RECOVERY is not set", configured)
            self.assertIn(
                'CONFIG_LSM="lockdown,yama,integrity,baseband_guard"',
                configured,
            )
            changed_build_config = build_config.read_text(encoding="utf-8")
            self.assertIn('POST_DEFCONFIG_CMDS=""', changed_build_config)
            self.assertIn(original_guard_lines, changed_build_config)
            self.assertEqual(result["defconfig"], defconfig)
            self.assertEqual(result["check_defconfig_file"], build_config)

    def test_check_defconfig_missing_or_ambiguous_stops(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            common = Path(temporary_dir)
            (common / "build.config.gki").write_text("KMI_ENFORCED=1\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "check_defconfig"):
                builder.disable_check_defconfig(common)

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            common = Path(temporary_dir)
            for name in ("build.config.gki", "build.config.gki.aarch64"):
                (common / name).write_text('POST_DEFCONFIG_CMDS="check_defconfig"\n', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "check_defconfig"):
                builder.disable_check_defconfig(common)


class BuildOrchestrationTests(unittest.TestCase):
    def test_prepare_workspace_rejects_existing_state(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            workspace = root / "workspace"
            artifacts = root / "artifacts"
            mayfly = builder.MayflyBuilder("stock-5.10.226", "root", workspace, artifacts)
            mayfly._prepare_workspace()
            self.assertTrue((workspace / "tools").is_dir())
            self.assertTrue((workspace / "work").is_dir())
            with self.assertRaises(FileExistsError):
                mayfly._prepare_workspace()

    def test_repo_tool_version_is_checked_with_current_python(self):
        dependencies = builder.load_dependencies()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = builder.MayflyBuilder(
                "stock-5.10.226",
                "root",
                root / "workspace",
                root / "artifacts",
            )
            mayfly._prepare_workspace()
            mayfly.runner = RecordingRunner(outputs=["repo launcher version 2.15\n"])

            def materialize_repo(runner, dependency, destination):
                destination.mkdir(parents=True)
                (destination / "repo").write_text("launcher\n", encoding="utf-8")

            with mock.patch("mayfly_builder.clone_pinned_dependency", side_effect=materialize_repo):
                repo_tool = mayfly._prepare_repo_tool(dependencies)

            self.assertEqual(
                mayfly.runner.calls,
                [([sys.executable, str(repo_tool), "--version"], {"capture_output": True})],
            )

    def test_repo_tool_version_mismatch_stops(self):
        dependencies = builder.load_dependencies()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = builder.MayflyBuilder(
                "stock-5.10.226",
                "root",
                root / "workspace",
                root / "artifacts",
            )
            mayfly._prepare_workspace()
            mayfly.runner = RecordingRunner(outputs=["repo launcher version 2.16\n"])

            def materialize_repo(runner, dependency, destination):
                destination.mkdir(parents=True)
                (destination / "repo").write_text("launcher\n", encoding="utf-8")

            with mock.patch("mayfly_builder.clone_pinned_dependency", side_effect=materialize_repo):
                with self.assertRaisesRegex(RuntimeError, "2.15"):
                    mayfly._prepare_repo_tool(dependencies)

    def test_superproject_is_cloned_and_ls_tree_is_parsed_before_repo_init(self):
        dependencies = builder.load_dependencies()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = builder.MayflyBuilder(
                "stock-5.10.226",
                "root",
                root / "workspace",
                root / "artifacts",
            )
            mayfly._prepare_workspace()
            mayfly.runner = RecordingRunner(
                outputs=[superproject_ls_tree(mayfly.source.common_commit)]
            )
            with mock.patch("mayfly_builder.clone_pinned_dependency") as clone_mock:
                pins = mayfly._prepare_superproject(dependencies)

            clone_mock.assert_called_once_with(
                mayfly.runner,
                dependencies[mayfly.source.superproject_dependency],
                mayfly.workspace / "work" / "superproject",
            )
            self.assertEqual(pins, superproject_core_pins(mayfly.source.common_commit))
            ls_tree_command = mayfly.runner.calls[0][0]
            self.assertEqual(
                ls_tree_command,
                [
                    "git",
                    "-C",
                    str(mayfly.workspace / "work" / "superproject"),
                    "ls-tree",
                    "-r",
                    mayfly.source.superproject_commit,
                ],
            )

    def test_source_sync_rewrites_manifest_verifies_common_and_resolves_all_shas(self):
        dependencies = builder.load_dependencies()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            workspace = root / "workspace"
            mayfly = builder.MayflyBuilder(
                "stock-5.10.226",
                "root",
                workspace,
                root / "artifacts",
            )
            mayfly._prepare_workspace()
            repo_tool = workspace / "tools" / "git-repo" / "repo"
            repo_tool.parent.mkdir(parents=True)
            repo_tool.write_text("launcher\n", encoding="utf-8")
            project_pins = superproject_core_pins(mayfly.source.common_commit)

            def materialize_repo_outputs(args, kwargs):
                source_root = workspace / "source"
                if "init" in args:
                    manifest = source_root / ".repo" / "manifests" / "default.xml"
                    manifest.parent.mkdir(parents=True)
                    projects = "".join(
                        f'<project name="kernel/{index}" path="{path}" revision="old" />'
                        for index, path in enumerate(SUPERPROJECT_CORE_PATHS)
                    )
                    manifest.write_text(f"<manifest>{projects}</manifest>", encoding="utf-8")
                elif "sync" in args:
                    (source_root / "common").mkdir()
                elif "manifest" in args:
                    output = Path(args[args.index("-o") + 1])
                    projects = "".join(
                        f'<project name="kernel/{index}" path="{path}" revision="{project_pins[path]}" />'
                        for index, path in enumerate(SUPERPROJECT_CORE_PATHS)
                    )
                    output.write_text(f"<manifest>{projects}</manifest>", encoding="utf-8")

            mayfly.runner = RecordingRunner(
                outputs=[mayfly.source.common_commit + "\n"],
                on_run=materialize_repo_outputs,
            )
            source_root = mayfly._sync_source(dependencies, repo_tool, project_pins)

            manifest = ET.parse(source_root / ".repo" / "manifests" / "default.xml").getroot()
            self.assertEqual(
                {project.get("path"): project.get("revision") for project in manifest.iter("project")},
                project_pins,
            )
            self.assertTrue((source_root / "resolved-manifest.xml").is_file())
            commands = [call[0] for call in mayfly.runner.calls]
            sync_command = next(command for command in commands if "sync" in command)
            self.assertIn("--fail-fast", sync_command)
            self.assertIn("--no-manifest-update", sync_command)
            self.assertTrue(any("manifest" in command and "-r" in command for command in commands))

    def test_repository_clones_are_profile_conditional_and_bbg_is_not_shallow(self):
        dependencies = builder.load_dependencies()
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = builder.MayflyBuilder(
                "security-5.10.236-r1",
                "balanced-bbg",
                root / "workspace",
                root / "artifacts",
            )
            mayfly._prepare_workspace()
            with mock.patch("mayfly_builder.clone_pinned_dependency") as clone_mock:
                repositories = mayfly._clone_dependencies(dependencies)

            self.assertEqual(set(repositories), {"kernelsu", "susfs", "sukisu_patch", "bbg"})
            self.assertEqual(clone_mock.call_count, 4)
            bbg_call = [call for call in clone_mock.call_args_list if call.args[1] is dependencies["baseband_guard"]][0]
            self.assertFalse(bbg_call.kwargs["shallow"])

    def test_final_output_validation_rechecks_resolved_common_commit(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = builder.MayflyBuilder(
                "security-5.10.236-r1",
                "root",
                root / "workspace",
                root / "artifacts",
            )
            source_root = root / "source"
            mayfly._manifest_pins = superproject_core_pins(mayfly.source.common_commit)
            with mock.patch("mayfly_builder.validate_final_config"), mock.patch(
                "mayfly_builder.validate_kernel_release"
            ), mock.patch("mayfly_builder.validate_image"), mock.patch(
                "mayfly_builder.validate_resolved_manifest"
            ) as manifest_mock:
                mayfly._validate_build_outputs(source_root)

            manifest_mock.assert_called_once_with(
                source_root / "resolved-manifest.xml",
                expected_common_commit=mayfly.source.common_commit,
                expected_projects=mayfly._manifest_pins,
            )

    def test_build_pipeline_order_and_success_summary(self):
        events = []

        class Harness(builder.MayflyBuilder):
            def _prepare_workspace(self):
                events.append("workspace")

            def _prepare_repo_tool(self, dependencies):
                events.append("repo-tool")
                return Path("repo")

            def _prepare_superproject(self, dependencies):
                events.append("superproject")
                return {"common": self.source.common_commit}

            def _sync_source(self, dependencies, repo_tool, project_pins):
                events.append("sync")
                return Path("source")

            def _clone_dependencies(self, dependencies):
                events.append("clone")
                return {"kernelsu": Path("ksu"), "susfs": Path("susfs")}

            def _integrate_sources(self, source_root, repositories, dependencies):
                events.append("integrate")

            def _configure_source(self, source_root):
                events.append("configure")

            def _run_kernel_build(self, source_root):
                events.append("build")

            def _validate_build_outputs(self, source_root):
                events.append("validate")

            def _apply_kpm_if_enabled(self, source_root, repositories, dependencies):
                events.append("kpm")
                return None

            def _publish_build_outputs(self, dependencies, source_root, kpm_hash):
                events.append("publish")
                return {"Image": "a" * 64}

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = Harness("stock-5.10.226", "root", root / "workspace", root / "artifacts")
            summary = mayfly.build()

        self.assertEqual(
            events,
            [
                "workspace",
                "repo-tool",
                "superproject",
                "sync",
                "clone",
                "integrate",
                "configure",
                "build",
                "validate",
                "kpm",
                "publish",
            ],
        )
        self.assertEqual(summary["mode"], "build")
        self.assertEqual(summary["source"], "stock-5.10.226")
        self.assertEqual(summary["profile"], "root")
        self.assertEqual(summary["files"], {"Image": "a" * 64})

    def test_build_failure_stops_before_validation_and_publish(self):
        events = []

        class FailingHarness(builder.MayflyBuilder):
            def _prepare_workspace(self):
                events.append("workspace")

            def _prepare_repo_tool(self, dependencies):
                return Path("repo")

            def _prepare_superproject(self, dependencies):
                return {"common": self.source.common_commit}

            def _sync_source(self, dependencies, repo_tool, project_pins):
                return Path("source")

            def _clone_dependencies(self, dependencies):
                return {}

            def _integrate_sources(self, source_root, repositories, dependencies):
                events.append("integrate")

            def _configure_source(self, source_root):
                events.append("configure")

            def _run_kernel_build(self, source_root):
                events.append("build")
                raise subprocess.CalledProcessError(2, ["build/build.sh"])

            def _validate_build_outputs(self, source_root):
                events.append("validate")

            def _publish_build_outputs(self, dependencies, source_root, kpm_hash):
                events.append("publish")
                return {}

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = FailingHarness("stock-5.10.226", "root", root / "workspace", root / "artifacts")
            with self.assertRaises(subprocess.CalledProcessError):
                mayfly.build()
        self.assertEqual(events, ["workspace", "integrate", "configure", "build"])

    def test_build_logs_each_major_stage(self):
        class LoggingHarness(builder.MayflyBuilder):
            def _prepare_workspace(self):
                return None

            def _prepare_repo_tool(self, dependencies):
                return Path("repo")

            def _prepare_superproject(self, dependencies):
                return {"common": self.source.common_commit}

            def _sync_source(self, dependencies, repo_tool, project_pins):
                return Path("source")

            def _clone_dependencies(self, dependencies):
                return {}

            def _integrate_sources(self, source_root, repositories, dependencies):
                return None

            def _configure_source(self, source_root):
                return None

            def _run_kernel_build(self, source_root):
                return None

            def _validate_build_outputs(self, source_root):
                return None

            def _apply_kpm_if_enabled(self, source_root, repositories, dependencies):
                return None

            def _publish_build_outputs(self, dependencies, source_root, kpm_hash):
                return {"Image": "a" * 64}

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            mayfly = LoggingHarness("stock-5.10.226", "root", root / "workspace", root / "artifacts")
            with self.assertLogs("mayfly_builder", level="INFO") as captured:
                mayfly.build()
        log_text = "\n".join(captured.output)
        for stage in (
            "workspace",
            "repo",
            "superproject",
            "sync",
            "clone",
            "integrate",
            "configure",
            "build",
            "validate",
            "publish",
        ):
            self.assertIn(stage, log_text)


class BuildAndArtifactTests(unittest.TestCase):
    def test_build_invocation_is_full_lto_build_sh_and_four_jobs_max(self):
        command = builder.kernel_build_command(Path("source"), jobs=4)
        self.assertEqual(command, [str(Path("source/build/build.sh")), "-j4"])
        environment = builder.kernel_build_environment({"PATH": "/safe/bin"})
        self.assertEqual(environment["BUILD_CONFIG"], "common/build.config.gki.aarch64")
        self.assertEqual(environment["LTO"], "full")
        self.assertEqual(environment["PATH"], "/safe/bin")
        for jobs in (0, 5):
            with self.subTest(jobs=jobs):
                with self.assertRaises(ValueError):
                    builder.kernel_build_command(Path("source"), jobs=jobs)

    def test_release_and_image_validation_are_fail_closed(self):
        source = builder.SOURCE_SPECS["stock-5.10.226"]
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            release = root / "kernel.release"
            release.write_text(source.expected_release_prefix + "-g123\n", encoding="utf-8")
            self.assertEqual(builder.validate_kernel_release(release, source), source.expected_release_prefix + "-g123")
            release.write_text("5.10.999-unsafe\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                builder.validate_kernel_release(release, source)
            release.write_text(source.expected_release_prefix + "\nextra-line\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                builder.validate_kernel_release(release, source)

            image = write_arm64_image(
                root / "Image",
                marker=b"valid",
                actual_size=8 * 1024 * 1024 + 4096,
            )
            builder.validate_image(image)

    def test_image_validation_rejects_invalid_arm64_headers_and_sizes(self):
        cases = (
            ("short", 8 * 1024 * 1024, 7 * 1024 * 1024, None),
            ("small-header", 8 * 1024 * 1024 - 1, 8 * 1024 * 1024, None),
            ("large-header", 256 * 1024 * 1024 + 1, 8 * 1024 * 1024, None),
            ("truncated", 9 * 1024 * 1024, 8 * 1024 * 1024, None),
            ("magic", 8 * 1024 * 1024, 8 * 1024 * 1024, b"NOPE"),
        )
        for name, image_size, actual_size, replacement_magic in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                image = write_arm64_image(
                    Path(temporary_dir) / "Image",
                    image_size=image_size,
                    actual_size=actual_size,
                )
                if replacement_magic is not None:
                    with image.open("r+b") as output:
                        output.seek(0x38)
                        output.write(replacement_magic)
                with self.assertRaises((ValueError, RuntimeError)):
                    builder.validate_image(image)

    def test_image_validation_rejects_tiny_nonempty_file(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            image = Path(temporary_dir) / "Image"
            image.write_bytes(b"image")
            with self.assertRaises((ValueError, RuntimeError)):
                builder.validate_image(image)

    def _make_artifact_sources(self, root):
        names = (
            "Image",
            "final.config",
            "resolved-manifest.xml",
            "kernel.release",
        )
        sources = {}
        source_dir = root / "source-files"
        source_dir.mkdir()
        for name in names:
            path = source_dir / name
            path.write_text(f"content for {name}\n", encoding="utf-8")
            sources[name] = path
        return sources

    def test_artifacts_are_new_regular_nonempty_and_checksummed(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            workspace = Path(temporary_dir)
            sources = self._make_artifact_sources(workspace)
            artifacts = workspace / "artifacts"
            info = {"source": "stock-5.10.226", "features": {"kpm": False}}
            hashes = builder.publish_artifacts(workspace, artifacts, sources, info)

            expected = set(sources) | {"BUILD_INFO.json", "SHA256SUMS.txt"}
            self.assertEqual({path.name for path in artifacts.iterdir()}, expected)
            for path in artifacts.iterdir():
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                self.assertGreater(path.stat().st_size, 0)
            self.assertEqual(set(hashes), set(sources))
            build_info = json.loads((artifacts / "BUILD_INFO.json").read_text(encoding="utf-8"))
            self.assertEqual(build_info["files"], hashes)
            sums = (artifacts / "SHA256SUMS.txt").read_text(encoding="utf-8")
            self.assertIn("  Image\n", sums)
            self.assertIn("  BUILD_INFO.json\n", sums)

    def test_artifacts_reject_existing_target_empty_outside_and_zero_sources(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            workspace = Path(temporary_dir)
            sources = self._make_artifact_sources(workspace)
            artifacts = workspace / "artifacts"
            artifacts.mkdir()
            (artifacts / "old-file").write_text("stale", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                builder.publish_artifacts(workspace, artifacts, sources, {})

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            workspace = Path(temporary_dir)
            empty = workspace / "empty"
            empty.touch()
            with self.assertRaises(ValueError):
                builder.publish_artifacts(workspace, workspace / "artifacts", {"Image": empty}, {})
            with self.assertRaises(ValueError):
                builder.publish_artifacts(workspace, workspace / "zero", {}, {})

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as workspace_dir, tempfile.TemporaryDirectory(
            dir=REPO_ROOT
        ) as outside_dir:
            workspace = Path(workspace_dir)
            outside = Path(outside_dir) / "Image"
            outside.write_bytes(b"outside")
            with self.assertRaises(ValueError):
                builder.publish_artifacts(workspace, workspace / "artifacts", {"Image": outside}, {})

    def test_artifacts_reject_symlink_source(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            workspace = Path(temporary_dir)
            target = workspace / "target"
            target.write_bytes(b"image")
            link = workspace / "Image"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaises(ValueError):
                builder.publish_artifacts(workspace, workspace / "artifacts", {"Image": link}, {})

    def test_build_info_records_pins_features_lto_exclusion_and_kpm_hash(self):
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]
        dependencies["sukisu_patch"]["kpm_patch_sha256"] = "a" * 64
        kpm_audit = {
            "patcher_sha256": "a" * 64,
            "pre_image_sha256": "b" * 64,
            "post_image_sha256": "c" * 64,
        }
        info = builder.make_build_info(
            builder.SOURCE_SPECS["stock-5.10.226"],
            builder.PROFILE_SPECS["root-kpm"],
            dependencies,
            kpm_audit=kpm_audit,
        )
        self.assertEqual(info["lto"], "full")
        self.assertEqual(info["source"]["common_commit"], "ea4a6f067d3f7ae0ae3d460716449adf06a5ff15")
        self.assertTrue(info["features"]["kpm"])
        self.assertEqual(
            info["kpm_patcher_sha256"],
            "a" * 64,
        )
        self.assertEqual(
            info["kpm"],
            {
                "patcher": {
                    "path": "kpm/patch_linux",
                    "sha256": "a" * 64,
                    "size": 6013320,
                },
                "pre_image": {"sha256": "b" * 64},
                "post_image": {"sha256": "c" * 64},
            },
        )
        self.assertIn("SukiSU_patch/69_hide_stuff.patch", info["excluded_patches"])
        self.assertEqual(info["patch_exclusions"], builder.PATCH_EXCLUSIONS)
        self.assertEqual(
            info["local_patches"]["sukisu_susfs_compat"]["sha256"],
            "8b0493e5485196ac808076906479feb9a6955c1d19abaeeb59509ba8105c09fe",
        )
        self.assertEqual(
            info["dependencies"]["sukisu_ultra"],
            dependencies["sukisu_ultra"]["commit"],
        )
        self.assertTrue(info["check_defconfig_disabled"])
        self.assertTrue(info["final_config_validation"])
        self.assertEqual(
            info["kernelsu"],
            {
                "version_name": "4.1.3",
                "version_code": 40796,
                "version_full": "v4.1.3-278d822a@pinned",
            },
        )

    def test_build_info_rejects_incomplete_or_mismatched_kpm_audit(self):
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]
        dependencies["sukisu_patch"]["kpm_patch_sha256"] = "a" * 64
        source = builder.SOURCE_SPECS["stock-5.10.226"]
        profile = builder.PROFILE_SPECS["root-kpm"]
        with self.assertRaises(ValueError):
            builder.make_build_info(
                source,
                profile,
                dependencies,
                kpm_patcher_sha256="a" * 64,
            )
        with self.assertRaises(ValueError):
            builder.make_build_info(
                source,
                profile,
                dependencies,
                kpm_audit={
                    "patcher_sha256": "0" * 64,
                    "pre_image_sha256": "b" * 64,
                    "post_image_sha256": "c" * 64,
                },
            )

    def test_security_build_info_uses_only_frozen_r1_common(self):
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]
        info = builder.make_build_info(
            builder.SOURCE_SPECS["security-5.10.236-r1"],
            builder.PROFILE_SPECS["root"],
            dependencies,
        )
        self.assertEqual(
            info["dependencies"]["android_common_2025_05_r1"],
            "b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e",
        )
        self.assertNotIn("android_common_2025_05", info["dependencies"])
        self.assertNotIn("fbb4c9b0aa2909575b240a5404b6a3eaa1d2755d", json.dumps(info))


class CliAndWorkflowTests(unittest.TestCase):
    def test_cli_requires_explicit_source_and_profile(self):
        cli = importlib.import_module("build_mayfly")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.parse_args(["--dry-run"])

    def test_dry_run_prints_json_without_creating_workspace_or_artifacts(self):
        cli = importlib.import_module("build_mayfly")
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            workspace = root / "workspace"
            artifacts = root / "artifacts"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = cli.main(
                    [
                        "--source",
                        "stock-5.10.226",
                        "--profile",
                        "root",
                        "--workspace",
                        str(workspace),
                        "--artifacts",
                        str(artifacts),
                        "--dry-run",
                    ]
                )
            summary = json.loads(stdout.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(summary["mode"], "dry-run")
            self.assertEqual(summary["source"]["name"], "stock-5.10.226")
            self.assertEqual(summary["profile"]["name"], "root")
            self.assertFalse(summary["profile"]["features"]["kpm"])
            self.assertFalse(workspace.exists())
            self.assertFalse(artifacts.exists())

    def test_kpm_profiles_dry_run_rejects_noncanonical_patcher_hash(self):
        for profile in ("root-kpm", "balanced", "balanced-bbg"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
                root = Path(temporary_dir)
                payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
                payload["dependencies"]["sukisu_patch"]["kpm_patch_sha256"] = (
                    "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2"
                )
                lock_path = root / "dependencies.lock.json"
                lock_path.write_text(json.dumps(payload), encoding="utf-8")
                workspace = root / "workspace"
                artifacts = root / "artifacts"
                mayfly = builder.MayflyBuilder(
                    "stock-5.10.226",
                    profile,
                    workspace,
                    artifacts,
                    lock_path=lock_path,
                )
                with self.assertRaisesRegex(ValueError, "64"):
                    mayfly.dry_run()
                self.assertFalse(workspace.exists())
                self.assertFalse(artifacts.exists())

    def test_all_source_profile_dry_runs_succeed_without_state(self):
        for source in builder.SOURCE_SPECS:
            for profile in builder.PROFILE_SPECS:
                with self.subTest(source=source, profile=profile), tempfile.TemporaryDirectory(
                    dir=REPO_ROOT
                ) as temporary_dir:
                    root = Path(temporary_dir)
                    workspace = root / "workspace"
                    artifacts = root / "artifacts"
                    summary = builder.MayflyBuilder(
                        source,
                        profile,
                        workspace,
                        artifacts,
                    ).dry_run()
                    self.assertEqual(summary["source"]["name"], source)
                    self.assertEqual(summary["profile"]["name"], profile)
                    self.assertFalse(workspace.exists())
                    self.assertFalse(artifacts.exists())

    def test_workflow_is_read_only_pinned_and_dedicated(self):
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        expected_actions = {
            "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
            "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
            "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
            "AdityaGarg8/remove-unwanted-software": "90e01b21170618765a73370fcc3abbd1684a7793",
        }
        for action, commit in expected_actions.items():
            with self.subTest(action=action):
                self.assertIn(f"uses: {action}@{commit}", text)

        self.assertRegex(text, r"permissions:\s*\n\s+contents:\s*read")
        self.assertIn("build_mayfly.py", text)
        self.assertNotIn("kernel_builder.py", text)
        self.assertNotRegex(text, r"(?m)^\s*python3?\s+[^\n]*\bbuild\.py\b")
        self.assertIn("set -euo pipefail", text)
        self.assertIn("args=(", text)
        self.assertIn("timeout-minutes: 180", text)
        self.assertIn("concurrency:", text)
        self.assertIn("if-no-files-found: error", text)
        self.assertIn("retention-days: 7", text)
        self.assertRegex(text, r"(?m)^\s+path:\s*artifacts/?\s*$")

    def test_workflow_runs_full_unittest_suite_before_build(self):
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        test_command = "python3 -m unittest discover -s tests -v"
        build_command = "python3 .github/workflows/scripts/build_mayfly.py"
        self.assertIn(test_command, text)
        self.assertLess(text.index(test_command), text.index(build_command))

    def test_workflow_has_only_source_profile_choices_and_safe_defaults(self):
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        dispatch = text.split("jobs:", 1)[0]
        self.assertEqual(set(re.findall(r"(?m)^\s{6}([a-z][a-z0-9_-]*):\s*$", dispatch)), {"source", "profile"})
        self.assertIn("default: stock-5.10.226", dispatch)
        self.assertIn("default: root", dispatch)
        self.assertGreaterEqual(dispatch.count("type: choice"), 2)
        for choice in builder.SOURCE_SPECS:
            self.assertIn(f"- {choice}", dispatch)
        for choice in builder.PROFILE_SPECS:
            self.assertIn(f"- {choice}", dispatch)
        self.assertIn("- security-5.10.236-r1", dispatch)
        self.assertNotIn("\n          - security-5.10.236\n", dispatch)

    def test_workflow_has_no_dangerous_or_publishing_features(self):
        text = WORKFLOW_PATH.read_text(encoding="utf-8").lower()
        forbidden = (
            "secrets.",
            "telegram",
            "release",
            "fastboot",
            "permissions: write",
            "contents: write",
            "apt-get upgrade",
            "apt upgrade",
            "pip install",
            "remove-swapfile: 'true'",
            'remove-swapfile: "true"',
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)
        self.assertIn("apt-get update", text)
        self.assertIn("apt-get install", text)

    def test_dedicated_scripts_pass_static_safety_scan(self):
        source = "\n".join(
            (SCRIPTS_DIR / name).read_text(encoding="utf-8")
            for name in ("mayfly_builder.py", "build_mayfly.py")
        )
        forbidden = (
            "check=False",
            "shell=True",
            "| bash",
            "|bash",
            "HEAD~",
            "--fuzz=1",
            "--fuzz=2",
            "--fuzz=3",
            "setup.sh",
            "kernel_builder",
            "fastboot",
            "chmod 777",
            "chmod -R 777",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, source)
        self.assertIn("shell=False", source)
        self.assertIn("check=True", source)
        self.assertIn("--fuzz=0", source)
        self.assertNotIn("69_hide_stuff.patch", "\n".join(builder.planned_patch_paths(builder.PROFILE_SPECS["balanced-bbg"])))

    def test_readme_documents_raw_image_safety_path(self):
        text = README_PATH.read_text(encoding="utf-8")
        for value in (
            "Mayfly 安全 GKI 构建",
            "stock-5.10.226",
            "security-5.10.236-r1",
            "balanced-bbg",
            "--dry-run",
            "Image",
            "69_hide_stuff.patch",
            "sukisu-v4.1.3-susfs-v2.2.0-compat.patch",
            "kernel/module.c",
            "fs/proc/task_mmu.c",
            "UTS 版本伪装",
            "mayfly_builder.py",
            "完整构建树在 sync 前由固定 superproject gitlinks 锁定",
        ):
            with self.subTest(value=value):
                self.assertIn(value, text)
        section = text.split("Mayfly 安全 GKI 构建", 1)[1]
        self.assertIn("不生成 `boot.img`", section)
        self.assertIn("不执行刷写", section)


    def test_readme_documents_repo_launcher_2_15(self):
        text = README_PATH.read_text(encoding="utf-8")
        self.assertIn("repo launcher `2.15`", text)
        self.assertNotIn("repo launcher `2.16`", text)


class LinuxIntegrationTests(unittest.TestCase):
    def test_real_relative_symlink_integration(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            target = root / "work" / "KernelSU" / "kernel"
            target.mkdir(parents=True)
            link = root / "common" / "drivers" / "kernelsu"
            link.parent.mkdir(parents=True)
            try:
                builder._create_relative_directory_symlink(target, link)
            except OSError as exc:
                if os.name == "nt":
                    self.skipTest(f"symlink unavailable on Windows: {exc}")
                raise
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), target.resolve())
            self.assertFalse(os.path.isabs(os.readlink(link)))

    def test_real_patch_command_runs_strict_dry_run_then_apply(self):
        if shutil.which("patch") is None:
            self.skipTest("system patch command unavailable")
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            root = Path(temporary_dir)
            source = root / "source.txt"
            source.write_text("old\n", encoding="utf-8")
            patch_file = root / "change.patch"
            patch_file.write_text(
                "--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-old\n+new\n",
                encoding="utf-8",
            )

            builder.apply_patch_strict(builder.CommandRunner(), patch_file, root)

            self.assertEqual(source.read_text(encoding="utf-8"), "new\n")

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_kpm_prepare_adds_only_owner_execute_without_running_patcher(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary_dir:
            patch_repo = Path(temporary_dir) / "SukiSU_patch"
            patch_linux = patch_repo / "kpm" / "patch_linux"
            dependency = write_elf64_x86_64(patch_linux)
            patch_linux.chmod(0o644)

            prepared, digest = builder.prepare_kpm_patcher(patch_repo, dependency)

            self.assertEqual(prepared, patch_linux.resolve())
            self.assertEqual(digest, dependency["kpm_patch_sha256"])
            self.assertEqual(stat.S_IMODE(prepared.stat().st_mode), 0o744)


if __name__ == "__main__":
    unittest.main()
