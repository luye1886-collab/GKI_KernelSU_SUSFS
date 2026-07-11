import copy
import importlib
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".github" / "workflows" / "scripts"
CONFIG_PATH = SCRIPTS_DIR / "config.py"
LOCK_PATH = REPO_ROOT / ".github" / "workflows" / "config" / "dependencies.lock.json"
README_PATH = REPO_ROOT / "README.md"
WORKFLOW_PATHS = (
    REPO_ROOT / ".github" / "workflows" / "kernel-build.yml",
    REPO_ROOT / ".github" / "workflows" / "build-kernels.yml",
)

EXPECTED_COMMITS = {
    "sukisu_ultra": "278d822a4ebd214bcfd774b7910cb11cdc560bb9",
    "susfs4ksu": "81f01bc58d055687a6276114c1371b8ac09e8b26",
    "sukisu_patch": "547ae94bcaec53d030398f857950c64662043a5d",
    "anykernel3": "0b46673ae91aee8d60bd6ee257b4d56d3f6a0114",
    "baseband_guard": "cef0daaef94d46022e1f8883ba7a30dfab849dbe",
    "git_repo": "784e16f3aa941ca3564d823cc686017a161621a1",
    "android_manifest_2024_11": "22d661860f086f1ebc8c84491245c6b13c879e5e",
    "android_common_2024_11_head": "86d2c543709fae6db701da79f72861ab014723a6",
    "mayfly_stock_common_baseline": "ea4a6f067d3f7ae0ae3d460716449adf06a5ff15",
    "android_manifest_2025_05": "b169c4e85157aefd89d56ed2e5fa5fed21965ee3",
    "android_common_2025_05": "fbb4c9b0aa2909575b240a5404b6a3eaa1d2755d",
    "android_common_2025_05_r1": "b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e",
    "android_superproject_2024_11": "26b4934c64e8a9c04caa51b6b4f0eb4396856df7",
    "android_superproject_2025_05": "03e3311628edfc56454b777d69344e529029cad4",
}

REPO_CONFIGS = {
    "sukisu_ultra": "KSU_REPO_CONFIG",
    "susfs4ksu": "SUSFS_REPO_CONFIG",
    "sukisu_patch": "SUKISU_PATCH_REPO_CONFIG",
    "anykernel3": "ANYKERNEL_CONFIG",
    "baseband_guard": "BBG_CONFIG",
}

VALID_REQUIRED_METADATA = {
    "sukisu_ultra": {"setup_path": "kernel/setup.sh", "version_name": "4.1.3"},
    "susfs4ksu": {
        "version": "v2.2.0",
        "patch_path": "kernel_patches",
        "mayfly_compat_patch_path": "patches/sukisu-v4.1.3-susfs-v2.2.0-compat.patch",
        "mayfly_compat_patch_sha256": "32cd15ec68f7c6fb00857f01144da905b60d547ccb6141a92d35aa1261b6c994",
        "mayfly_task_mmu_patch_path": "patches/mayfly-android12-5.10-susfs-task-mmu.patch",
        "mayfly_task_mmu_patch_sha256": "c3e70b66d8b67aa29ab6935954deb7cf4402e44e231b73e7cee1a4dedc0326c1",
    },
    "sukisu_patch": {
        "kpm_patch_path": "kpm/patch_linux",
        "hide_stuff_patch_path": "69_hide_stuff.patch",
        "hide_stuff_patch_sha256": "59965d78e4ff2d7a427b8c2a0ddfedbb75693bda60934ec9bdc4d7627fb666a5",
        "mayfly_hide_stuff_patch_path": "patches/mayfly-android12-5.10-69-hide-stuff.patch",
        "mayfly_hide_stuff_patch_sha256": "f743de89e1079402f5b1742daed22ec50357949cc4c9ab824b39f486a4815f53",
    },
    "baseband_guard": {"setup_path": "setup.sh"},
    "git_repo": {"path": "repo", "version": "2.15"},
    "android_manifest_2024_11": {
        "ref": "common-android12-5.10-2024-11",
        "path": "default.xml",
    },
    "android_manifest_2025_05": {
        "ref": "common-android12-5.10-2025-05",
        "path": "default.xml",
    },
    "android_common_2024_11_head": {"ref": "deprecated/android12-5.10-2024-11"},
    "mayfly_stock_common_baseline": {"ref": "deprecated/android12-5.10-2024-11"},
    "android_common_2025_05": {"ref": "deprecated/android12-5.10-2025-05"},
    "android_common_2025_05_r1": {
        "ref": "refs/tags/android12-5.10-2025-05_r1",
        "release_tag": "android12-5.10-2025-05_r1",
    },
    "android_superproject_2024_11": {
        "ref": "common-android12-5.10-2024-11",
        "common_commit": "ea4a6f067d3f7ae0ae3d460716449adf06a5ff15",
    },
    "android_superproject_2025_05": {
        "ref": "common-android12-5.10-2025-05",
        "common_commit": "b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e",
    },
}

AUDIT_BRANCH_HEAD_METADATA = {
    "branch_head_date": "2026-05-26",
    "experimental_only": True,
}

SAFE_PATH_METADATA_FIELDS = (
    ("sukisu_ultra", "setup_path"),
    ("susfs4ksu", "patch_path"),
    ("susfs4ksu", "mayfly_compat_patch_path"),
    ("susfs4ksu", "mayfly_task_mmu_patch_path"),
    ("sukisu_patch", "kpm_patch_path"),
    ("sukisu_patch", "hide_stuff_patch_path"),
    ("sukisu_patch", "mayfly_hide_stuff_patch_path"),
    ("baseband_guard", "setup_path"),
    ("git_repo", "path"),
    ("android_manifest_2024_11", "path"),
    ("android_manifest_2025_05", "path"),
)


def import_config():
    scripts_path = str(SCRIPTS_DIR)
    if scripts_path not in sys.path:
        sys.path.insert(0, scripts_path)

    sys.modules.pop("config", None)
    with mock.patch(
        "urllib.request.urlopen",
        side_effect=AssertionError("config import attempted network access"),
    ) as urlopen_mock:
        module = importlib.import_module("config")
    return module, urlopen_mock


def valid_lock_payload():
    dependencies = {
        name: {
            "repo_url": f"https://example.invalid/{name}.git",
            "commit": commit,
        }
        for name, commit in EXPECTED_COMMITS.items()
    }
    for name, metadata in VALID_REQUIRED_METADATA.items():
        dependencies[name].update(metadata)
    dependencies["android_common_2025_05"].update(AUDIT_BRANCH_HEAD_METADATA)
    dependencies["sukisu_ultra"]["version_code"] = 40796
    dependencies["sukisu_patch"].update(
        {
            "kpm_patch_sha256": "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2d",
            "kpm_patch_size": 6013320,
            "hide_stuff_patch_size": 2601,
        }
    )
    return {"schema_version": 1, "dependencies": dependencies}


class ConfigImportSecurityTests(unittest.TestCase):
    def test_config_source_does_not_disable_tls_verification(self):
        config_source = CONFIG_PATH.read_text(encoding="utf-8")
        for forbidden_symbol in ("CERT_NONE", "check_hostname", "_create_unverified_context"):
            with self.subTest(symbol=forbidden_symbol):
                self.assertNotIn(forbidden_symbol, config_source)

    def test_import_and_reload_do_not_access_network_or_print(self):
        scripts_path = str(SCRIPTS_DIR)
        if scripts_path not in sys.path:
            sys.path.insert(0, scripts_path)

        sys.modules.pop("config", None)
        captured_stdout = io.StringIO()
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=AssertionError("config import attempted network access"),
        ) as urlopen_mock, mock.patch(
            "socket.create_connection",
            side_effect=AssertionError("config import attempted socket access"),
        ) as socket_mock, mock.patch(
            "http.client.HTTPConnection.connect",
            side_effect=AssertionError("config import attempted HTTP connection"),
        ) as http_connect_mock:
            with redirect_stdout(captured_stdout):
                config = importlib.import_module("config")
                importlib.reload(config)

        urlopen_mock.assert_not_called()
        socket_mock.assert_not_called()
        http_connect_mock.assert_not_called()
        self.assertEqual(captured_stdout.getvalue(), "")


class DependencyLockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config, _ = import_config()

    def test_lock_contains_expected_https_repositories_and_full_commits(self):
        self.assertTrue(LOCK_PATH.is_file(), f"missing lock file: {LOCK_PATH}")
        lock_data = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.assertEqual(lock_data.get("schema_version"), 1)

        dependencies = lock_data.get("dependencies")
        self.assertIsInstance(dependencies, dict)
        self.assertEqual(set(dependencies), set(EXPECTED_COMMITS))

        for name, expected_commit in EXPECTED_COMMITS.items():
            with self.subTest(dependency=name):
                dependency = dependencies[name]
                self.assertRegex(dependency.get("repo_url", ""), r"^https://[^\s]+$")
                self.assertEqual(dependency.get("commit"), expected_commit)
                self.assertRegex(dependency["commit"], r"^[0-9a-f]{40}$")

    def test_lock_records_mayfly_2024_11_baseline_metadata(self):
        self.assertTrue(LOCK_PATH.is_file(), f"missing lock file: {LOCK_PATH}")
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]

        common_head = dependencies["android_common_2024_11_head"]
        self.assertEqual(common_head.get("ref"), "deprecated/android12-5.10-2024-11")

        baseline = dependencies["mayfly_stock_common_baseline"]
        self.assertEqual(baseline.get("device"), "mayfly")
        self.assertEqual(baseline.get("baseline_of"), "android_common_2024_11_head")
        self.assertEqual(baseline.get("commits_before_head"), 37)

    def test_lock_records_exact_local_sukisu_susfs_compat_patch(self):
        susfs = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]["susfs4ksu"]
        self.assertEqual(
            susfs.get("mayfly_compat_patch_path"),
            "patches/sukisu-v4.1.3-susfs-v2.2.0-compat.patch",
        )
        self.assertEqual(
            susfs.get("mayfly_compat_patch_sha256"),
            "32cd15ec68f7c6fb00857f01144da905b60d547ccb6141a92d35aa1261b6c994",
        )

    def test_lock_validator_requires_exact_local_compat_patch_hash(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        for value in (None, "0" * 64, "8B0493E5485196AC808076906479FEB9A6955C1D19ABAEEB59509BA8105C09FE"):
            with self.subTest(value=value):
                lock_data = valid_lock_payload()
                if value is None:
                    lock_data["dependencies"]["susfs4ksu"].pop("mayfly_compat_patch_sha256")
                else:
                    lock_data["dependencies"]["susfs4ksu"]["mayfly_compat_patch_sha256"] = value
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_lock_separates_experimental_branch_head_from_frozen_r1(self):
        self.assertTrue(LOCK_PATH.is_file(), f"missing lock file: {LOCK_PATH}")
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]

        branch_head = dependencies["android_common_2025_05"]
        self.assertEqual(
            branch_head.get("ref"),
            "deprecated/android12-5.10-2025-05",
        )
        self.assertEqual(branch_head.get("branch_head_date"), "2026-05-26")
        self.assertIs(branch_head.get("experimental_only"), True)
        self.assertIn("audit", branch_head.get("description", "").lower())

        frozen = dependencies["android_common_2025_05_r1"]
        self.assertEqual(frozen.get("commit"), EXPECTED_COMMITS["android_common_2025_05_r1"])
        self.assertEqual(frozen.get("ref"), "refs/tags/android12-5.10-2025-05_r1")
        self.assertEqual(frozen.get("release_tag"), "android12-5.10-2025-05_r1")

    def test_lock_validator_requires_branch_head_audit_metadata(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_values = (
            ("branch_head_date", None),
            ("branch_head_date", "2025-05-01"),
            ("experimental_only", None),
            ("experimental_only", False),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                lock_data = valid_lock_payload()
                if value is None:
                    lock_data["dependencies"]["android_common_2025_05"].pop(field)
                else:
                    lock_data["dependencies"]["android_common_2025_05"][field] = value
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_lock_validator_rejects_unsafe_release_tag(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        lock_data = valid_lock_payload()
        lock_data["dependencies"]["android_common_2025_05_r1"]["release_tag"] = "tag;command"
        with self.assertRaises((ValueError, RuntimeError)):
            validator(lock_data)

    def test_lock_records_exact_superproject_snapshots(self):
        dependencies = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]
        expected = {
            "android_superproject_2024_11": (
                "26b4934c64e8a9c04caa51b6b4f0eb4396856df7",
                "common-android12-5.10-2024-11",
                "ea4a6f067d3f7ae0ae3d460716449adf06a5ff15",
            ),
            "android_superproject_2025_05": (
                "03e3311628edfc56454b777d69344e529029cad4",
                "common-android12-5.10-2025-05",
                "b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e",
            ),
        }
        for name, (commit, ref, common_commit) in expected.items():
            with self.subTest(dependency=name):
                dependency = dependencies[name]
                self.assertEqual(dependency["repo_url"], "https://android.googlesource.com/kernel/superproject")
                self.assertEqual(dependency["commit"], commit)
                self.assertEqual(dependency["ref"], ref)
                self.assertEqual(dependency["common_commit"], common_commit)

    def test_lock_validator_rejects_invalid_structure(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        with self.assertRaises((ValueError, RuntimeError)):
            validator({"schema_version": 1, "dependencies": []})

    def test_lock_validator_rejects_non_https_url(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        lock_data = valid_lock_payload()
        lock_data["dependencies"]["sukisu_ultra"]["repo_url"] = "git://example.invalid/repo"
        with self.assertRaises((ValueError, RuntimeError)):
            validator(lock_data)

    def test_lock_validator_rejects_unsafe_https_urls(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_urls = {
            "username": "https://user@example.invalid/repo.git",
            "password": "https://user:secret@example.invalid/repo.git",
            "query": "https://example.invalid/repo.git?ref=main",
            "empty_query": "https://example.invalid/repo.git?",
            "fragment": "https://example.invalid/repo.git#main",
            "backslash": r"https://example.invalid/repo\evil.git",
            "missing_hostname": "https:///repo.git",
            "invalid_port": "https://example.invalid:not-a-port/repo.git",
            "explicit_port": "https://example.invalid:443/repo.git",
            "empty_path": "https://example.invalid",
        }
        for case_name, repo_url in invalid_urls.items():
            with self.subTest(case=case_name, repo_url=repo_url):
                lock_data = copy.deepcopy(valid_lock_payload())
                lock_data["dependencies"]["sukisu_ultra"]["repo_url"] = repo_url
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_lock_validator_rejects_repo_urls_outside_safe_ascii_charset(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_urls = {
            "semicolon": "https://example.invalid/repo;command.git",
            "ampersand": "https://example.invalid/repo&command.git",
            "pipe": "https://example.invalid/repo|command.git",
            "backtick": "https://example.invalid/repo`command`.git",
            "command_substitution": "https://example.invalid/repo$(command).git",
            "percent_encoding": "https://example.invalid/%2e%2e/repo.git",
        }
        for case_name, repo_url in invalid_urls.items():
            with self.subTest(case=case_name, repo_url=repo_url):
                lock_data = copy.deepcopy(valid_lock_payload())
                lock_data["dependencies"]["sukisu_ultra"]["repo_url"] = repo_url
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_lock_validator_requires_non_empty_string_metadata(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_values = (("missing", None), ("empty", ""), ("whitespace", "   "), ("non_string", 42))

        for dependency_name, metadata in VALID_REQUIRED_METADATA.items():
            for field_name in metadata:
                for case_name, invalid_value in invalid_values:
                    with self.subTest(
                        dependency=dependency_name,
                        field=field_name,
                        case=case_name,
                    ):
                        lock_data = copy.deepcopy(valid_lock_payload())
                        dependency = lock_data["dependencies"][dependency_name]
                        if case_name == "missing":
                            dependency.pop(field_name)
                        else:
                            dependency[field_name] = invalid_value
                        with self.assertRaises((ValueError, RuntimeError)):
                            validator(lock_data)

    def test_lock_validator_rejects_unsafe_relative_metadata_paths(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_paths = (
            "/absolute/path",
            "../parent",
            "nested/../parent",
            r"windows\path",
            ".",
            "nested/./child",
            "-option",
            "nested//child",
            "path with space",
            "path;command",
            "path&command",
            "path|command",
            "path`command`",
            "path$(command)",
            "path%20encoded",
        )

        for dependency_name, field_name in SAFE_PATH_METADATA_FIELDS:
            for invalid_path in invalid_paths:
                with self.subTest(
                    dependency=dependency_name,
                    field=field_name,
                    path=invalid_path,
                ):
                    lock_data = copy.deepcopy(valid_lock_payload())
                    lock_data["dependencies"][dependency_name][field_name] = invalid_path
                    with self.assertRaises((ValueError, RuntimeError)):
                        validator(lock_data)

    def test_lock_validator_rejects_unsafe_branch_and_ref_values(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_refs = (
            "-main",
            "/main",
            "feature..main",
            "feature//main",
            "feature/",
            "feature.",
            "feature branch",
            "feature;command",
            "feature&command",
            "feature|command",
            "feature`command`",
            "feature$(command)",
            "feature%20encoded",
        )
        metadata_fields = (
            ("sukisu_ultra", "branch"),
            ("android_common_2025_05", "ref"),
            ("android_common_2025_05_r1", "ref"),
        )

        for dependency_name, field_name in metadata_fields:
            for invalid_ref in invalid_refs:
                with self.subTest(
                    dependency=dependency_name,
                    field=field_name,
                    value=invalid_ref,
                ):
                    lock_data = copy.deepcopy(valid_lock_payload())
                    lock_data["dependencies"][dependency_name][field_name] = invalid_ref
                    with self.assertRaises((ValueError, RuntimeError)):
                        validator(lock_data)

    def test_lock_validator_rejects_non_full_or_uppercase_commit(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        for invalid_commit in ("278d822", "HEAD~1", "A" * 40):
            with self.subTest(commit=invalid_commit):
                lock_data = copy.deepcopy(valid_lock_payload())
                lock_data["dependencies"]["sukisu_ultra"]["commit"] = invalid_commit
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_runtime_repository_configs_expose_locked_commits(self):
        for name, config_name in REPO_CONFIGS.items():
            with self.subTest(dependency=name):
                repo_config = getattr(self.config, config_name)
                self.assertEqual(repo_config.get("commit"), EXPECTED_COMMITS[name])

    def test_kernel_version_comes_from_lock(self):
        self.assertEqual(self.config.KERNEL_VERSION, "v2.2.0")

    def test_lock_records_fixed_kernelsu_build_version(self):
        dependency = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]["sukisu_ultra"]
        self.assertEqual(dependency.get("version_name"), "4.1.3")
        self.assertEqual(dependency.get("version_code"), 40796)

    def test_lock_validator_requires_fixed_kernelsu_build_version(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_values = (
            ("version_name", None),
            ("version_name", "latest"),
            ("version_code", None),
            ("version_code", 40795),
            ("version_code", "40796"),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                lock_data = valid_lock_payload()
                if value is None:
                    lock_data["dependencies"]["sukisu_ultra"].pop(field)
                else:
                    lock_data["dependencies"]["sukisu_ultra"][field] = value
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_lock_records_fixed_kpm_patcher_identity(self):
        dependency = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]["sukisu_patch"]
        self.assertEqual(dependency.get("kpm_patch_path"), "kpm/patch_linux")
        self.assertEqual(
            dependency.get("kpm_patch_sha256"),
            "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2d",
        )
        self.assertEqual(dependency.get("kpm_patch_size"), 6013320)

    def test_lock_records_git_repo_launcher_version_2_15(self):
        dependency = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["dependencies"]["git_repo"]
        self.assertEqual(dependency.get("version"), "2.15")

    def test_lock_validator_requires_git_repo_launcher_version_2_15(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        for value in (None, "2.16", 2.15):
            with self.subTest(value=value):
                lock_data = valid_lock_payload()
                if value is None:
                    lock_data["dependencies"]["git_repo"].pop("version")
                else:
                    lock_data["dependencies"]["git_repo"]["version"] = value
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)

    def test_lock_validator_requires_fixed_kpm_patcher_identity(self):
        validator = getattr(self.config, "_validate_dependency_lock", None)
        self.assertTrue(callable(validator))
        invalid_values = (
            ("kpm_patch_path", None),
            ("kpm_patch_path", "../patch_linux"),
            ("kpm_patch_sha256", None),
            (
                "kpm_patch_sha256",
                "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2",
            ),
            ("kpm_patch_sha256", "0" * 64),
            ("kpm_patch_size", None),
            ("kpm_patch_size", 6013319),
            ("kpm_patch_size", "6013320"),
        )
        for field, value in invalid_values:
            with self.subTest(field=field, value=value):
                lock_data = valid_lock_payload()
                if value is None:
                    lock_data["dependencies"]["sukisu_patch"].pop(field)
                else:
                    lock_data["dependencies"]["sukisu_patch"][field] = value
                with self.assertRaises((ValueError, RuntimeError)):
                    validator(lock_data)


class BuildConfigSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config, _ = import_config()

    def make_mayfly_config(self, **overrides):
        values = {
            "android_version": "android12",
            "kernel_version": "5.10",
            "sub_level": "236",
            "os_patch_level": "2025-05",
            "revision": "r1",
            "custom_version": "mayfly_12-5.10+safe",
        }
        values.update(overrides)
        return self.config.BuildConfig(**values)

    def test_default_dependency_pins_are_applied(self):
        build_config = self.make_mayfly_config()
        self.assertEqual(build_config.kernelsu_commit, EXPECTED_COMMITS["sukisu_ultra"])
        self.assertEqual(build_config.susfs_commit, EXPECTED_COMMITS["susfs4ksu"])

    def test_explicit_commits_require_full_hex_sha(self):
        for field_name in ("kernelsu_commit", "susfs_commit"):
            for invalid_commit in ("278d822", "HEAD~1", "main"):
                with self.subTest(field=field_name, commit=invalid_commit):
                    with self.assertRaisesRegex(ValueError, field_name):
                        self.make_mayfly_config(**{field_name: invalid_commit})

    def test_explicit_uppercase_commit_overrides_are_rejected(self):
        uppercase_commit = EXPECTED_COMMITS["sukisu_ultra"].upper()
        for field_name in ("kernelsu_commit", "susfs_commit"):
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(ValueError, field_name):
                    self.make_mayfly_config(**{field_name: uppercase_commit})

    def test_malicious_or_malformed_custom_version_is_rejected(self):
        invalid_versions = (
            "",
            "may fly",
            'may"fly',
            "may'fly",
            "may;fly",
            "may$fly",
            "may/fly",
            "a" * 49,
        )
        for custom_version in invalid_versions:
            with self.subTest(custom_version=custom_version):
                with self.assertRaisesRegex(ValueError, "custom_version"):
                    self.make_mayfly_config(custom_version=custom_version)

    def test_android12_numeric_sub_level_requires_year_month_patch_level(self):
        for os_patch_level in ("2025-5", "2025/05", "2025-13"):
            with self.subTest(os_patch_level=os_patch_level):
                with self.assertRaisesRegex(ValueError, "os_patch_level"):
                    self.make_mayfly_config(os_patch_level=os_patch_level)

    def test_android12_lts_pair_is_allowed(self):
        try:
            build_config = self.make_mayfly_config(sub_level="X", os_patch_level="lts")
        except ValueError as exc:
            self.fail(f"X/lts should be a valid Android 12 pairing: {exc}")
        self.assertTrue(build_config.is_lts())
        self.assertEqual(build_config.formatted_branch, "android12-5.10-lts")

    def test_android12_numeric_sub_level_rejects_lts_patch_level(self):
        with self.assertRaisesRegex(ValueError, "os_patch_level"):
            self.make_mayfly_config(sub_level="236", os_patch_level="lts")

    def test_android12_x_sub_level_rejects_calendar_patch_level(self):
        with self.assertRaisesRegex(ValueError, "os_patch_level"):
            self.make_mayfly_config(sub_level="X", os_patch_level="2025-05")

    def test_android12_revision_requires_lowercase_r_and_digits(self):
        for revision in ("1", "r", "R1", "r1;echo"):
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "revision"):
                    self.make_mayfly_config(revision=revision)

    def test_valid_mayfly_configuration_passes(self):
        build_config = self.make_mayfly_config()
        self.assertEqual(build_config.config_name, "android12-5.10-236")
        self.assertEqual(build_config.custom_version, "mayfly_12-5.10+safe")

    def test_all_supported_android_kernel_combinations_use_default_pins(self):
        for android_version, kernel_versions in self.config.ANDROID_KERNEL_MAP.items():
            for kernel_version in kernel_versions:
                with self.subTest(android=android_version.value, kernel=kernel_version.value):
                    is_android12_5_10 = (
                        android_version is self.config.AndroidVersion.ANDROID12
                        and kernel_version is self.config.KernelVersion.KERNEL_5_10
                    )
                    build_config = self.config.BuildConfig(
                        android_version=android_version.value,
                        kernel_version=kernel_version.value,
                        sub_level="1",
                        os_patch_level="2025-05" if is_android12_5_10 else "not-a-calendar-patch",
                        revision="r1" if is_android12_5_10 else "not-an-android12-revision",
                    )
                    self.assertRegex(build_config.kernelsu_commit, r"^[0-9a-f]{40}$")
                    self.assertRegex(build_config.susfs_commit, r"^[0-9a-f]{40}$")
                    self.assertEqual(build_config.kernelsu_commit, EXPECTED_COMMITS["sukisu_ultra"])
                    self.assertEqual(build_config.susfs_commit, EXPECTED_COMMITS["susfs4ksu"])

    def test_to_dict_includes_susfs_commit(self):
        build_config = self.make_mayfly_config()
        serialized = build_config.to_dict()
        self.assertIn("susfs_commit", serialized)
        self.assertEqual(serialized["susfs_commit"], EXPECTED_COMMITS["susfs4ksu"])

    def test_validate_commit_hash_only_accepts_full_hex_sha(self):
        self.assertTrue(self.config.validate_commit_hash(EXPECTED_COMMITS["sukisu_ultra"]))
        for invalid_commit in ("278d822", "HEAD~1", "main", "g" * 40, "A" * 40):
            with self.subTest(commit=invalid_commit):
                self.assertFalse(self.config.validate_commit_hash(invalid_commit))


class ReadmeSecurityTests(unittest.TestCase):
    def test_readme_documents_locked_full_commit_policy(self):
        readme = README_PATH.read_text(encoding="utf-8")
        self.assertNotIn("HEAD~1", readme)
        self.assertNotIn("HEAD~N", readme)
        self.assertNotIn("abc1234", readme)
        self.assertIn("dependencies.lock.json", readme)
        self.assertIn("完整 40 位小写十六进制 commit", readme)

    def test_documentation_and_workflows_describe_locked_commit_policy(self):
        documentation_paths = (README_PATH, *WORKFLOW_PATHS)
        for document_path in documentation_paths:
            with self.subTest(document=document_path.name):
                content = document_path.read_text(encoding="utf-8")
                self.assertNotIn("HEAD~", content)
                self.assertIn("dependencies.lock.json", content)

        expected_description = (
            "留空使用 dependencies.lock.json 锁定值；覆盖仅接受完整 40 位小写 commit"
        )
        for workflow_path in WORKFLOW_PATHS:
            with self.subTest(workflow=workflow_path.name):
                workflow = workflow_path.read_text(encoding="utf-8")
                self.assertEqual(workflow.count(expected_description), 2)


if __name__ == "__main__":
    unittest.main()
