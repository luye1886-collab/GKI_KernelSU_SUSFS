"""Fail-closed helpers for the dedicated mayfly GKI build path."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Mapping, Sequence
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


SCRIPT_DIR = Path(__file__).resolve().parent
WORKFLOW_DIR = SCRIPT_DIR.parent
DEFAULT_LOCK_PATH = SCRIPT_DIR.parent / "config" / "dependencies.lock.json"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
KCONFIG_SYMBOL_RE = re.compile(r"^CONFIG_[A-Z0-9_]+$")
SAFE_REPO_URL_RE = re.compile(r"^[A-Za-z0-9._~:/-]+$")
SAFE_RELATIVE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
COMMON_UPSTREAM_RE = re.compile(r"^deprecated/android12-5\.10-[0-9]{4}-[0-9]{2}$")
KSU_VERSION_NAME = "4.1.3"
KSU_VERSION_CODE = 40796
KPM_PATCH_PATH = "kpm/patch_linux"
KPM_PATCH_SHA256 = "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2d"
KPM_PATCH_SIZE = 6013320
SUKISU_SUSFS_COMPAT_PATCH_PATH = "patches/sukisu-v4.1.3-susfs-v2.2.0-compat.patch"
SUKISU_SUSFS_COMPAT_PATCH_SHA256 = "8b0493e5485196ac808076906479feb9a6955c1d19abaeeb59509ba8105c09fe"
ARM64_IMAGE_MIN_SIZE = 8 * 1024 * 1024
ARM64_IMAGE_MAX_SIZE = 256 * 1024 * 1024
ARM64_IMAGE_MAGIC = b"ARMd"
KSU_KBUILD_FORBIDDEN = (
    "CURL_BIN",
    "GITHUB_API",
    "fetch --unshallow",
    "releases/latest",
    "commits?sha",
    "git rev-list --count",
)
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceSpec:
    name: str
    manifest_dependency: str
    manifest_commit: str
    superproject_dependency: str
    superproject_commit: str
    common_dependency: str
    common_ref: str
    locked_common_ref: str
    release_tag: str | None
    common_commit: str
    expected_release_prefix: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "manifest_dependency": self.manifest_dependency,
            "manifest_commit": self.manifest_commit,
            "superproject_dependency": self.superproject_dependency,
            "superproject_commit": self.superproject_commit,
            "common_dependency": self.common_dependency,
            "common_sync_ref": self.common_ref,
            "locked_common_ref": self.locked_common_ref,
            "release_tag": self.release_tag,
            "common_commit": self.common_commit,
            "expected_release_prefix": self.expected_release_prefix,
        }


@dataclass(frozen=True)
class ProfileSpec:
    name: str
    kpm: bool
    zram_lz4kd: bool
    bbr_default: bool
    bbg: bool

    def feature_dict(self) -> dict[str, bool]:
        return {
            "kpm": self.kpm,
            "zram_lz4kd": self.zram_lz4kd,
            "bbr_default": self.bbr_default,
            "bbg": self.bbg,
        }

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "features": self.feature_dict()}


SOURCE_SPECS = {
    "stock-5.10.226": SourceSpec(
        name="stock-5.10.226",
        manifest_dependency="android_manifest_2024_11",
        manifest_commit="22d661860f086f1ebc8c84491245c6b13c879e5e",
        superproject_dependency="android_superproject_2024_11",
        superproject_commit="26b4934c64e8a9c04caa51b6b4f0eb4396856df7",
        common_dependency="mayfly_stock_common_baseline",
        common_ref="deprecated/android12-5.10-2024-11",
        locked_common_ref="deprecated/android12-5.10-2024-11",
        release_tag=None,
        common_commit="ea4a6f067d3f7ae0ae3d460716449adf06a5ff15",
        expected_release_prefix="5.10.226-android12-9",
    ),
    "security-5.10.236-r1": SourceSpec(
        name="security-5.10.236-r1",
        manifest_dependency="android_manifest_2025_05",
        manifest_commit="b169c4e85157aefd89d56ed2e5fa5fed21965ee3",
        superproject_dependency="android_superproject_2025_05",
        superproject_commit="03e3311628edfc56454b777d69344e529029cad4",
        common_dependency="android_common_2025_05_r1",
        common_ref="deprecated/android12-5.10-2025-05",
        locked_common_ref="refs/tags/android12-5.10-2025-05_r1",
        release_tag="android12-5.10-2025-05_r1",
        common_commit="b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e",
        expected_release_prefix="5.10.236-android12-9",
    ),
}

PROFILE_SPECS = {
    "root": ProfileSpec("root", False, False, False, False),
    "root-kpm": ProfileSpec("root-kpm", True, False, False, False),
    "balanced": ProfileSpec("balanced", True, True, True, False),
    "balanced-bbg": ProfileSpec("balanced-bbg", True, True, True, True),
}

EXCLUDED_PATCHES = {
    "SukiSU_patch/69_hide_stuff.patch": (
        "Excluded because proc maps/path falsification is a third-party detection bypass."
    ),
    "SukiSU-Ultra/kernel/feature/uts_spoof.c": (
        "Excluded at compile time because kernel release/version spoof is outside the defensive scope."
    ),
    "SukiSU_patch/other/zram/zram_patch/5.10/lz4kd.patch:kernel/module.c": (
        "Excluded because it weakens module version checks and rewrites module blacklist handling."
    ),
    "susfs4ksu/kernel_patches/50_add_susfs_in_gki-android12-5.10.patch:fs/proc/task_mmu.c": (
        "Excluded because it only supports disabled map, kstat, and open-redirect concealment features."
    ),
}

PATCH_EXCLUSIONS = {
    "susfs_kernelsu_upstream": (
        "kernel/core/init.c",
        "kernel/policy/app_profile.h",
    ),
    "susfs_common": ("fs/proc/task_mmu.c",),
    "lz4kd": ("kernel/module.c",),
}

SUSFS_CONCEALMENT_CONFIGS = (
    "CONFIG_KSU_SUSFS_SUS_PATH",
    "CONFIG_KSU_SUSFS_SUS_MOUNT",
    "CONFIG_KSU_SUSFS_SUS_KSTAT",
    "CONFIG_KSU_SUSFS_SPOOF_UNAME",
    "CONFIG_KSU_SUSFS_ENABLE_LOG",
    "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS",
    "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG",
    "CONFIG_KSU_SUSFS_OPEN_REDIRECT",
    "CONFIG_KSU_SUSFS_SUS_MAP",
)

KMI_GUARDS = {
    "CONFIG_MODVERSIONS": "y",
    "CONFIG_CFI_CLANG": "y",
    "CONFIG_LTO_CLANG_FULL": "y",
    "CONFIG_ANDROID_VENDOR_HOOKS": "y",
    "CONFIG_TRIM_UNUSED_KSYMS": "y",
}

REQUIRED_ARTIFACT_NAMES = frozenset(
    {"Image", "final.config", "resolved-manifest.xml", "kernel.release"}
)
OPTIONAL_ARTIFACT_NAMES = frozenset({"Image.pre-kpm", "Module.symvers"})


class CommandRunner:
    """Run argument arrays without a shell and propagate every failure."""

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        capture_output: bool = False,
        text: bool = True,
    ) -> subprocess.CompletedProcess:
        if not isinstance(args, (list, tuple)):
            raise TypeError("命令必须使用 list 或 tuple 参数")
        if not args or any(not isinstance(value, str) for value in args):
            raise TypeError("命令参数必须全部是非空参数数组中的字符串")
        return subprocess.run(
            list(args),
            cwd=cwd,
            env=env,
            shell=False,
            check=True,
            text=text,
            capture_output=capture_output,
        )


def _validate_https_url(name: str, value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or any(char.isspace() for char in value):
        raise ValueError(f"依赖 {name} 的仓库地址无效")
    if SAFE_REPO_URL_RE.fullmatch(value) is None:
        raise ValueError(f"依赖 {name} 的仓库地址包含不安全字符")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"依赖 {name} 的仓库地址无效") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
    ):
        raise ValueError(f"依赖 {name} 必须使用无凭据、无端口的 HTTPS 地址")
    return value


def _validate_relative_posix_path(name: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or SAFE_RELATIVE_PATH_RE.fullmatch(value) is None
        or value.startswith(("/", "-"))
        or "//" in value
        or any(part in ("", ".", "..") for part in value.split("/"))
    ):
        raise ValueError(f"依赖 {name} 必须提供安全的相对 POSIX 路径")
    return value


def load_dependencies(lock_path: Path = DEFAULT_LOCK_PATH) -> dict[str, dict[str, object]]:
    try:
        payload = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"依赖锁文件不存在: {lock_path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"依赖锁文件不可读或不是有效 JSON: {lock_path}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("依赖锁 schema_version 必须为 1")
    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ValueError("依赖锁 dependencies 必须是对象")
    for name, dependency in dependencies.items():
        if not isinstance(name, str) or not isinstance(dependency, dict):
            raise ValueError("依赖锁条目结构无效")
        _validate_https_url(name, dependency.get("repo_url"))
        commit = dependency.get("commit")
        if not isinstance(commit, str) or FULL_SHA_RE.fullmatch(commit) is None:
            raise ValueError(f"依赖 {name} 必须锁定完整 40 位小写 commit")
    for dependency_name in ("git_repo", "android_manifest_2024_11", "android_manifest_2025_05"):
        dependency = dependencies.get(dependency_name)
        if not isinstance(dependency, dict):
            raise ValueError(f"依赖锁缺少必需条目: {dependency_name}")
        _validate_relative_posix_path(
            f"{dependency_name}.path",
            dependency.get("path"),
        )
    if dependencies["git_repo"].get("version") != "2.15":
        raise ValueError("git_repo version 必须固定为 2.15")
    kernelsu = dependencies.get("sukisu_ultra")
    if not isinstance(kernelsu, dict):
        raise ValueError("依赖锁缺少必需条目: sukisu_ultra")
    if kernelsu.get("version_name") != KSU_VERSION_NAME:
        raise ValueError(f"sukisu_ultra version_name 必须固定为 {KSU_VERSION_NAME}")
    if type(kernelsu.get("version_code")) is not int or kernelsu["version_code"] != KSU_VERSION_CODE:
        raise ValueError(f"sukisu_ultra version_code 必须固定为整数 {KSU_VERSION_CODE}")
    kpm = dependencies.get("sukisu_patch")
    if not isinstance(kpm, dict):
        raise ValueError("依赖锁缺少必需条目: sukisu_patch")
    if kpm.get("kpm_patch_path") != KPM_PATCH_PATH:
        raise ValueError(f"sukisu_patch kpm_patch_path 必须固定为 {KPM_PATCH_PATH}")
    if kpm.get("kpm_patch_sha256") != KPM_PATCH_SHA256:
        raise ValueError("sukisu_patch kpm_patch_sha256 必须匹配固定的完整 64 位 SHA256")
    if type(kpm.get("kpm_patch_size")) is not int or kpm["kpm_patch_size"] != KPM_PATCH_SIZE:
        raise ValueError(f"sukisu_patch kpm_patch_size 必须固定为整数 {KPM_PATCH_SIZE}")
    susfs = dependencies.get("susfs4ksu")
    if not isinstance(susfs, dict):
        raise ValueError("依赖锁缺少必需条目: susfs4ksu")
    compat_path = _validate_relative_posix_path(
        "susfs4ksu.mayfly_compat_patch_path",
        susfs.get("mayfly_compat_patch_path"),
    )
    if compat_path != SUKISU_SUSFS_COMPAT_PATCH_PATH:
        raise ValueError("SukiSU/SUSFS 兼容补丁路径与固定值不一致")
    if susfs.get("mayfly_compat_patch_sha256") != SUKISU_SUSFS_COMPAT_PATCH_SHA256:
        raise ValueError("SukiSU/SUSFS 兼容补丁 SHA256 与固定值不一致")
    return dependencies


def _validate_source_pins(
    source: SourceSpec,
    dependencies: Mapping[str, Mapping[str, object]],
) -> None:
    required = (
        "git_repo",
        source.manifest_dependency,
        source.superproject_dependency,
        source.common_dependency,
    )
    missing = [name for name in required if name not in dependencies]
    if missing:
        raise ValueError(f"依赖锁缺少 mayfly 源条目: {', '.join(missing)}")
    manifest_commit = dependencies[source.manifest_dependency].get("commit")
    common_commit = dependencies[source.common_dependency].get("commit")
    common_dependency = dependencies[source.common_dependency]
    common_ref = common_dependency.get("ref")
    if manifest_commit != source.manifest_commit:
        raise ValueError(f"{source.name} manifest commit 与固定规格不一致")
    if common_commit != source.common_commit or common_ref != source.locked_common_ref:
        raise ValueError(f"{source.name} common 固定版本与依赖锁不一致")
    if source.release_tag is not None and common_dependency.get("release_tag") != source.release_tag:
        raise ValueError(f"{source.name} common release tag 与固定规格不一致")
    if common_dependency.get("experimental_only") is True:
        raise ValueError(f"{source.name} 不允许使用 experimental_only common 依赖")
    superproject = dependencies[source.superproject_dependency]
    if superproject.get("commit") != source.superproject_commit:
        raise ValueError(f"{source.name} superproject commit 与固定规格不一致")
    if superproject.get("common_commit") != source.common_commit:
        raise ValueError(f"{source.name} superproject common gitlink 与固定 common 不一致")


def dependency_names_for_profile(source: SourceSpec, profile: ProfileSpec) -> tuple[str, ...]:
    names = [
        "git_repo",
        source.manifest_dependency,
        source.superproject_dependency,
        source.common_dependency,
        "sukisu_ultra",
        "susfs4ksu",
    ]
    if profile.kpm or profile.zram_lz4kd:
        names.append("sukisu_patch")
    if profile.bbg:
        names.append("baseband_guard")
    return tuple(names)


def planned_patch_paths(profile: ProfileSpec) -> tuple[str, ...]:
    patches = [
        "kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch",
        SUKISU_SUSFS_COMPAT_PATCH_PATH,
        "kernel_patches/50_add_susfs_in_gki-android12-5.10.patch",
    ]
    if profile.zram_lz4kd:
        patches.append("other/zram/zram_patch/5.10/lz4kd.patch")
    return tuple(patches)


def clone_pinned_dependency(
    runner: CommandRunner,
    dependency: Mapping[str, object],
    destination: Path,
    *,
    shallow: bool = True,
) -> None:
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"依赖目标已存在，拒绝复用: {destination}")
    repo_url = _validate_https_url("clone", dependency.get("repo_url"))
    commit = dependency.get("commit")
    if not isinstance(commit, str) or FULL_SHA_RE.fullmatch(commit) is None:
        raise ValueError("clone commit 必须是完整 40 位小写 SHA")
    runner.run(["git", "init", str(destination)])
    runner.run(["git", "-C", str(destination), "remote", "add", "origin", repo_url])
    fetch = ["git", "-C", str(destination), "fetch"]
    if shallow:
        fetch.append("--depth=1")
    fetch.extend(["origin", commit])
    runner.run(fetch)
    runner.run(["git", "-C", str(destination), "checkout", "--detach", commit])
    result = runner.run(
        ["git", "-C", str(destination), "rev-parse", "HEAD"],
        capture_output=True,
    )
    actual = result.stdout.strip()
    if actual != commit:
        raise RuntimeError(f"依赖 HEAD 核验失败: 期望 {commit}，实际 {actual or '<empty>'}")


def _require_regular_file(path: Path, label: str) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.exists():
        raise FileNotFoundError(f"{label} 不存在或是符号链接: {path}")
    try:
        file_stat = path.stat()
    except OSError as exc:
        raise RuntimeError(f"无法读取 {label}: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"{label} 必须是普通文件: {path}")
    if file_stat.st_size <= 0:
        raise ValueError(f"{label} 不能为空: {path}")
    return path


def apply_patch_strict(
    runner: CommandRunner,
    patch_path: Path,
    cwd: Path,
    *,
    strip: int = 1,
) -> None:
    patch_path = _require_regular_file(patch_path, "补丁文件").resolve()
    cwd = Path(cwd)
    if not cwd.is_dir():
        raise NotADirectoryError(f"补丁目标目录不存在: {cwd}")
    if strip < 0:
        raise ValueError("patch strip 不能为负数")
    common = ["patch", "--batch", "--forward", "--fuzz=0", f"-p{strip}", "-i", str(patch_path)]
    runner.run(["patch", "--dry-run", *common[1:]], cwd=cwd)
    runner.run(common, cwd=cwd)


def apply_git_patch_strict(
    runner: CommandRunner,
    patch_path: Path,
    cwd: Path,
    *,
    excluded_paths: Sequence[str] = (),
    whitespace: str = "nowarn",
) -> None:
    patch_path = _require_regular_file(patch_path, "补丁文件").resolve()
    cwd = Path(cwd)
    if cwd.is_symlink() or not cwd.is_dir():
        raise NotADirectoryError(f"补丁目标目录不存在或是符号链接: {cwd}")
    if whitespace not in {"nowarn", "error-all"}:
        raise ValueError(f"不支持的 git apply whitespace 模式: {whitespace}")

    validated_exclusions: list[str] = []
    for path in excluded_paths:
        validated = _validate_relative_posix_path("git apply exclude", path)
        if validated in validated_exclusions:
            raise ValueError(f"git apply exclude 重复: {validated}")
        validated_exclusions.append(validated)

    options = [f"--whitespace={whitespace}"]
    options.extend(f"--exclude={path}" for path in validated_exclusions)
    runner.run(["git", "apply", "--check", *options, str(patch_path)], cwd=cwd)
    runner.run(["git", "apply", *options, str(patch_path)], cwd=cwd)


def rewrite_common_manifest(manifest_path: Path, common_ref: str) -> None:
    manifest_path = _require_regular_file(manifest_path, "manifest")
    if not isinstance(common_ref, str) or not common_ref.startswith("deprecated/android12-5.10-"):
        raise ValueError("common ref 不符合 mayfly Android 12 5.10 固定分支")
    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError as exc:
        raise RuntimeError(f"manifest XML 解析失败: {manifest_path}") from exc
    matches = [
        project
        for project in tree.getroot().iter("project")
        if project.get("path") == "common" and project.get("name") == "kernel/common"
    ]
    if len(matches) != 1:
        raise RuntimeError(f"manifest 中 common project 必须恰好一个，实际 {len(matches)} 个")
    matches[0].set("revision", common_ref)
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)


def parse_superproject_ls_tree(
    output: str,
    *,
    expected_common_commit: str,
) -> dict[str, str]:
    if not isinstance(output, str):
        raise TypeError("superproject ls-tree 输出必须是字符串")
    if FULL_SHA_RE.fullmatch(expected_common_commit) is None:
        raise ValueError("预期 common commit 必须是完整 40 位小写 SHA")
    pins: dict[str, str] = {}
    gitlink_pattern = re.compile(r"^160000 commit ([0-9a-f]{40})\t([^\r\n]+)$")
    for line in output.splitlines():
        match = gitlink_pattern.fullmatch(line)
        if match is None:
            if line.startswith("160000 "):
                raise ValueError(f"superproject gitlink 行格式无效: {line}")
            continue
        revision, path = match.groups()
        _validate_relative_posix_path("superproject gitlink", path)
        if path in pins:
            raise RuntimeError(f"superproject gitlink path 重复: {path}")
        pins[path] = revision
    if not pins:
        raise ValueError("superproject 不包含 gitlink")
    if pins.get("common") != expected_common_commit:
        raise RuntimeError(
            "superproject common gitlink 不匹配: "
            f"期望 {expected_common_commit}，实际 {pins.get('common', '<missing>')}"
        )
    return pins


def rewrite_manifest_with_superproject(
    manifest_path: Path,
    project_pins: Mapping[str, str],
    *,
    common_upstream: str,
) -> dict[str, str]:
    manifest_path = _require_regular_file(manifest_path, "manifest")
    if not isinstance(common_upstream, str) or COMMON_UPSTREAM_RE.fullmatch(common_upstream) is None:
        raise ValueError("common upstream must be a deprecated Android 12 5.10 monthly branch")
    if not isinstance(project_pins, Mapping) or not project_pins:
        raise ValueError("superproject pins 不能为空")
    validated_pins: dict[str, str] = {}
    for path, revision in project_pins.items():
        _validate_relative_posix_path("superproject path", path)
        if not isinstance(revision, str) or FULL_SHA_RE.fullmatch(revision) is None:
            raise ValueError(f"superproject revision 不是完整小写 SHA: {path}")
        if path in validated_pins:
            raise RuntimeError(f"superproject path 重复: {path}")
        validated_pins[path] = revision
    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError as exc:
        raise RuntimeError(f"manifest XML 解析失败: {manifest_path}") from exc
    projects = list(tree.getroot().iter("project"))
    if not projects:
        raise ValueError("manifest 不包含 project")
    manifest_pins: dict[str, str] = {}
    for project in projects:
        path = project.get("path")
        if not path:
            raise ValueError("manifest project 缺少 path")
        _validate_relative_posix_path("manifest project path", path)
        if path in manifest_pins:
            raise RuntimeError(f"manifest project path 重复: {path}")
        revision = validated_pins.get(path)
        if revision is None:
            raise RuntimeError(f"manifest project 缺少 superproject 映射: {path}")
        project.set("revision", revision)
        if path == "common":
            project.set("upstream", common_upstream)
        manifest_pins[path] = revision
    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
    return manifest_pins


def validate_resolved_manifest(
    manifest_path: Path,
    *,
    expected_common_commit: str | None = None,
    expected_projects: Mapping[str, str] | None = None,
) -> dict[str, str]:
    manifest_path = _require_regular_file(manifest_path, "resolved manifest")
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError as exc:
        raise RuntimeError(f"resolved manifest XML 解析失败: {manifest_path}") from exc
    projects = list(root.iter("project"))
    if not projects:
        raise ValueError("resolved manifest 不包含 project")
    revisions: dict[str, str] = {}
    for project in projects:
        identity = project.get("path") or project.get("name")
        revision = project.get("revision")
        if not identity or not revision or FULL_SHA_RE.fullmatch(revision) is None:
            raise ValueError(f"resolved manifest project revision 不是完整小写 SHA: {identity or '<unknown>'}")
        if identity in revisions:
            raise ValueError(f"resolved manifest project 标识重复: {identity}")
        revisions[identity] = revision
    if expected_common_commit is not None:
        if FULL_SHA_RE.fullmatch(expected_common_commit) is None:
            raise ValueError("预期 common commit 必须是完整 40 位小写 SHA")
        if revisions.get("common") != expected_common_commit:
            raise RuntimeError(
                "resolved manifest common revision 不匹配: "
                f"期望 {expected_common_commit}，实际 {revisions.get('common', '<missing>')}"
            )
    if expected_projects is not None:
        if not isinstance(expected_projects, Mapping) or not expected_projects:
            raise ValueError("预期 manifest project pins 不能为空")
        expected = dict(expected_projects)
        for path, revision in expected.items():
            _validate_relative_posix_path("expected project path", path)
            if not isinstance(revision, str) or FULL_SHA_RE.fullmatch(revision) is None:
                raise ValueError(f"预期 project revision 无效: {path}")
        if set(revisions) != set(expected):
            missing = sorted(set(expected) - set(revisions))
            extra = sorted(set(revisions) - set(expected))
            raise RuntimeError(f"resolved manifest project 集合不匹配: missing={missing}, extra={extra}")
        for path, expected_revision in expected.items():
            if revisions[path] != expected_revision:
                raise RuntimeError(
                    f"resolved manifest revision 不匹配: {path} 期望 {expected_revision}，实际 {revisions[path]}"
                )
    return revisions


def repo_init_command(
    repo_tool: Path,
    source: SourceSpec,
    dependencies: Mapping[str, Mapping[str, object]],
) -> list[str]:
    _validate_source_pins(source, dependencies)
    manifest = dependencies[source.manifest_dependency]
    repo_dependency = dependencies["git_repo"]
    manifest_path = _validate_relative_posix_path(
        f"{source.manifest_dependency}.path",
        manifest.get("path"),
    )
    return [
        sys.executable,
        str(repo_tool),
        "init",
        "-u",
        str(manifest["repo_url"]),
        "-b",
        source.manifest_commit,
        "-m",
        manifest_path,
        "--repo-url",
        str(repo_dependency["repo_url"]),
        "--repo-rev",
        str(repo_dependency["commit"]),
        "--no-clone-bundle",
    ]


def _validated_jobs(jobs: int) -> int:
    if type(jobs) is not int or not 1 <= jobs <= 4:
        raise ValueError("并发数必须在 1 到 4 之间")
    return jobs


def repo_sync_command(repo_tool: Path, *, jobs: int = 4) -> list[str]:
    jobs = _validated_jobs(jobs)
    return [
        sys.executable,
        str(repo_tool),
        "sync",
        "--fail-fast",
        "--no-manifest-update",
        "--no-clone-bundle",
        "-c",
        f"-j{jobs}",
    ]


def verify_common_head(
    runner: CommandRunner,
    common_dir: Path,
    source: SourceSpec,
) -> None:
    common_dir = Path(common_dir)
    result = runner.run(
        ["git", "-C", str(common_dir), "rev-parse", "HEAD"],
        capture_output=True,
    )
    actual = result.stdout.strip()
    if actual != source.common_commit:
        raise RuntimeError(
            f"common revision 核验失败: 期望 {source.common_commit}，实际 {actual or '<empty>'}"
        )


def repo_manifest_command(repo_tool: Path, output_path: Path) -> list[str]:
    return [sys.executable, str(repo_tool), "manifest", "-r", "-o", str(output_path)]


def ensure_exact_line(path: Path, line: str) -> None:
    path = _require_regular_file(path, "集成目标文件")
    if not isinstance(line, str) or not line or "\n" in line or "\r" in line:
        raise ValueError("集成行必须是单行非空字符串")
    content = path.read_text(encoding="utf-8")
    count = content.splitlines().count(line)
    if count > 1:
        raise RuntimeError(f"集成目标已包含重复行: {line}")
    if count == 1:
        return
    separator = "" if content.endswith("\n") else "\n"
    path.write_text(f"{content}{separator}{line}\n", encoding="utf-8")


def _create_relative_directory_symlink(target: Path, link: Path) -> None:
    target = Path(target)
    link = Path(link)
    if target.is_symlink() or not target.is_dir():
        raise NotADirectoryError(f"符号链接目标目录无效: {target}")
    if not link.parent.is_dir():
        raise NotADirectoryError(f"符号链接父目录不存在: {link.parent}")
    relative_target = os.path.relpath(target, link.parent)
    if link.is_symlink():
        if os.readlink(link) != relative_target:
            raise FileExistsError(f"符号链接指向非预期目标: {link}")
        return
    if link.exists():
        raise FileExistsError(f"符号链接位置已被占用: {link}")
    os.symlink(relative_target, link, target_is_directory=True)


def integrate_kernelsu(common_dir: Path, kernelsu_dir: Path) -> None:
    common_dir = Path(common_dir)
    kernelsu_dir = Path(kernelsu_dir)
    _require_regular_file(kernelsu_dir / "kernel" / "Kconfig", "KernelSU Kconfig")
    _require_regular_file(kernelsu_dir / "kernel" / "Makefile", "KernelSU Makefile")
    _create_relative_directory_symlink(
        kernelsu_dir / "kernel",
        common_dir / "drivers" / "kernelsu",
    )
    ensure_exact_line(
        common_dir / "drivers" / "Makefile",
        "obj-$(CONFIG_KSU) += kernelsu/",
    )
    ensure_exact_line(
        common_dir / "drivers" / "Kconfig",
        'source "drivers/kernelsu/Kconfig"',
    )


def _kernelsu_version_info(
    *,
    version_name: object,
    version_code: object,
    commit: object,
) -> dict[str, object]:
    if version_name != KSU_VERSION_NAME:
        raise ValueError(f"KernelSU version_name 必须固定为 {KSU_VERSION_NAME}")
    if type(version_code) is not int or version_code != KSU_VERSION_CODE:
        raise ValueError(f"KernelSU version_code 必须固定为整数 {KSU_VERSION_CODE}")
    if not isinstance(commit, str) or FULL_SHA_RE.fullmatch(commit) is None:
        raise ValueError("KernelSU commit 必须是完整 40 位小写 SHA")
    return {
        "version_name": version_name,
        "version_code": version_code,
        "version_full": f"v{version_name}-{commit[:8]}@pinned",
    }


def pin_kernelsu_kbuild(
    kbuild_path: Path,
    *,
    version_name: object,
    version_code: object,
    commit: object,
) -> dict[str, object]:
    kbuild_path = _require_regular_file(kbuild_path, "KernelSU Kbuild")
    version = _kernelsu_version_info(
        version_name=version_name,
        version_code=version_code,
        commit=commit,
    )
    content = kbuild_path.read_text(encoding="utf-8")
    start_matches = list(re.finditer(r"(?m)^MDIR :=[^\r\n]*(?:\r?\n|$)", content))
    end_matches = list(re.finditer(r"(?m)^ifndef KSU_EXPECTED_SIZE(?:\r?\n|$)", content))
    if len(start_matches) != 1 or len(end_matches) != 1:
        raise RuntimeError("KernelSU Kbuild 动态版本块锚点必须各出现一次")
    start = start_matches[0].start()
    end = end_matches[0].start()
    if start >= end:
        raise RuntimeError("KernelSU Kbuild 动态版本块锚点顺序无效")

    fixed_block = (
        f"KSU_VERSION := {version['version_code']}\n"
        f"KSU_VERSION_FULL := {version['version_full']}\n"
        "ccflags-y += -DKSU_VERSION=$(KSU_VERSION)\n"
        'ccflags-y += -DKSU_VERSION_FULL=\\"$(KSU_VERSION_FULL)\\"\n\n'
    )
    pinned_content = content[:start] + fixed_block + content[end:]
    forbidden = [token for token in KSU_KBUILD_FORBIDDEN if token in pinned_content]
    if forbidden:
        raise RuntimeError(f"KernelSU Kbuild 仍包含动态联网或版本漂移逻辑: {', '.join(forbidden)}")
    kbuild_path.write_text(pinned_content, encoding="utf-8", newline="\n")
    return version


def copy_tree_contents_strict(source_dir: Path, destination_dir: Path) -> int:
    source_dir = Path(source_dir)
    destination_dir = Path(destination_dir)
    if source_dir.is_symlink() or not source_dir.is_dir():
        raise NotADirectoryError(f"复制源目录不存在或是符号链接: {source_dir}")
    if destination_dir.is_symlink():
        raise ValueError(f"复制目标不能是符号链接: {destination_dir}")
    destination_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for source_path in sorted(source_dir.rglob("*")):
        if source_path.is_symlink():
            raise ValueError(f"复制源包含符号链接: {source_path}")
        relative = source_path.relative_to(source_dir)
        destination_path = destination_dir / relative
        if source_path.is_dir():
            if destination_path.exists() and not destination_path.is_dir():
                raise ValueError(f"复制目标类型冲突: {destination_path}")
            destination_path.mkdir(parents=True, exist_ok=True)
            continue
        _require_regular_file(source_path, "复制源文件")
        if destination_path.is_symlink() or (destination_path.exists() and not destination_path.is_file()):
            raise ValueError(f"复制目标类型冲突: {destination_path}")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)
        copied += 1
    if copied == 0:
        raise ValueError(f"复制源目录不包含普通文件: {source_dir}")
    return copied


def integrate_susfs(
    runner: CommandRunner,
    common_dir: Path,
    kernelsu_dir: Path,
    susfs_dir: Path,
    kernelsu_dependency: Mapping[str, object],
    susfs_dependency: Mapping[str, object],
) -> None:
    common_dir = Path(common_dir)
    kernelsu_dir = Path(kernelsu_dir)
    patch_root = Path(susfs_dir) / "kernel_patches"
    ksu_patch = patch_root / "KernelSU" / "10_enable_susfs_for_ksu.patch"
    common_patch = patch_root / "50_add_susfs_in_gki-android12-5.10.patch"
    apply_git_patch_strict(
        runner,
        ksu_patch,
        kernelsu_dir,
        excluded_paths=PATCH_EXCLUSIONS["susfs_kernelsu_upstream"],
    )
    compat_patch, _ = validate_local_compat_patch(susfs_dependency)
    apply_git_patch_strict(
        runner,
        compat_patch,
        kernelsu_dir,
        whitespace="error-all",
    )
    pin_kernelsu_kbuild(
        kernelsu_dir / "kernel" / "Kbuild",
        version_name=kernelsu_dependency.get("version_name"),
        version_code=kernelsu_dependency.get("version_code"),
        commit=kernelsu_dependency.get("commit"),
    )
    copy_tree_contents_strict(patch_root / "fs", common_dir / "fs")
    copy_tree_contents_strict(patch_root / "include" / "linux", common_dir / "include" / "linux")
    apply_git_patch_strict(
        runner,
        common_patch,
        common_dir,
        excluded_paths=PATCH_EXCLUSIONS["susfs_common"],
    )


def integrate_lz4kd(
    runner: CommandRunner,
    common_dir: Path,
    patch_repo: Path,
) -> None:
    common_dir = Path(common_dir)
    lz4k_root = Path(patch_repo) / "other" / "zram" / "lz4k"
    copy_tree_contents_strict(lz4k_root / "include" / "linux", common_dir / "include" / "linux")
    copy_tree_contents_strict(lz4k_root / "lib", common_dir / "lib")
    copy_tree_contents_strict(lz4k_root / "crypto", common_dir / "crypto")
    apply_git_patch_strict(
        runner,
        Path(patch_repo) / "other" / "zram" / "zram_patch" / "5.10" / "lz4kd.patch",
        common_dir,
        excluded_paths=PATCH_EXCLUSIONS["lz4kd"],
    )


def integrate_bbg(common_dir: Path, bbg_dir: Path) -> None:
    common_dir = Path(common_dir)
    bbg_dir = Path(bbg_dir)
    _require_regular_file(bbg_dir / "Kconfig", "Baseband Guard Kconfig")
    _require_regular_file(bbg_dir / "Makefile", "Baseband Guard Makefile")
    _create_relative_directory_symlink(
        bbg_dir,
        common_dir / "security" / "baseband-guard",
    )
    ensure_exact_line(
        common_dir / "security" / "Makefile",
        "obj-$(CONFIG_BBG) += baseband-guard/",
    )
    ensure_exact_line(
        common_dir / "security" / "Kconfig",
        'source "security/baseband-guard/Kconfig"',
    )


def set_kconfig(config_text: str, symbol: str, value: str) -> str:
    if not isinstance(config_text, str):
        raise TypeError("Kconfig 内容必须是字符串")
    if KCONFIG_SYMBOL_RE.fullmatch(symbol) is None:
        raise ValueError(f"Kconfig symbol 无效: {symbol}")
    if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
        raise ValueError(f"Kconfig value 无效: {symbol}")
    assignment = re.compile(rf"^{re.escape(symbol)}=.*$")
    disabled = re.compile(rf"^# {re.escape(symbol)} is not set$")
    kept = [
        line
        for line in config_text.splitlines()
        if assignment.fullmatch(line) is None and disabled.fullmatch(line) is None
    ]
    new_line = f"# {symbol} is not set" if value == "n" else f"{symbol}={value}"
    kept.append(new_line)
    return "\n".join(kept) + "\n"


def append_lsm(existing: str, entry: str) -> str:
    if not isinstance(existing, str) or not isinstance(entry, str) or not entry:
        raise ValueError("CONFIG_LSM 内容无效")
    values = [value.strip() for value in existing.strip('"').split(",") if value.strip()]
    if not values:
        raise ValueError("CONFIG_LSM 不能为空")
    if entry in values:
        if values[-1] == entry and values.count(entry) == 1:
            return ",".join(values)
        raise ValueError(f"CONFIG_LSM 中 {entry} 已存在但不在唯一末尾位置")
    values.append(entry)
    return ",".join(values)


def profile_kconfig(
    profile: ProfileSpec,
    *,
    existing_lsm: str | None = None,
) -> dict[str, str]:
    values = {
        "CONFIG_KSU": "y",
        "CONFIG_KSU_DEBUG": "n",
        "CONFIG_KSU_MANUAL_SU": "y",
        "CONFIG_KSU_DISABLE_MANAGER": "n",
        "CONFIG_KSU_DISABLE_POLICY": "n",
        "CONFIG_KSU_SUSFS": "y",
    }
    values.update({symbol: "n" for symbol in SUSFS_CONCEALMENT_CONFIGS})
    values["CONFIG_KPM"] = "y" if profile.kpm else "n"

    if profile.zram_lz4kd:
        values.update(
            {
                "CONFIG_ZSMALLOC": "y",
                "CONFIG_ZRAM": "y",
                "CONFIG_CRYPTO_LZO": "y",
                "CONFIG_CRYPTO_LZ4K": "y",
                "CONFIG_CRYPTO_LZ4KD": "y",
                "CONFIG_ZRAM_DEF_COMP_LZ4KD": "y",
                "CONFIG_ZRAM_WRITEBACK": "y",
            }
        )

    if profile.bbr_default:
        values.update(
            {
                "CONFIG_TCP_CONG_ADVANCED": "y",
                "CONFIG_TCP_CONG_BBR": "y",
                "CONFIG_NET_SCH_FQ": "y",
                "CONFIG_DEFAULT_BBR": "y",
                "CONFIG_DEFAULT_CUBIC": "n",
                "CONFIG_DEFAULT_TCP_CONG": '"bbr"',
            }
        )
    else:
        values.update(
            {
                "CONFIG_TCP_CONG_ADVANCED": "n",
                "CONFIG_TCP_CONG_CUBIC": "y",
                "CONFIG_DEFAULT_TCP_CONG": '"cubic"',
            }
        )

    if profile.bbg:
        values.update(
            {
                "CONFIG_BBG": "y",
                "CONFIG_BBG_BLOCK_BOOT": "n",
                "CONFIG_BBG_BLOCK_RECOVERY": "n",
            }
        )
        if existing_lsm is not None:
            values["CONFIG_LSM"] = f'"{append_lsm(existing_lsm, "baseband_guard")}"'
    return values


def parse_kconfig_text(config_text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in config_text.splitlines():
        disabled = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if disabled:
            values[disabled.group(1)] = "n"
            continue
        assignment = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=(.*)", line)
        if assignment:
            value = assignment.group(2)
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            values[assignment.group(1)] = value
    return values


def validate_final_config(config_path: Path, profile: ProfileSpec) -> dict[str, str]:
    config_path = _require_regular_file(config_path, "最终 .config")
    config_text = config_path.read_text(encoding="utf-8")
    seen: set[str] = set()
    duplicates: set[str] = set()
    for line in config_text.splitlines():
        match = re.fullmatch(r"(?:# )?(CONFIG_[A-Z0-9_]+)(?:=.*| is not set)", line)
        if match:
            symbol = match.group(1)
            if symbol in seen:
                duplicates.add(symbol)
            seen.add(symbol)
    if duplicates:
        raise RuntimeError(f"最终 .config 包含重复配置项: {', '.join(sorted(duplicates))}")
    parsed = parse_kconfig_text(config_text)
    expected = profile_kconfig(profile, existing_lsm=parsed.get("CONFIG_LSM"))
    expected.update(KMI_GUARDS)
    for symbol, expected_value in expected.items():
        normalized = expected_value.strip('"')
        if parsed.get(symbol) != normalized:
            raise RuntimeError(
                f"最终配置核验失败: {symbol} 期望 {normalized}，实际 {parsed.get(symbol, '<missing>')}"
            )

    def assert_not_enabled(symbol: str) -> None:
        if parsed.get(symbol) in {"y", "m"}:
            raise RuntimeError(f"最终配置核验失败: {symbol} 必须缺失或为 n")

    if not profile.zram_lz4kd:
        assert_not_enabled("CONFIG_CRYPTO_LZ4KD")
        assert_not_enabled("CONFIG_ZRAM_DEF_COMP_LZ4KD")
    if not profile.bbg:
        assert_not_enabled("CONFIG_BBG")
    if not profile.bbr_default:
        assert_not_enabled("CONFIG_TCP_CONG_BBR")
    if profile.bbg:
        lsm_values = parsed["CONFIG_LSM"].split(",")
        if lsm_values[-1] != "baseband_guard" or lsm_values.count("baseband_guard") != 1:
            raise RuntimeError("CONFIG_LSM 必须且只能在末尾追加一次 baseband_guard")
    return parsed


def disable_check_defconfig(common_dir: Path) -> Path:
    common_dir = Path(common_dir)
    candidates = (
        common_dir / "build.config.gki",
        common_dir / "build.config.gki.aarch64",
    )
    pattern = re.compile(
        r'(?m)^POST_DEFCONFIG_CMDS=(?:"check_defconfig"|\'check_defconfig\'|check_defconfig)$'
    )
    matches: list[tuple[Path, str]] = []
    for candidate in candidates:
        if not candidate.exists():
            continue
        candidate = _require_regular_file(candidate, "build config")
        content = candidate.read_text(encoding="utf-8")
        if pattern.search(content):
            matches.append((candidate, content))
    if len(matches) != 1:
        raise RuntimeError(
            f"check_defconfig 配置必须恰好匹配一次，实际匹配 {len(matches)} 个文件"
        )
    path, content = matches[0]
    updated, replacements = pattern.subn('POST_DEFCONFIG_CMDS=""', content)
    if replacements != 1:
        raise RuntimeError(f"check_defconfig 配置必须恰好替换一次，实际 {replacements} 次")
    path.write_text(updated, encoding="utf-8")
    return path


def configure_profile_defconfig(common_dir: Path, profile: ProfileSpec) -> dict[str, Path]:
    common_dir = Path(common_dir)
    defconfig = _require_regular_file(
        common_dir / "arch" / "arm64" / "configs" / "gki_defconfig",
        "gki_defconfig",
    )
    content = defconfig.read_text(encoding="utf-8")
    current = parse_kconfig_text(content)
    existing_lsm = current.get("CONFIG_LSM")
    if profile.bbg and existing_lsm is None:
        raise RuntimeError("balanced-bbg 要求 gki_defconfig 已有 CONFIG_LSM")
    values = profile_kconfig(profile, existing_lsm=existing_lsm)
    for symbol, value in values.items():
        content = set_kconfig(content, symbol, value)
    defconfig.write_text(content, encoding="utf-8")
    changed_build_config = disable_check_defconfig(common_dir)
    return {
        "defconfig": defconfig,
        "check_defconfig_file": changed_build_config,
    }


def kernel_build_command(source_root: Path, *, jobs: int = 4) -> list[str]:
    jobs = _validated_jobs(jobs)
    return [str(Path(source_root) / "build" / "build.sh"), f"-j{jobs}"]


def kernel_build_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(base if base is not None else os.environ)
    environment["BUILD_CONFIG"] = "common/build.config.gki.aarch64"
    environment["LTO"] = "full"
    return environment


def sha256_file(path: Path) -> str:
    path = _require_regular_file(path, "哈希输入文件")
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_local_compat_patch(
    susfs_dependency: Mapping[str, object],
) -> tuple[Path, str]:
    relative_path = _validate_relative_posix_path(
        "susfs4ksu.mayfly_compat_patch_path",
        susfs_dependency.get("mayfly_compat_patch_path"),
    )
    if relative_path != SUKISU_SUSFS_COMPAT_PATCH_PATH:
        raise ValueError("SukiSU/SUSFS 兼容补丁路径与固定值不一致")
    expected_hash = susfs_dependency.get("mayfly_compat_patch_sha256")
    if expected_hash != SUKISU_SUSFS_COMPAT_PATCH_SHA256:
        raise ValueError("SukiSU/SUSFS 兼容补丁 SHA256 元数据与固定值不一致")

    workflow_root = WORKFLOW_DIR.resolve()
    patch_path = _require_regular_file(
        WORKFLOW_DIR / Path(*relative_path.split("/")),
        "SukiSU/SUSFS 兼容补丁",
    ).resolve()
    try:
        patch_path.relative_to(workflow_root)
    except ValueError as exc:
        raise ValueError("SukiSU/SUSFS 兼容补丁越出 workflow 目录") from exc
    actual_hash = sha256_file(patch_path)
    if actual_hash != expected_hash:
        raise RuntimeError("SukiSU/SUSFS 兼容补丁 SHA256 与依赖锁不一致")
    return patch_path, actual_hash


def validate_kernelsu_hardening(kernelsu_dir: Path) -> None:
    kernel_dir = Path(kernelsu_dir) / "kernel"
    paths = {
        "Kbuild": _require_regular_file(kernel_dir / "Kbuild", "KernelSU Kbuild"),
        "init": _require_regular_file(kernel_dir / "core" / "init.c", "KernelSU init.c"),
        "profile": _require_regular_file(
            kernel_dir / "policy" / "app_profile.h",
            "KernelSU app_profile.h",
        ),
        "dispatch": _require_regular_file(
            kernel_dir / "supercall" / "dispatch.c",
            "KernelSU dispatch.c",
        ),
    }
    contents = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    forbidden = {
        "Kbuild": ("feature/uts_spoof.o",),
        "init": ("ksu_spoof_version", "ksu_init_symbol_resolver"),
        "dispatch": ("feature/uts_spoof.h", "do_set_spoof_version", "KSU_IOCTL_SET_SPOOF_VERSION"),
    }
    for name, tokens in forbidden.items():
        present = [token for token in tokens if token in contents[name]]
        if present:
            raise RuntimeError(f"KernelSU UTS 版本伪装编译路径未禁用: {name}: {', '.join(present)}")

    required = {
        "init": ("susfs_init();", "ksu_sucompat_init();", "ksu_setuid_hook_init();"),
        "profile": (
            "int escape_to_root_for_init(void);",
            "void escape_to_root_for_cmd_su(uid_t target_uid, pid_t target_pid);",
        ),
    }
    for name, tokens in required.items():
        missing = [token for token in tokens if token not in contents[name]]
        if missing:
            raise RuntimeError(f"KernelSU/SUSFS 兼容集成不完整: {name}: {', '.join(missing)}")


def validate_kpm_patcher(
    patch_repo: Path,
    dependency: Mapping[str, object],
) -> tuple[Path, str]:
    patch_repo = Path(patch_repo)
    if patch_repo.is_symlink() or not patch_repo.is_dir():
        raise NotADirectoryError(f"KPM 仓库目录不可用: {patch_repo}")
    relative_path = _validate_relative_posix_path(
        "sukisu_patch.kpm_patch_path",
        dependency.get("kpm_patch_path"),
    )
    if relative_path != KPM_PATCH_PATH:
        raise ValueError(f"KPM patcher 路径必须固定为 {KPM_PATCH_PATH}")
    expected_hash = dependency.get("kpm_patch_sha256")
    if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
        raise ValueError("KPM patcher SHA256 元数据无效")
    expected_size = dependency.get("kpm_patch_size")
    if type(expected_size) is not int or expected_size <= 0:
        raise ValueError("KPM patcher size 元数据必须是正整数")

    repository_root = patch_repo.resolve()
    patch_linux = _require_regular_file(patch_repo / Path(relative_path), "KPM patch_linux")
    resolved_patch = patch_linux.resolve()
    try:
        resolved_patch.relative_to(repository_root)
    except ValueError as exc:
        raise ValueError("KPM patcher 路径越出固定仓库") from exc
    if patch_linux.stat().st_size != expected_size:
        raise RuntimeError("KPM patcher 文件大小与锁定元数据不一致")
    actual_hash = sha256_file(patch_linux)
    if actual_hash != expected_hash:
        raise RuntimeError("KPM patcher SHA256 与锁定元数据不一致")
    with patch_linux.open("rb") as patch_file:
        elf_header = patch_file.read(20)
    if len(elf_header) < 20 or elf_header[:4] != b"\x7fELF":
        raise ValueError("KPM patch_linux 不是 ELF 文件")
    if elf_header[4] != 2:
        raise ValueError("KPM patch_linux 必须是 ELF64")
    if elf_header[5] != 1:
        raise ValueError("KPM patch_linux 必须是 little-endian ELF")
    if int.from_bytes(elf_header[18:20], "little") != 62:
        raise ValueError("KPM patch_linux 必须是 x86_64 ELF")
    return resolved_patch, actual_hash


def prepare_kpm_patcher(
    patch_repo: Path,
    dependency: Mapping[str, object],
) -> tuple[Path, str]:
    patch_linux, patch_hash = validate_kpm_patcher(patch_repo, dependency)
    previous_mode = patch_linux.stat().st_mode
    patch_linux.chmod(previous_mode | stat.S_IXUSR)
    if not os.access(patch_linux, os.X_OK):
        raise PermissionError("KPM patcher 未获得 owner execute 权限")
    if os.name == "posix":
        previous_exec = previous_mode & (stat.S_IXGRP | stat.S_IXOTH)
        current_mode = patch_linux.stat().st_mode
        if not current_mode & stat.S_IXUSR or current_mode & (stat.S_IXGRP | stat.S_IXOTH) != previous_exec:
            raise PermissionError("KPM patcher 权限变更超出 owner execute")
    return patch_linux, patch_hash


def apply_kpm(
    runner: CommandRunner,
    patch_repo: Path,
    image_path: Path,
    dependency: Mapping[str, object],
) -> dict[str, str]:
    patch_linux, patch_hash = prepare_kpm_patcher(patch_repo, dependency)
    image_path = _require_regular_file(image_path, "Image")
    validate_image(image_path)
    backup_path = image_path.with_name("Image.pre-kpm")
    output_path = image_path.with_name("oImage")
    if backup_path.exists() or backup_path.is_symlink() or output_path.exists() or output_path.is_symlink():
        raise FileExistsError("KPM 输出或备份已存在，拒绝覆盖")
    pre_image_hash = sha256_file(image_path)
    shutil.copy2(image_path, backup_path)
    runner.run([str(patch_linux)], cwd=image_path.parent)
    try:
        _require_regular_file(output_path, "KPM oImage")
        validate_image(output_path)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise RuntimeError("KPM 未生成有效非空 oImage") from exc
    post_image_hash = sha256_file(output_path)
    if post_image_hash == pre_image_hash:
        raise RuntimeError("KPM 前后 Image SHA256 相同")
    os.replace(output_path, image_path)
    validate_image(image_path)
    return {
        "patcher_sha256": patch_hash,
        "pre_image_sha256": pre_image_hash,
        "post_image_sha256": post_image_hash,
    }


def validate_kernel_release(release_path: Path, source: SourceSpec) -> str:
    release_path = _require_regular_file(release_path, "kernel.release")
    release_lines = release_path.read_text(encoding="utf-8").splitlines()
    if len(release_lines) != 1 or not release_lines[0].strip():
        raise RuntimeError("kernel.release 必须恰好包含一行非空版本号")
    release = release_lines[0].strip()
    if not release.startswith(source.expected_release_prefix):
        raise RuntimeError(
            f"kernel.release 不匹配: 期望前缀 {source.expected_release_prefix}，实际 {release}"
        )
    return release


def validate_image(image_path: Path) -> None:
    image_path = _require_regular_file(image_path, "Image")
    file_size = image_path.stat().st_size
    if file_size < ARM64_IMAGE_MIN_SIZE:
        raise ValueError("Image 实际大小小于 8 MiB")
    with image_path.open("rb") as image_file:
        header = image_file.read(0x3C)
    if len(header) < 0x3C:
        raise ValueError("Image 头部过短")
    if header[0x38:0x3C] != ARM64_IMAGE_MAGIC:
        raise RuntimeError("Image 缺少 ARM64 magic")
    image_size = int.from_bytes(header[0x10:0x18], "little")
    if not ARM64_IMAGE_MIN_SIZE <= image_size <= ARM64_IMAGE_MAX_SIZE:
        raise RuntimeError("Image 头部 image_size 超出 8 MiB 到 256 MiB 范围")
    if file_size < image_size:
        raise RuntimeError("Image 实际大小小于头部声明的 image_size")


def _ensure_inside(path: Path, root: Path, label: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} 越出本次 workspace: {path}") from exc


def publish_artifacts(
    workspace: Path,
    artifacts_dir: Path,
    sources: Mapping[str, Path],
    build_info: Mapping[str, object],
) -> dict[str, str]:
    workspace = Path(workspace)
    artifacts_dir = Path(artifacts_dir)
    if artifacts_dir.exists() or artifacts_dir.is_symlink():
        raise FileExistsError(f"产物目录已存在，拒绝混入旧文件: {artifacts_dir}")
    if not sources:
        raise ValueError("产物集合为空")
    source_names = set(sources)
    allowed = REQUIRED_ARTIFACT_NAMES | OPTIONAL_ARTIFACT_NAMES
    if not REQUIRED_ARTIFACT_NAMES.issubset(source_names):
        missing = ", ".join(sorted(REQUIRED_ARTIFACT_NAMES - source_names))
        raise ValueError(f"缺少必需产物: {missing}")
    if not source_names.issubset(allowed):
        unexpected = ", ".join(sorted(source_names - allowed))
        raise ValueError(f"包含未允许产物: {unexpected}")

    validated: dict[str, Path] = {}
    for name, source_path in sources.items():
        if Path(name).name != name:
            raise ValueError(f"产物名称不安全: {name}")
        source_path = _require_regular_file(Path(source_path), name)
        _ensure_inside(source_path, workspace, name)
        validated[name] = source_path

    artifacts_dir.mkdir(parents=True)
    try:
        for name, source_path in validated.items():
            shutil.copy2(source_path, artifacts_dir / name)
        payload_hashes = {
            name: sha256_file(artifacts_dir / name)
            for name in sorted(validated)
        }
        complete_info = dict(build_info)
        complete_info["files"] = payload_hashes
        build_info_path = artifacts_dir / "BUILD_INFO.json"
        build_info_path.write_text(
            json.dumps(complete_info, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        checksum_targets = sorted([*validated, "BUILD_INFO.json"])
        checksum_lines = [
            f"{sha256_file(artifacts_dir / name)}  {name}"
            for name in checksum_targets
        ]
        (artifacts_dir / "SHA256SUMS.txt").write_text(
            "\n".join(checksum_lines) + "\n",
            encoding="utf-8",
        )
        expected_names = source_names | {"BUILD_INFO.json", "SHA256SUMS.txt"}
        actual_names = {path.name for path in artifacts_dir.iterdir()}
        if actual_names != expected_names:
            raise RuntimeError("产物目录包含缺失或未允许文件")
        for path in artifacts_dir.iterdir():
            _require_regular_file(path, f"产物 {path.name}")
    except Exception:
        shutil.rmtree(artifacts_dir)
        raise
    return payload_hashes


def make_build_info(
    source: SourceSpec,
    profile: ProfileSpec,
    dependencies: Mapping[str, Mapping[str, object]],
    *,
    kpm_patcher_sha256: str | None = None,
    kpm_audit: Mapping[str, str] | None = None,
) -> dict[str, object]:
    dependency_commits = {
        name: dependencies[name]["commit"]
        for name in dependency_names_for_profile(source, profile)
    }
    info: dict[str, object] = {
        "device": "mayfly",
        "source": source.to_dict(),
        "profile": profile.name,
        "features": profile.feature_dict(),
        "dependencies": dependency_commits,
        "lto": "full",
        "build_config": "common/build.config.gki.aarch64",
        "check_defconfig_disabled": True,
        "final_config_validation": True,
        "excluded_patches": dict(EXCLUDED_PATCHES),
        "patch_exclusions": dict(PATCH_EXCLUSIONS),
        "applied_patches": list(planned_patch_paths(profile)),
        "local_patches": {
            "sukisu_susfs_compat": {
                "path": dependencies["susfs4ksu"].get("mayfly_compat_patch_path"),
                "sha256": dependencies["susfs4ksu"].get("mayfly_compat_patch_sha256"),
            }
        },
        "kernelsu": _kernelsu_version_info(
            version_name=dependencies["sukisu_ultra"].get("version_name"),
            version_code=dependencies["sukisu_ultra"].get("version_code"),
            commit=dependencies["sukisu_ultra"].get("commit"),
        ),
    }
    if kpm_audit is not None:
        if not profile.kpm:
            raise ValueError("非 KPM profile 不得包含 KPM 审计信息")
        audit_values = {
            name: kpm_audit.get(name)
            for name in ("patcher_sha256", "pre_image_sha256", "post_image_sha256")
        }
        for name, value in audit_values.items():
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ValueError(f"KPM {name} 无效")
        if audit_values["pre_image_sha256"] == audit_values["post_image_sha256"]:
            raise ValueError("KPM 前后 Image SHA256 不能相同")
        dependency = dependencies["sukisu_patch"]
        expected_patcher_hash = dependency.get("kpm_patch_sha256")
        if (
            not isinstance(expected_patcher_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_patcher_hash) is None
            or audit_values["patcher_sha256"] != expected_patcher_hash
        ):
            raise ValueError("KPM patcher SHA256 审计值与依赖锁不一致")
        info["kpm_patcher_sha256"] = audit_values["patcher_sha256"]
        info["kpm"] = {
            "patcher": {
                "path": dependency.get("kpm_patch_path"),
                "sha256": audit_values["patcher_sha256"],
                "size": dependency.get("kpm_patch_size"),
            },
            "pre_image": {"sha256": audit_values["pre_image_sha256"]},
            "post_image": {"sha256": audit_values["post_image_sha256"]},
        }
    elif kpm_patcher_sha256 is not None:
        raise ValueError("KPM 审计必须同时包含 patcher、pre_image 和 post_image SHA256")
    elif profile.kpm:
        raise ValueError("KPM profile 缺少 patcher 与 Image SHA256 审计信息")
    return info


class MayflyBuilder:
    """Own the dedicated mayfly build state without touching generic builders."""

    def __init__(
        self,
        source_name: str,
        profile_name: str,
        workspace: Path,
        artifacts_dir: Path,
        *,
        lock_path: Path = DEFAULT_LOCK_PATH,
        runner: CommandRunner | None = None,
        jobs: int = 4,
    ) -> None:
        try:
            self.source = SOURCE_SPECS[source_name]
        except KeyError as exc:
            raise ValueError(f"不支持的 mayfly source: {source_name}") from exc
        try:
            self.profile = PROFILE_SPECS[profile_name]
        except KeyError as exc:
            raise ValueError(f"不支持的 mayfly profile: {profile_name}") from exc
        self.workspace = Path(workspace)
        self.artifacts_dir = Path(artifacts_dir)
        self.lock_path = Path(lock_path)
        self.runner = runner or CommandRunner()
        self.jobs = _validated_jobs(jobs)
        self._manifest_pins: dict[str, str] | None = None

    def _validated_dependencies(self) -> dict[str, dict[str, object]]:
        dependencies = load_dependencies(self.lock_path)
        _validate_source_pins(self.source, dependencies)
        needed = dependency_names_for_profile(self.source, self.profile)
        missing = [name for name in needed if name not in dependencies]
        if missing:
            raise ValueError(f"依赖锁缺少 profile 依赖: {', '.join(missing)}")
        if self.profile.kpm:
            patcher_hash = dependencies["sukisu_patch"].get("kpm_patch_sha256")
            if not isinstance(patcher_hash, str) or re.fullmatch(r"[0-9a-f]{64}", patcher_hash) is None:
                raise ValueError("KPM patcher SHA256 必须是完整 64 位小写十六进制值")
        return dependencies

    def dry_run(self) -> dict[str, object]:
        dependencies = self._validated_dependencies()
        needed = dependency_names_for_profile(self.source, self.profile)
        return {
            "mode": "dry-run",
            "device": "mayfly",
            "source": self.source.to_dict(),
            "profile": self.profile.to_dict(),
            "workspace": str(self.workspace),
            "artifacts": str(self.artifacts_dir),
            "jobs": self.jobs,
            "lto": "full",
            "dependencies": {
                name: {
                    "repo_url": dependencies[name]["repo_url"],
                    "commit": dependencies[name]["commit"],
                }
                for name in needed
            },
            "patches": list(planned_patch_paths(self.profile)),
            "excluded_patches": dict(EXCLUDED_PATCHES),
        }

    def _prepare_workspace(self) -> None:
        if self.workspace.exists() or self.workspace.is_symlink():
            raise FileExistsError(f"workspace 已存在，拒绝复用: {self.workspace}")
        if self.artifacts_dir.exists() or self.artifacts_dir.is_symlink():
            raise FileExistsError(f"产物目录已存在，拒绝混入旧文件: {self.artifacts_dir}")
        self.workspace.mkdir(parents=True)
        (self.workspace / "tools").mkdir()
        (self.workspace / "work").mkdir()

    def _prepare_repo_tool(
        self,
        dependencies: Mapping[str, Mapping[str, object]],
    ) -> Path:
        repo_dir = self.workspace / "tools" / "git-repo"
        clone_pinned_dependency(self.runner, dependencies["git_repo"], repo_dir)
        repo_path_value = _validate_relative_posix_path(
            "git_repo.path",
            dependencies["git_repo"].get("path"),
        )
        if "/" in repo_path_value:
            raise ValueError("git-repo path 必须是简单相对文件名")
        repo_tool = _require_regular_file(repo_dir / repo_path_value, "固定 git-repo launcher")
        result = self.runner.run(
            [sys.executable, str(repo_tool), "--version"],
            capture_output=True,
        )
        version_output = "\n".join((result.stdout or "", result.stderr or ""))
        expected = f"repo launcher version {dependencies['git_repo']['version']}"
        if expected not in version_output:
            raise RuntimeError(f"git-repo launcher 版本不匹配，必须包含 {expected}")
        return repo_tool

    def _prepare_superproject(
        self,
        dependencies: Mapping[str, Mapping[str, object]],
    ) -> dict[str, str]:
        superproject_dir = self.workspace / "work" / "superproject"
        dependency = dependencies[self.source.superproject_dependency]
        clone_pinned_dependency(self.runner, dependency, superproject_dir)
        result = self.runner.run(
            [
                "git",
                "-C",
                str(superproject_dir),
                "ls-tree",
                "-r",
                self.source.superproject_commit,
            ],
            capture_output=True,
        )
        return parse_superproject_ls_tree(
            result.stdout,
            expected_common_commit=self.source.common_commit,
        )

    def _sync_source(
        self,
        dependencies: Mapping[str, Mapping[str, object]],
        repo_tool: Path,
        project_pins: Mapping[str, str],
    ) -> Path:
        source_root = self.workspace / "source"
        if source_root.exists() or source_root.is_symlink():
            raise FileExistsError(f"source 目录已存在: {source_root}")
        source_root.mkdir()
        self.runner.run(
            repo_init_command(repo_tool, self.source, dependencies),
            cwd=source_root,
        )
        manifest_path_value = _validate_relative_posix_path(
            f"{self.source.manifest_dependency}.path",
            dependencies[self.source.manifest_dependency].get("path"),
        )
        manifest_path = source_root / ".repo" / "manifests" / Path(*manifest_path_value.split("/"))
        self._manifest_pins = rewrite_manifest_with_superproject(
            manifest_path,
            project_pins,
            common_upstream=self.source.common_ref,
        )
        self.runner.run(
            repo_sync_command(repo_tool, jobs=self.jobs),
            cwd=source_root,
        )
        common_dir = source_root / "common"
        if common_dir.is_symlink() or not common_dir.is_dir():
            raise RuntimeError(f"repo sync 后 common 目录不存在: {common_dir}")
        verify_common_head(self.runner, common_dir, self.source)
        resolved_manifest = source_root / "resolved-manifest.xml"
        if resolved_manifest.exists() or resolved_manifest.is_symlink():
            raise FileExistsError(f"resolved manifest 已存在: {resolved_manifest}")
        self.runner.run(
            repo_manifest_command(repo_tool, resolved_manifest),
            cwd=source_root,
        )
        validate_resolved_manifest(
            resolved_manifest,
            expected_common_commit=self.source.common_commit,
            expected_projects=self._manifest_pins,
        )
        return source_root

    def _clone_dependencies(
        self,
        dependencies: Mapping[str, Mapping[str, object]],
    ) -> dict[str, Path]:
        work_dir = self.workspace / "work"
        if work_dir.is_symlink() or not work_dir.is_dir():
            raise RuntimeError(f"work 目录不存在: {work_dir}")
        repositories = {
            "kernelsu": work_dir / "KernelSU",
            "susfs": work_dir / "susfs4ksu",
        }
        clone_pinned_dependency(
            self.runner,
            dependencies["sukisu_ultra"],
            repositories["kernelsu"],
        )
        clone_pinned_dependency(
            self.runner,
            dependencies["susfs4ksu"],
            repositories["susfs"],
        )
        if self.profile.kpm or self.profile.zram_lz4kd:
            repositories["sukisu_patch"] = work_dir / "SukiSU_patch"
            clone_pinned_dependency(
                self.runner,
                dependencies["sukisu_patch"],
                repositories["sukisu_patch"],
            )
        if self.profile.bbg:
            repositories["bbg"] = work_dir / "Baseband-guard"
            clone_pinned_dependency(
                self.runner,
                dependencies["baseband_guard"],
                repositories["bbg"],
                shallow=False,
            )
        return repositories

    def _integrate_sources(
        self,
        source_root: Path,
        repositories: Mapping[str, Path],
        dependencies: Mapping[str, Mapping[str, object]],
    ) -> None:
        common_dir = Path(source_root) / "common"
        if common_dir.is_symlink() or not common_dir.is_dir():
            raise RuntimeError(f"common 目录不可用: {common_dir}")
        integrate_kernelsu(common_dir, repositories["kernelsu"])
        integrate_susfs(
            self.runner,
            common_dir,
            repositories["kernelsu"],
            repositories["susfs"],
            dependencies["sukisu_ultra"],
            dependencies["susfs4ksu"],
        )
        validate_kernelsu_hardening(repositories["kernelsu"])
        if self.profile.zram_lz4kd:
            integrate_lz4kd(self.runner, common_dir, repositories["sukisu_patch"])
        if self.profile.bbg:
            integrate_bbg(common_dir, repositories["bbg"])

    def _configure_source(self, source_root: Path) -> None:
        configure_profile_defconfig(Path(source_root) / "common", self.profile)

    def _run_kernel_build(self, source_root: Path) -> None:
        source_root = Path(source_root)
        build_script = _require_regular_file(
            source_root / "build" / "build.sh",
            "build/build.sh",
        )
        command = kernel_build_command(source_root, jobs=self.jobs)
        if Path(command[0]) != build_script:
            raise RuntimeError("构建入口不是固定 build/build.sh")
        self.runner.run(
            command,
            cwd=source_root,
            env=kernel_build_environment(),
        )

    def _output_paths(self, source_root: Path) -> dict[str, Path]:
        source_root = Path(source_root)
        output_root = source_root / "out" / "android12-5.10"
        return {
            "Image": output_root / "dist" / "Image",
            "final.config": output_root / "common" / ".config",
            "resolved-manifest.xml": source_root / "resolved-manifest.xml",
            "kernel.release": output_root / "common" / "include" / "config" / "kernel.release",
        }

    def _validate_build_outputs(self, source_root: Path) -> None:
        if not self._manifest_pins:
            raise RuntimeError("缺少预固定 manifest project pins")
        paths = self._output_paths(source_root)
        validate_final_config(paths["final.config"], self.profile)
        validate_kernel_release(paths["kernel.release"], self.source)
        validate_image(paths["Image"])
        validate_resolved_manifest(
            paths["resolved-manifest.xml"],
            expected_common_commit=self.source.common_commit,
            expected_projects=self._manifest_pins,
        )

    def _apply_kpm_if_enabled(
        self,
        source_root: Path,
        repositories: Mapping[str, Path],
        dependencies: Mapping[str, Mapping[str, object]],
    ) -> dict[str, str] | None:
        if not self.profile.kpm:
            return None
        patch_repo = repositories.get("sukisu_patch")
        if patch_repo is None:
            raise RuntimeError("KPM profile 缺少固定 SukiSU_patch 仓库")
        image_path = self._output_paths(source_root)["Image"]
        audit = apply_kpm(
            self.runner,
            patch_repo,
            image_path,
            dependencies["sukisu_patch"],
        )
        validate_image(image_path)
        return audit

    def _artifact_sources(self, source_root: Path) -> dict[str, Path]:
        source_root = Path(source_root)
        paths = self._output_paths(source_root)
        dist_dir = paths["Image"].parent
        backup = dist_dir / "Image.pre-kpm"
        if self.profile.kpm:
            paths["Image.pre-kpm"] = _require_regular_file(backup, "Image.pre-kpm")
        elif backup.exists() or backup.is_symlink():
            raise RuntimeError("非 KPM profile 出现意外 Image.pre-kpm")
        module_candidates = (
            dist_dir / "Module.symvers",
            source_root / "out" / "android12-5.10" / "common" / "Module.symvers",
        )
        for candidate in module_candidates:
            if candidate.exists() or candidate.is_symlink():
                paths["Module.symvers"] = _require_regular_file(candidate, "Module.symvers")
                break
        return paths

    def _publish_build_outputs(
        self,
        dependencies: Mapping[str, Mapping[str, object]],
        source_root: Path,
        kpm_audit: Mapping[str, str] | None,
    ) -> dict[str, str]:
        build_info = make_build_info(
            self.source,
            self.profile,
            dependencies,
            kpm_audit=kpm_audit,
        )
        return publish_artifacts(
            self.workspace,
            self.artifacts_dir,
            self._artifact_sources(source_root),
            build_info,
        )

    def build(self) -> dict[str, object]:
        dependencies = self._validated_dependencies()
        LOGGER.info("stage=workspace source=%s profile=%s", self.source.name, self.profile.name)
        self._prepare_workspace()
        LOGGER.info("stage=repo prepare pinned launcher")
        repo_tool = self._prepare_repo_tool(dependencies)
        LOGGER.info("stage=superproject clone and parse pinned gitlinks")
        project_pins = self._prepare_superproject(dependencies)
        LOGGER.info("stage=sync initialize and resolve source")
        source_root = self._sync_source(dependencies, repo_tool, project_pins)
        LOGGER.info("stage=clone fetch pinned feature repositories")
        repositories = self._clone_dependencies(dependencies)
        LOGGER.info("stage=integrate apply strict source changes")
        self._integrate_sources(source_root, repositories, dependencies)
        LOGGER.info("stage=configure write mayfly profile")
        self._configure_source(source_root)
        LOGGER.info("stage=build run build/build.sh")
        self._run_kernel_build(source_root)
        LOGGER.info("stage=validate verify config release manifest and Image")
        self._validate_build_outputs(source_root)
        LOGGER.info("stage=kpm apply=%s", self.profile.kpm)
        kpm_audit = self._apply_kpm_if_enabled(source_root, repositories, dependencies)
        LOGGER.info("stage=publish write allowlisted artifacts")
        files = self._publish_build_outputs(
            dependencies,
            source_root,
            kpm_audit,
        )
        return {
            "mode": "build",
            "device": "mayfly",
            "source": self.source.name,
            "profile": self.profile.name,
            "artifacts": str(self.artifacts_dir),
            "files": files,
        }
