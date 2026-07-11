from dataclasses import dataclass
from enum import Enum
import json
from pathlib import Path, PurePosixPath
import re
from typing import Optional
from urllib.parse import urlsplit


_LOCK_PATH = Path(__file__).resolve().parent.parent / "config" / "dependencies.lock.json"
_FULL_LOWER_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SEMANTIC_VERSION_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
_SAFE_REPO_URL_PATTERN = re.compile(r"^[A-Za-z0-9._~:/-]+$")
_SAFE_RELATIVE_POSIX_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_SAFE_GIT_REF_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
_REQUIRED_GIT_DEPENDENCIES = frozenset(
    {
        "sukisu_ultra",
        "susfs4ksu",
        "sukisu_patch",
        "anykernel3",
        "baseband_guard",
        "git_repo",
        "android_manifest_2024_11",
        "android_common_2024_11_head",
        "mayfly_stock_common_baseline",
        "android_manifest_2025_05",
        "android_common_2025_05",
        "android_common_2025_05_r1",
        "android_superproject_2024_11",
        "android_superproject_2025_05",
    }
)
_REQUIRED_DEPENDENCY_METADATA = {
    "sukisu_ultra": ("setup_path", "version_name"),
    "susfs4ksu": (
        "version",
        "patch_path",
        "mayfly_compat_patch_path",
        "mayfly_compat_patch_sha256",
        "mayfly_task_mmu_patch_path",
        "mayfly_task_mmu_patch_sha256",
    ),
    "sukisu_patch": (
        "kpm_patch_path",
        "hide_stuff_patch_path",
        "hide_stuff_patch_sha256",
        "mayfly_hide_stuff_patch_path",
        "mayfly_hide_stuff_patch_sha256",
    ),
    "baseband_guard": ("setup_path",),
    "git_repo": ("path", "version"),
    "android_manifest_2024_11": ("ref", "path"),
    "android_manifest_2025_05": ("ref", "path"),
    "android_common_2024_11_head": ("ref",),
    "mayfly_stock_common_baseline": ("ref",),
    "android_common_2025_05": ("ref",),
    "android_common_2025_05_r1": ("ref", "release_tag"),
    "android_superproject_2024_11": ("ref", "common_commit"),
    "android_superproject_2025_05": ("ref", "common_commit"),
}
_SAFE_RELATIVE_PATH_FIELDS = frozenset(
    {
        "path",
        "setup_path",
        "patch_path",
        "mayfly_compat_patch_path",
        "mayfly_task_mmu_patch_path",
        "hide_stuff_patch_path",
        "mayfly_hide_stuff_patch_path",
    }
)
_MAYFLY_COMPAT_PATCH_PATH = "patches/sukisu-v4.1.3-susfs-v2.2.0-compat.patch"
_MAYFLY_COMPAT_PATCH_SHA256 = "32cd15ec68f7c6fb00857f01144da905b60d547ccb6141a92d35aa1261b6c994"
_MAYFLY_TASK_MMU_PATCH_PATH = "patches/mayfly-android12-5.10-susfs-task-mmu.patch"
_MAYFLY_TASK_MMU_PATCH_SHA256 = "c3e70b66d8b67aa29ab6935954deb7cf4402e44e231b73e7cee1a4dedc0326c1"
_HIDE_STUFF_PATCH_PATH = "69_hide_stuff.patch"
_HIDE_STUFF_PATCH_SHA256 = "59965d78e4ff2d7a427b8c2a0ddfedbb75693bda60934ec9bdc4d7627fb666a5"
_HIDE_STUFF_PATCH_SIZE = 2601
_MAYFLY_HIDE_STUFF_PATCH_PATH = "patches/mayfly-android12-5.10-69-hide-stuff.patch"
_MAYFLY_HIDE_STUFF_PATCH_SHA256 = "f743de89e1079402f5b1742daed22ec50357949cc4c9ab824b39f486a4815f53"


def _validate_https_repo_url(dependency_name: str, repo_url: object) -> None:
    error_message = f"依赖 {dependency_name} 必须提供严格的 HTTPS repo_url"
    if (
        not isinstance(repo_url, str)
        or repo_url != repo_url.strip()
        or _SAFE_REPO_URL_PATTERN.fullmatch(repo_url) is None
        or any(character.isspace() for character in repo_url)
        or "\\" in repo_url
        or "?" in repo_url
        or "#" in repo_url
    ):
        raise ValueError(error_message)

    try:
        parsed_url = urlsplit(repo_url)
        hostname = parsed_url.hostname
        port = parsed_url.port
    except ValueError as exc:
        raise ValueError(error_message) from exc

    if (
        parsed_url.scheme != "https"
        or not hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
        or port is not None
        or not parsed_url.path
        or not parsed_url.path.startswith("/")
    ):
        raise ValueError(error_message)


def _is_safe_relative_posix_path(path_value: str) -> bool:
    path = PurePosixPath(path_value)
    path_segments = path_value.split("/")
    return (
        _SAFE_RELATIVE_POSIX_PATH_PATTERN.fullmatch(path_value) is not None
        and not path_value.startswith("-")
        and "//" not in path_value
        and "\\" not in path_value
        and not path.is_absolute()
        and all(segment not in (".", "..") for segment in path_segments)
    )


def _is_safe_git_ref(ref_value: object) -> bool:
    return (
        isinstance(ref_value, str)
        and _SAFE_GIT_REF_PATTERN.fullmatch(ref_value) is not None
        and not ref_value.startswith(("-", "/"))
        and ".." not in ref_value
        and "//" not in ref_value
        and not ref_value.endswith(("/", "."))
    )


def _validate_dependency_lock(lock_data: object) -> dict[str, dict[str, object]]:
    if not isinstance(lock_data, dict):
        raise ValueError("依赖锁根节点必须是对象")
    if type(lock_data.get("schema_version")) is not int or lock_data["schema_version"] != 1:
        raise ValueError("依赖锁 schema_version 必须为 1")

    dependencies = lock_data.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ValueError("依赖锁 dependencies 必须是对象")

    missing_dependencies = _REQUIRED_GIT_DEPENDENCIES.difference(dependencies)
    if missing_dependencies:
        missing = ", ".join(sorted(missing_dependencies))
        raise ValueError(f"依赖锁缺少必需条目: {missing}")

    for name, dependency in dependencies.items():
        if not isinstance(name, str) or not name:
            raise ValueError("依赖锁名称必须是非空字符串")
        if not isinstance(dependency, dict):
            raise ValueError(f"依赖 {name} 必须是对象")

        _validate_https_repo_url(name, dependency.get("repo_url"))

        commit = dependency.get("commit")
        if not isinstance(commit, str) or _FULL_LOWER_SHA_PATTERN.fullmatch(commit) is None:
            raise ValueError(f"依赖 {name} 必须提供 40 位小写十六进制 commit")

        for field_name in ("branch", "ref", "release_tag"):
            if field_name in dependency and not _is_safe_git_ref(dependency[field_name]):
                raise ValueError(f"依赖 {name}.{field_name} 必须是安全的 Git ref")

    for dependency_name, field_names in _REQUIRED_DEPENDENCY_METADATA.items():
        dependency = dependencies[dependency_name]
        for field_name in field_names:
            field_value = dependency.get(field_name)
            if not isinstance(field_value, str) or not field_value.strip():
                raise ValueError(f"依赖 {dependency_name}.{field_name} 必须是非空字符串")
            if field_name in _SAFE_RELATIVE_PATH_FIELDS and not _is_safe_relative_posix_path(field_value):
                raise ValueError(f"依赖 {dependency_name}.{field_name} 必须是安全的相对 POSIX 路径")

    susfs_version = dependencies["susfs4ksu"].get("version")
    if not isinstance(susfs_version, str) or _SEMANTIC_VERSION_PATTERN.fullmatch(susfs_version) is None:
        raise ValueError("依赖 susfs4ksu 必须提供语义化版本号")
    susfs = dependencies["susfs4ksu"]
    if susfs.get("mayfly_compat_patch_path") != _MAYFLY_COMPAT_PATCH_PATH:
        raise ValueError("依赖 susfs4ksu.mayfly_compat_patch_path 与固定路径不一致")
    if susfs.get("mayfly_compat_patch_sha256") != _MAYFLY_COMPAT_PATCH_SHA256:
        raise ValueError("依赖 susfs4ksu.mayfly_compat_patch_sha256 与固定哈希不一致")
    if susfs.get("mayfly_task_mmu_patch_path") != _MAYFLY_TASK_MMU_PATCH_PATH:
        raise ValueError("依赖 susfs4ksu.mayfly_task_mmu_patch_path 与固定路径不一致")
    if susfs.get("mayfly_task_mmu_patch_sha256") != _MAYFLY_TASK_MMU_PATCH_SHA256:
        raise ValueError("依赖 susfs4ksu.mayfly_task_mmu_patch_sha256 与固定哈希不一致")

    kernelsu = dependencies["sukisu_ultra"]
    if kernelsu.get("version_name") != "4.1.3":
        raise ValueError("依赖 sukisu_ultra.version_name 必须固定为 4.1.3")
    if type(kernelsu.get("version_code")) is not int or kernelsu["version_code"] != 40796:
        raise ValueError("依赖 sukisu_ultra.version_code 必须固定为整数 40796")

    kpm = dependencies["sukisu_patch"]
    if kpm.get("kpm_patch_path") != "kpm/patch_linux":
        raise ValueError("依赖 sukisu_patch.kpm_patch_path 必须固定为 kpm/patch_linux")
    if kpm.get("kpm_patch_sha256") != "1bd00563e9d8fbbd11a16c0c1c59c5add406e6c5c92557def50f93d6f0aebe2d":
        raise ValueError("依赖 sukisu_patch.kpm_patch_sha256 必须匹配固定的完整 64 位 SHA256")
    if type(kpm.get("kpm_patch_size")) is not int or kpm["kpm_patch_size"] != 6013320:
        raise ValueError("依赖 sukisu_patch.kpm_patch_size 必须固定为整数 6013320")
    if kpm.get("hide_stuff_patch_path") != _HIDE_STUFF_PATCH_PATH:
        raise ValueError("依赖 sukisu_patch.hide_stuff_patch_path 与固定路径不一致")
    if kpm.get("hide_stuff_patch_sha256") != _HIDE_STUFF_PATCH_SHA256:
        raise ValueError("依赖 sukisu_patch.hide_stuff_patch_sha256 与固定哈希不一致")
    if type(kpm.get("hide_stuff_patch_size")) is not int or kpm["hide_stuff_patch_size"] != _HIDE_STUFF_PATCH_SIZE:
        raise ValueError("依赖 sukisu_patch.hide_stuff_patch_size 与固定大小不一致")
    if kpm.get("mayfly_hide_stuff_patch_path") != _MAYFLY_HIDE_STUFF_PATCH_PATH:
        raise ValueError("依赖 sukisu_patch.mayfly_hide_stuff_patch_path 与固定路径不一致")
    if kpm.get("mayfly_hide_stuff_patch_sha256") != _MAYFLY_HIDE_STUFF_PATCH_SHA256:
        raise ValueError("依赖 sukisu_patch.mayfly_hide_stuff_patch_sha256 与固定哈希不一致")

    if dependencies["git_repo"].get("version") != "2.15":
        raise ValueError("依赖 git_repo.version 必须固定为 2.15")

    branch_head = dependencies["android_common_2025_05"]
    if branch_head.get("branch_head_date") != "2026-05-26":
        raise ValueError("依赖 android_common_2025_05 必须标注 2026-05-26 branch head 日期")
    if branch_head.get("experimental_only") is not True:
        raise ValueError("依赖 android_common_2025_05 必须标记 experimental_only=true")

    for dependency_name in ("android_superproject_2024_11", "android_superproject_2025_05"):
        common_commit = dependencies[dependency_name].get("common_commit")
        if not isinstance(common_commit, str) or _FULL_LOWER_SHA_PATTERN.fullmatch(common_commit) is None:
            raise ValueError(f"依赖 {dependency_name}.common_commit 必须是完整 40 位小写 commit")

    return dependencies


def _load_dependency_lock(lock_path: Path = _LOCK_PATH) -> dict[str, dict[str, object]]:
    try:
        with lock_path.open("r", encoding="utf-8") as lock_file:
            lock_data = json.load(lock_file)
    except FileNotFoundError as exc:
        raise RuntimeError(f"依赖锁文件不存在: {lock_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"依赖锁文件不是有效的 JSON: {lock_path}") from exc
    except OSError as exc:
        raise RuntimeError(f"无法读取依赖锁文件: {lock_path}") from exc
    return _validate_dependency_lock(lock_data)


DEPENDENCY_LOCK = _load_dependency_lock()
KERNEL_VERSION = DEPENDENCY_LOCK["susfs4ksu"]["version"]


class AndroidVersion(Enum):
    ANDROID12 = "android12"
    ANDROID13 = "android13"
    ANDROID14 = "android14"
    ANDROID15 = "android15"


class KernelVersion(Enum):
    KERNEL_5_10 = "5.10"
    KERNEL_5_15 = "5.15"
    KERNEL_6_1 = "6.1"
    KERNEL_6_6 = "6.6"


class KSUVersion(Enum):
    STABLE = "Stable(标准)"
    DEV = "Dev(开发)"


ANDROID_KERNEL_MAP = {
    AndroidVersion.ANDROID12: [KernelVersion.KERNEL_5_10],
    AndroidVersion.ANDROID13: [KernelVersion.KERNEL_5_10, KernelVersion.KERNEL_5_15],
    AndroidVersion.ANDROID14: [KernelVersion.KERNEL_5_15, KernelVersion.KERNEL_6_1],
    AndroidVersion.ANDROID15: [KernelVersion.KERNEL_6_6],
}

# Locked repository configurations
KSU_REPO_CONFIG = dict(DEPENDENCY_LOCK["sukisu_ultra"])
KSU_REPO_CONFIG["setup_script"] = (
    "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/"
    f"{KSU_REPO_CONFIG['commit']}/{KSU_REPO_CONFIG['setup_path']}"
)
SUSFS_REPO_CONFIG = dict(DEPENDENCY_LOCK["susfs4ksu"])
SUKISU_PATCH_REPO_CONFIG = dict(DEPENDENCY_LOCK["sukisu_patch"])
ANYKERNEL_CONFIG = dict(DEPENDENCY_LOCK["anykernel3"])

# Kernel Patches 仓库配置
KERNEL_PATCHES_CONFIG = {"repo_url": "https://github.com/Tools-cx-app/kernel_patches.git"}

BBG_CONFIG = dict(DEPENDENCY_LOCK["baseband_guard"])
BBG_CONFIG["setup_script"] = (
    "https://raw.githubusercontent.com/vc-teahouse/Baseband-guard/"
    f"{BBG_CONFIG['commit']}/{BBG_CONFIG['setup_path']}"
)

# 工具链配置
TOOLCHAIN_CONFIG = {"aosp_mirror": "https://android.googlesource.com",
                    "build_tools_branch": "main-kernel-build-2024",
                    "mkbootimg_branch": "main-kernel-build-2024"}
LEGACY_FIXES = {
    "android13-5.15-below-123": {"url": "https://github.com/zzh20188/GKI_KernelSU_SUSFS/raw/refs/heads/legacy/fix_5.15.legacy", "min_sub_level": 123},
    "android12-5.10-below-136": {"url": "https://github.com/zzh20188/GKI_KernelSU_SUSFS/raw/refs/heads/legacy/fdinfo.c.patch", "min_sub_level": 136},
}
OP8E_PATCH_URL = "https://github.com/zzh20188/GKI_KernelSU_SUSFS/raw/refs/heads/dev/hmbird_patch.c"
KPM_PATCH_URL = "https://raw.githubusercontent.com/ShirkNeko/SukiSU_patch/refs/heads/main/kpm/patch_linux"


@dataclass
class BuildConfig:
    android_version: str
    kernel_version: str
    sub_level: str
    os_patch_level: str
    kernelsu_version: str = "Stable(标准)"
    kernelsu_commit: Optional[str] = None
    susfs_commit: Optional[str] = None
    use_zram: bool = False
    use_kpm: bool = True
    use_bbg: bool = False
    support_op8e: bool = False
    set_default_bbr: bool = False
    make_release: bool = True
    custom_version: Optional[str] = None
    revision: Optional[str] = None
    build_id: Optional[str] = None

    def __post_init__(self):
        self._validate_android_version()
        self._validate_kernel_version()
        self._validate_kernel_android_compat()
        self._validate_sub_level()
        self._validate_dependency_commits()
        self._validate_android12_5_10_inputs()
        self._set_build_id()

    def _validate_android_version(self):
        valid = [v.value for v in AndroidVersion]
        if self.android_version not in valid:
            raise ValueError(f"无效的 Android 版本: {self.android_version}. 支持: {', '.join(valid)}")

    def _validate_kernel_version(self):
        valid = [v.value for v in KernelVersion]
        if self.kernel_version not in valid:
            raise ValueError(f"无效的 Kernel 版本: {self.kernel_version}. 支持: {', '.join(valid)}")

    def _validate_kernel_android_compat(self):
        av = AndroidVersion(self.android_version)
        kv = KernelVersion(self.kernel_version)
        if kv not in ANDROID_KERNEL_MAP.get(av, []):
            raise ValueError(f"Android {self.android_version} 不支持 Kernel {self.kernel_version}")

    def _validate_sub_level(self):
        if self.sub_level != "X" and not self.sub_level.isdigit():
            raise ValueError(f"无效的 sub_level: {self.sub_level}")

    def _validate_dependency_commits(self):
        if self.kernelsu_commit is None:
            self.kernelsu_commit = KSU_REPO_CONFIG["commit"]
        if self.susfs_commit is None:
            self.susfs_commit = SUSFS_REPO_CONFIG["commit"]

        for field_name in ("kernelsu_commit", "susfs_commit"):
            commit = getattr(self, field_name)
            if not isinstance(commit, str) or not validate_commit_hash(commit):
                raise ValueError(f"无效的 {field_name}: 必须是完整的 40 位小写十六进制 commit")

    def _validate_android12_5_10_inputs(self):
        if self.android_version != "android12" or self.kernel_version != "5.10":
            return

        if self.sub_level == "X":
            if self.os_patch_level != "lts":
                raise ValueError("无效的 os_patch_level: sub_level 为 X 时必须使用 lts")
        elif not isinstance(self.os_patch_level, str) or re.fullmatch(
            r"[0-9]{4}-(0[1-9]|1[0-2])", self.os_patch_level
        ) is None:
            raise ValueError("无效的 os_patch_level: 数字 sub_level 必须使用 YYYY-MM 格式")
        if self.revision is not None and (
            not isinstance(self.revision, str) or re.fullmatch(r"r[0-9]+", self.revision) is None
        ):
            raise ValueError("无效的 revision: 必须使用 r+数字格式")
        if self.custom_version is not None and (
            not isinstance(self.custom_version, str)
            or re.fullmatch(r"[A-Za-z0-9._+-]{1,48}", self.custom_version) is None
        ):
            raise ValueError("无效的 custom_version: 仅允许 1 到 48 个安全字符")

    def _set_build_id(self):
        if self.build_id is None:
            self.build_id = f"{self.android_version}-{self.kernel_version}-{self.sub_level}-{self.os_patch_level}"

    @property
    def config_name(self) -> str:
        return f"{self.android_version}-{self.kernel_version}-{self.sub_level}"

    @property
    def formatted_branch(self) -> str:
        return f"{self.android_version}-{self.kernel_version}-{self.os_patch_level}"

    @property
    def kernel_branch(self) -> str:
        return f"gki-{self.android_version}-{self.kernel_version}"

    def get_susfs_patch_filename(self) -> str:
        return f"50_add_susfs_in_gki-{self.android_version}-{self.kernel_version}.patch"

    def is_lts(self) -> bool:
        return self.sub_level == "X"

    def get_sub_level_int(self) -> Optional[int]:
        return None if self.sub_level == "X" else int(self.sub_level)

    def to_dict(self) -> dict:
        return {
            "android_version": self.android_version,
            "kernel_version": self.kernel_version,
            "sub_level": self.sub_level,
            "os_patch_level": self.os_patch_level,
            "kernelsu_version": self.kernelsu_version,
            "kernelsu_commit": self.kernelsu_commit,
            "susfs_commit": self.susfs_commit,
            "use_zram": self.use_zram,
            "use_kpm": self.use_kpm,
            "use_bbg": self.use_bbg,
            "support_op8e": self.support_op8e,
            "set_default_bbr": self.set_default_bbr,
            "make_release": self.make_release,
            "custom_version": self.custom_version,
            "revision": self.revision,
            "build_id": self.build_id,
        }


def validate_commit_hash(commit_hash: str) -> bool:
    return isinstance(commit_hash, str) and _FULL_LOWER_SHA_PATTERN.fullmatch(commit_hash) is not None
