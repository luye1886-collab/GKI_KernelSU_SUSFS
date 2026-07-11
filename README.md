# GKI SukiSU-Ultra + SUSFS 构建系统

### 这是一个自动构建 GKI 内核的仓库

> 不支持一加 ColorOS14、15 和非 GKI 

> 第一次使用务必 **详细阅读** 以下内容，不要因为懒惰而占用他人时间！

> 使用 Python 辅助构建系统，支持指定 SukiSU-Ultra/SUSFS commit 版本构建


---

## 快速开始

### GitHub Actions

#### 方式一：构建单个版本
1. 进入 **Actions** 页面
2. 选择 **Kernel Build**
3. 点击 **Run workflow**
4. 选择 Android 版本、Kernel 版本和构建选项
5. 可选：指定 SukiSU-Ultra 或 SUSFS 的完整 40 位小写十六进制 commit

#### 方式二：构建所有版本
1. 选择 **Build Kernels**
2. 点击 **Run workflow**
3. 设置全局选项（KSU 版本、ZRAM、KPM 等）
4. 可选：指定完整 40 位小写十六进制 commit

### 命令行本地构建

```bash
# 进入构建目录
cd .github/workflows/scripts

# 安装依赖
pip install PyYAML

# 构建单个版本
python build.py --android android14 --kernel 6.1 --sub-level 124 --os-patch 2025-02

# 构建整个矩阵
python build.py --matrix android14-6.1

# 构建所有版本
python build.py --all

# 指定完整 commit 版本
python build.py --all --ksu-commit 278d822a4ebd214bcfd774b7910cb11cdc560bb9 --susfs-commit 81f01bc58d055687a6276114c1371b8ac09e8b26

# 列出所有支持的配置
python build.py --list-configs

# 列出预定义构建矩阵
python build.py --list-matrix
```

未显式指定 `--ksu-commit` 或 `--susfs-commit` 时，默认使用 `.github/workflows/config/dependencies.lock.json` 中的锁定值。显式覆盖仅接受完整 40 位小写十六进制 commit，不接受短 SHA、分支名或相对引用。

## Mayfly 安全 GKI 构建

Mayfly 使用独立的 `.github/workflows/mayfly-gki-build.yml` 和 `build_mayfly.py`。该路径必须显式选择固定源与分层 profile，不调用通用 `build.py`，也不执行第三方 `setup.sh`。

固定源：

- `stock-5.10.226`：Mayfly 原厂基线，预期 release 前缀为 `5.10.226-android12-9`。
- `security-5.10.236-r1`：冻结在 `android12-5.10-2025-05_r1` tag 和 `b97c62c4e7d1e80fb6a2cb0cb381f03bbcd26a4e` 的安全基线，预期 release 前缀为 `5.10.236-android12-9`。

锁文件中的 `fbb4c9b0aa2909575b240a5404b6a3eaa1d2755d` 是 2026-05 branch head，仅保留用于审计并标记为实验项，Mayfly 专用 builder 不会选择或克隆它。

完整构建树在 sync 前由固定 superproject gitlinks 锁定：builder 先核验对应 superproject 快照，再把 manifest 中每个 project 改写为精确 commit，并使用 `--no-manifest-update` 同步。`resolved-manifest.xml` 是同步后的逐项复核产物，不是事后才决定源码版本的依据。

git-repo 同样从锁定 commit 准备，并在 repo init 前执行版本自检；输出必须包含 repo launcher `2.15`，否则立即停止。

SukiSU v4.1.3 与 SUSFS v2.2.0 通过本地 `sukisu-v4.1.3-susfs-v2.2.0-compat.patch` 适配。该补丁保留 SukiSU 的命令行提权入口、符号解析器和仅限 root 调用的 UTS 版本伪装接口；构建不写入默认伪装值。

SUSFS 的 SUS_PATH、SUS_MOUNT、SUS_KSTAT、OPEN_REDIRECT、SUS_MAP 和符号隐藏能力会编译启用。两个锁定的 Android 12 5.10 基线在 `fs/proc/task_mmu.c` 中都与 SUSFS v2.2.0 上游 hunk 存在上下文差异，因此先排除该 hunk，再严格应用已在两条基线上验证的 `mayfly-android12-5.10-susfs-task-mmu.patch`。SUSFS 的全局 uname、bootconfig/cmdline 伪装和内核日志仍关闭，且不提供针对第三方 App 的规则。

锁定的 `SukiSU_patch/69_hide_stuff.patch` 会先按 Git blob 的规范 LF 字节大小与 SHA256 审计，再由 `mayfly-android12-5.10-69-hide-stuff.patch` 在上述 task_mmu 基线上应用相同语义。它会改变特定映射在 `/proc` 中的呈现，属于兼容/隐藏能力而不是安全修复，可能降低诊断可见性；所有 profile 均会编译该能力，但本仓库不提供面向第三方 App 的额外规则或认证伪造配置。

补丁应用仍采用最小排除策略：LZ4KD 补丁中的 `kernel/module.c` 会放宽模块版本校验并改写模块黑名单，因此不合入。该排除会写入 `BUILD_INFO.json`，供产物审计。

分层 profile：

- `root`：KSU、SUSFS core 与上述隐藏能力。
- `root-kpm`：`root` 加 KPM。
- `balanced`：`root-kpm` 加 LZ4KD/ZRAM 与默认 BBR。
- `balanced-bbg`：`balanced` 加 Baseband Guard，启动与 recovery 拦截保持关闭。

Mayfly 原厂系统通过 `vendor_dlkm` 模块提供约 6 GiB ZRAM。`balanced` 内置 LZ4KD/ZRAM 后可能与原厂 `zram.ko`、`zsmalloc.ko` 的加载顺序或配置冲突，因此不能作为首个测试层；临时启动后必须检查模块加载、Swap 容量、LMKD、休眠唤醒、功耗和内存压力，再决定是否继续使用。

先执行只读预演；`--dry-run` 只核验锁定值并输出 JSON，不创建 workspace 或产物目录：

```bash
python .github/workflows/scripts/build_mayfly.py \
  --source stock-5.10.226 \
  --profile root \
  --workspace /tmp/mayfly-gki \
  --artifacts artifacts \
  --dry-run
```

该专用路径只发布 raw `Image` 及验证元数据，不生成 `boot.img`、不签名 AVB、不制作 AnyKernel 包，也不执行刷写。原始 `69_hide_stuff.patch`、设备专用重基补丁和各自 SHA256 会记录在 `BUILD_INFO.json`，供产物审计。

---

## 构建矩阵

从 `matrix.json` 加载：

| Android | Kernel | Sub Levels | OS Patch |
|---------|--------|------------|----------|
| 12 | 5.10 | 136, 198, 209, 236, X (LTS) | 2022-11 ~ 2025-05 |
| 13 | 5.15 | 74, 123, 148, 170, 178, 180 | 2023-01 ~ 2025-05 |
| 14 | 6.1 | 78, 90, 99, 124, 145 | 2024-06 ~ 2025-09 |
| 15 | 6.6 | 50, 66, 102 | 2024-10 ~ 2025-10 |

总计 **19 个版本组合**

---

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--android`, `-a` | Android 版本 (android12/13/14/15) | android14 |
| `--kernel`, `-k` | Kernel 版本 (5.10/5.15/6.1/6.6) | 6.1 |
| `--sub-level`, `-s` | Sub level 版本或 X (LTS) | 124 |
| `--os-patch` | OS Patch Level | 2025-02 |
| `--revision` | Android 12 Revision | - |
| `--ksu-version` | SukiSU-Ultra 版本 (Stable/Dev) | Stable(标准) |
| `--ksu-commit` | 指定完整 40 位小写十六进制 SukiSU-Ultra commit | dependencies.lock.json |
| `--susfs-commit` | 指定完整 40 位小写十六进制 SUSFS commit | dependencies.lock.json |
| `--zram` | 启用 ZRAM (LZ4KD) | False |
| `--no-kpm` | 禁用 KPM | False |
| `--bbg` | 启用 Baseband-guard | False |
| `--op8e` | 启用 OnePlus 8E 支持 | False |
| `--bbr` | 设置 BBR 为默认拥塞算法 | False |
| `--no-release` | 不创建 GitHub Release | False |
| `--custom-version` | 自定义版本名称 | - |
| `--matrix`, `-m` | 使用预定义矩阵 | - |
| `--all` | 构建所有配置 | - |
| `--list-configs` | 列出所有支持的配置 | - |
| `--list-matrix` | 列出所有预定义矩阵 | - |
| `--dry-run` | 仅验证配置 | - |
| `--workspace`, `-w` | 工作目录 | /tmp/gki-build |

---

## 下载

1. **AnyKernel3.zip** - 下载即用！
   - 使用刷入软件，例如 [HorizonKernelFlasher](https://github.com/libxzr/HorizonKernelFlasher/releases) 进行刷写内核

2. **boot.img** - 下载与你内核格式相匹配的（无压缩、gz、lz4）
   - 使用 [Fastboot](https://magiskcn.com/) 刷入

---

## 支持的功能

| 功能 | 说明 |
|------|------|
| [KernelSU](https://kernelsu.org/zh_CN/) | SukiSU 内核Root方案 |
| [SUSFS4](https://gitlab.com/simonpunk/susfs4ksu) | 内核层面辅助 KSU 隐藏的功能补丁 |
| [BBR](https://blog.thinkin.top/archives/ke-pu-bbrdao-di-shi-shi-me) | TCP 拥塞控制算法 |
| [LZ4KD](https://github.com/ShirkNeko/SukiSU_patch/tree/main/other) | 来自华为源码的 ZRAM 算法 |
| [KPM](https://github.com/bmax121/KernelPatch) | 内核模块支持 |
| [Baseband-guard](https://github.com/vc-teahouse/Baseband-guard) | 基带安全防护 |

<details>

<summary>支持的 ZRAM 算法（可在 Scene 切换）</summary>

LZ4K、LZ4HC、deflate、842、lz4k_oplus

</details>

---

## KSU 管理器

在编译完成后，会生成最新的管理器 APK。

---

## 紧急救援指南

> **触发条件**
> 当设备因刷入错误/不兼容的内核无法启动时需执行救援

1. 进入 Fastboot 模式
   - 物理键组合：电源+音量-
   - 或 ADB 命令：`adb reboot bootloader`

2. 执行刷写命令
```bash
fastboot flash boot <boot.img文件全称>
```

---

## 内核版本兼容性说明

### 1. 跨子版本刷机规则

当手机 GKI 主版本为 5.10.x 时（如 5.10.168），可刷写同主版本更高子版本的内核（如 5.10.198）。

关于 **X-lts** 版本，以 `android12-5.10.X-lts-AnyKernel3.zip` 为例：
- **X-lts** 表示长期支持版（子版本号最大，当前示例为 5.10.236）
- LTS 随着 GKI 源码更新，编译版本号将持续递增
- ⚠️ 注意：LTS 虽为最新，但最新版 ≠ 最稳定（如 6.6.x 存在自动重启 BUG）

### 2. 内核版本伪装方法

在 MT 管理器终端执行：
```bash
uname -r | sed 's/^[^-]*//'
```
获取后复制版本号，填入 Action 编译面板即可实现内核版本伪装。

### 3. 定制构建矩阵

编辑 `.github/workflows/config/matrix.json` 添加或修改构建版本：
```json
{
  "android14-6.1": [
    {"sub_level": "124", "os_patch_level": "2025-02"},
    {"sub_level": "145", "os_patch_level": "2025-09"}
  ]
}
```

---

## 构建系统架构

```
.github/workflows/
├── config/
│   ├── dependencies.lock.json # 依赖仓库锁定版本
│   └── matrix.json            # 构建矩阵配置
├── patches/
│   ├── mayfly-android12-5.10-69-hide-stuff.patch  # 69_hide_stuff 的 Mayfly 重基补丁
│   ├── mayfly-android12-5.10-susfs-task-mmu.patch # SUSFS task_mmu 的 Mayfly 适配
│   └── sukisu-v4.1.3-susfs-v2.2.0-compat.patch  # Mayfly SukiSU/SUSFS 兼容补丁
├── scripts/
│   ├── build.py             # 主构建脚本（CLI 入口）
│   ├── build_mayfly.py      # Mayfly 专用 CLI 入口
│   ├── kernel_builder.py    # 内核构建核心类
│   ├── mayfly_builder.py    # Mayfly 失败即停构建核心
│   ├── config.py            # 配置定义和验证
│   ├── matrix_generator.py  # GitHub Actions 矩阵生成
│   ├── release_generator.py # Release 说明生成
│   └── cache_manager.py     # 构建缓存管理
├── mayfly-gki-build.yml     # Mayfly raw Image 专用工作流
├── kernel-build.yml         # 单版本构建工作流
└── build-kernels.yml        # 全量构建工作流
```

### 核心组件

| 组件 | 功能 |
|------|------|
| `KernelBuilder` | 内核构建核心类，负责克隆源码、应用补丁、编译、打包 |
| `BuildConfig` | 构建配置数据类，包含所有构建参数 |
| `CacheManager` | 管理 ccache 和构建缓存，支持跨分支复用 |
| `matrix_generator.py` | 为 GitHub Actions 生成构建矩阵 |
| `release_generator.py` | 自动生成 Release 说明 |

### 仓库依赖

| 仓库 | 用途 |
|------|------|
| [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) |  SukiSU-Ultra 源码和安装脚本 |
| [susfs4ksu](https://github.com/ShirkNeko/susfs4ksu) | SUSFS 内核补丁 |
| [SukiSU_patch](https://github.com/ShirkNeko/SukiSU_patch) | SukiSU-Ultra 附加补丁（ZRAM 等） |
| [AnyKernel3](https://github.com/WildPlusKernel/AnyKernel3) | 通用刷机包模板 |
| [kernel_patches](https://github.com/Tools-cx-app/kernel_patches) | 内核补丁合集 |
| [Baseband-guard](https://github.com/vc-teahouse/Baseband-guard) | 基带安全防护 |

---

## 更多内容

可以提及您的意见...我会尝试！
