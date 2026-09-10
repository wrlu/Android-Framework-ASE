# Android Framework Attack Surface Explorer (ASE)

Android 固件攻击面分析工具，分两阶段工作：

1. **collector** — 通过 adb 从 Android 设备 dump 固件（APK/APEX/二进制/SELinux 策略/init 脚本等）
2. **analyzer** — 基于 JADX 解析 dump 出的固件，分析导出组件权限和 AIDL 服务接口

## 目录结构

```
.
├── collector/
│   └── collect.py            # adb 固件采集脚本
└── analyzer/
    ├── analyzer.sh           # 启动脚本
    ├── build.gradle.kts      # Gradle 构建（JADX 1.5.5 + shadow fat-jar）
    └── src/main/java/net/wrlu/android/ase/
        ├── AnalyzerMain.java       # CLI 入口
        ├── workspace/Workspace.java
        ├── jadx/JadxInstance.java   # JADX 封装
        ├── components/              # 组件权限分析
        │   ├── ComponentAnalyzer.java
        │   ├── ManifestParser.java
        │   ├── Component.java
        │   ├── PackageInfo.java
        │   ├── DefinedPermission.java
        │   ├── PathPermission.java
        │   ├── IntentFilter.java
        │   └── IntentData.java
        └── aidl/                    # AIDL 接口搜索
            ├── AidlSearcher.java
            ├── AidlClass.java
            ├── ClassSearch.java
            └── IClassSearch.java
```

## 环境要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | 3.8+ | collector |
| adb | 1.0.41+ | collector（设备通信） |
| JDK | 21+ | analyzer |
| Gradle | 8.5+ | analyzer 构建（仓库自带 wrapper） |

## 阶段 1：固件采集（collector）

### 用法

```bash
cd collector
python3 collect.py -o <output_dir> [-d <device_serial>] [-s | -3]
```

### 参数

| 参数 | 说明 |
|------|------|
| `-o, --output` | dump 输出目录（默认当前目录） |
| `-d, --device` | adb 设备 serial（非交互选择） |
| `-s, --system` | 仅 dump 系统包 |
| `-3, --third-party` | 仅 dump 第三方应用（跳过 apex/binaries/selinux） |

### 采集内容

| 任务 | 输出 |
|------|------|
| 包（APK） | `packages/<pkg>/`（逐文件 pull） |
| APEX | `apex/`（独立目录） |
| Overlay | `overlay/`（独立目录） |
| 二进制 | `system/bin`, `system/lib64`, `vendor/bin`, ... |
| init 脚本 | `init/`（符号链接到各分区 etc/） |
| SELinux 策略 | `selinux/policy`（直接 pull）+ 各分区 etc/ 符号链接 |
| 权限策略 | `permissions/`（符号链接到各分区 etc/） |
| 元数据 | `getprop.txt`, `lshal.txt`, `service_list.txt`, `netstat.txt`, `settings_*.txt` |

## 阶段 2：攻击面分析（analyzer）

### 构建

```bash
cd analyzer
./gradlew shadowJar
# 产物: build/libs/analyzer-1.0.0-all.jar (~25MB)
```

### 用法

```bash
./analyzer.sh <workspace_dir> [--components] [--aidl]
```

| 参数 | 说明 |
|------|------|
| `<workspace_dir>` | 阶段 1 的 dump 目录（含 `packages/` 等） |
| `--components` | 仅运行组件权限分析 |
| `--aidl` | 仅运行 AIDL 接口搜索 |
| （默认） | 两个分析都运行 |

### JVM 内存

默认 `-Xmx32g`，可通过环境变量覆盖：

```bash
JAVA_OPTS="-Xmx64g" ./analyzer.sh <workspace_dir> --aidl
```

### 分析 1：组件权限分析（`--components`）

扫描 `packages/` 下所有 APK，通过 JADX 解码 AndroidManifest.xml，识别导出的 activity / service / provider / receiver，检查其权限保护级别。

**输出文件：**

| 文件 | 说明 |
|------|------|
| `all_comp.json` | 全量组件清单（含包名、组件、定义权限、声明权限、protected-broadcast） |
| `accessible_comp.json` | 可访问组件问题清单，按问题类型分桶：`undefined_permissions`（权限未定义）/ `unprivileged_permissions`（权限保护级别不足） |

**权限保护级别判定**（`PROTECTION_FLAG`）：

| 名称 | 值 | 视为 privileged |
|------|----|----|
| `signature` | 0x2 | ✅ |
| `system` | 0x10 | ✅ |
| `privileged` / `priv` | 0x20 | ✅ |
| `internal` | 0x40 | ✅ |
| `preinstalled` | 0x4000 | ✅ |
| `normal` | 0 | ❌ |
| `dangerous` | 0x1 | ❌ |

支持组合名（`signature|privileged`）和十进制/十六进制整数字符串。

**Deeplink 提取：** 导出且带 `android.intent.category.BROWSABLE` 的 activity，其 `intentFilters` 字段含 actions / categories / data（scheme, host, port, path, pathPrefix, pathPattern, mimeType）。

### 分析 2：AIDL 接口搜索（`--aidl`）

加载 `packages/android/` 目录下所有 framework jar/apk，识别 AIDL 接口（通过 Default + Stub + Stub.Proxy 三件套判定），搜索实现类并提取方法签名。

**输出文件：**

| 文件 | 说明 |
|------|------|
| `service_aidl.txt` | 每个 AIDL 接口一行头（`接口名 [实现类]`），后跟方法签名列表 |

**实现类搜索：** BFS 沿父类链向上查找直接或间接继承 `<Interface>$Stub` 的类，支持间接继承场景（如 `FooService extends BaseService extends IFoo.Stub`）。

## 完整流程示例

```bash
# 1. 采集固件
cd collector
python3 collect.py -o ~/firmware/pixel8

# 2. 构建分析器
cd ../analyzer
./gradlew shadowJar

# 3. 全量分析
./analyzer.sh ~/firmware/pixel8

# 或分别运行
./analyzer.sh ~/firmware/pixel8 --components
./analyzer.sh ~/firmware/pixel8 --aidl
```

## 输出目录结构（分析后）

```
<workspace>/
├── packages/              # 采集的 APK
├── apex/
├── ...
├── all_comp.json          # ← 组件分析输出
├── accessible_comp.json   # ← 组件分析输出
└── service_aidl.txt       # ← AIDL 分析输出
```
