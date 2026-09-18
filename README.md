# Android Framework Attack Surface Explorer (ASE)

Android 固件攻击面分析工具，分三个阶段工作：

1. **collector** — 通过 adb 从 Android 设备 dump 固件（APK/APEX/二进制/SELinux 策略/init 脚本等）
2. **java_analyzer** — 基于 JADX 解析 dump 出的固件，分析 Java 层导出组件权限和 AIDL 服务接口
3. **native_analyzer** — 扫描 .so 文件中的 Native AIDL 接口（descriptor 字符串 + Bn/Bp 符号 + service_list 交叉引用）

## 目录结构

```
.
├── collector/
│   └── collect.py                # adb 固件采集脚本
├── java_analyzer/
│   ├── analyzer.sh               # 启动脚本
│   ├── build.gradle.kts          # Gradle 构建（JADX 1.5.5 + shadow fat-jar）
│   └── src/main/java/net/wrlu/android/ase/
│       ├── AnalyzerMain.java          # CLI 入口
│       ├── workspace/Workspace.java
│       ├── jadx/JadxInstance.java      # JADX 封装
│       ├── components/                 # 组件权限分析
│       │   ├── ComponentAnalyzer.java
│       │   ├── ManifestParser.java
│       │   ├── Component.java
│       │   ├── PackageInfo.java
│       │   ├── DefinedPermission.java
│       │   ├── PathPermission.java
│       │   ├── IntentFilter.java
│       │   └── IntentData.java
│       └── aidl/                       # Java AIDL 接口搜索
│           ├── AidlSearcher.java
│           ├── AidlClass.java
│           ├── ClassSearch.java
│           └── IClassSearch.java
└── native_analyzer/
    └── native_analyzer.py        # Native AIDL 接口扫描脚本
```

## 环境要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | 3.8+ | collector, native_analyzer |
| adb | 1.0.41+ | collector（设备通信） |
| JDK | 21+ | java_analyzer |
| Gradle | 8.5+ | java_analyzer 构建（仓库自带 wrapper） |

Android 设备需已 root（`adb root` 或 `su`）。

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

## 阶段 2：Java 层分析（java_analyzer）

### 构建

```bash
cd java_analyzer
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
| `--aidl` | 仅运行 Java AIDL 接口搜索 |
| （默认） | 两个分析都运行 |

### JVM 内存

默认 `-Xmx4g`，可通过环境变量覆盖：

```bash
JAVA_OPTS="-Xmx8g" ./analyzer.sh <workspace_dir> --aidl
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

### 分析 2：Java AIDL 接口搜索（`--aidl`）

加载 `packages/android/` 目录下所有 framework jar/apk，识别 AIDL 接口（通过 Default + Stub + Stub.Proxy 三件套判定），搜索实现类并提取方法签名。

**输出文件：**

| 文件 | 说明 |
|------|------|
| `service_aidl.txt` | 每个 AIDL 接口一行头（`接口名 [实现类]`），后跟方法签名列表 |

**实现类搜索：** BFS 沿父类链向上查找直接或间接继承 `<Interface>$Stub` 的类，支持间接继承场景（如 `FooService extends BaseService extends IFoo.Stub`）。

## 阶段 3：Native AIDL 分析（native_analyzer）

### 用法

```bash
cd native_analyzer
python3 native_analyzer.py <workspace_dir>
```

无需构建，纯 Python 脚本，无外部依赖。

### 工作原理

扫描 workspace 下所有 `.so` 文件（`system/lib64`, `vendor/lib64`, `product/lib64`, `system_ext/lib64` 等），分三步识别 Native AIDL 接口：

**Step 1 — AIDL Descriptor 字符串扫描**

在 .so 二进制中搜索匹配 AIDL descriptor 模式的字符串：

```
模式: [a-z]+(.[A-Za-z_0-9]+)+.I[A-Z]\w*
示例: android.hardware.audio.core.IModule
      android.frameworks.stats.IStats
```

使用 lookbehind/ahead 防止匹配跨 null 边界的拼接字符串，自动剥离 `/instance` 后缀。

**Step 2 — Bn/Bp 符号检测**

对每个找到的 descriptor，检查同一 .so 中是否存在对应的 `Bn` / `Bp` 类（Itanium ABI mangled name 中的长度前缀编码）：

| 符号 | 含义 |
|------|------|
| `{len}Bn{Name}` | 服务端实现（Server Stub） |
| `{len}Bp{Name}` | 客户端引用（Client Proxy） |

例如 `android.hardware.audio.core.IBluetooth` → 检查 `9BnBluetooth` / `9BpBluetooth`。

**Step 3 — service_list.txt 交叉引用**

读取 `service_list.txt`，将扫描到的 descriptor 与已注册的 binder 服务匹配，标注哪些接口实际已注册运行。

### 输出文件

| 文件 | 说明 |
|------|------|
| `native_aidl.txt` | Native AIDL 接口清单，含注册状态、服务端/客户端 .so 路径 |

**输出格式：**

```
android.hardware.audio.core.IBluetooth [unregistered] [server]
  server: system/lib64/android.hardware.audio.core-V4-ndk.so
  client: system/lib64/android.hardware.audio.core-V4-ndk.so

android.frameworks.stats.IStats [registered] [server]
  server: system/lib64/android.frameworks.stats-V2-ndk.so
  client: system/lib64/android.frameworks.stats-V2-ndk.so
```

**标签说明：**

| 标签 | 含义 |
|------|------|
| `[registered]` | 在 service_list.txt 中找到，已注册为 binder 服务 |
| `[unregistered]` | 未在 service_list.txt 中找到 |
| `[server]` | .so 中存在 Bn 类（服务端实现） |
| `[client-only]` | .so 中仅存在 Bp 类（客户端引用） |
| `[reference]` | 仅找到 descriptor 字符串，无 Bn/Bp |

## 完整流程示例

```bash
# 1. 采集固件
cd collector
python3 collect.py -o ~/firmware/pixel8

# 2. Java 层分析
cd ../java_analyzer
./gradlew shadowJar
./analyzer.sh ~/firmware/pixel8

# 3. Native AIDL 分析
cd ../native_analyzer
python3 native_analyzer.py ~/firmware/pixel8
```

## 性能参考

以 Pixel 8 (shiba, Android 17) 固件为例（254 个包，826 个 .so，144MB framework）：

| 分析项 | 耗时 |
|--------|------|
| 组件分析 | ~2 分钟 |
| Java AIDL 搜索 | ~10 秒 |
| Native AIDL 扫描 | ~3 秒 |

## 输出目录结构（分析后）

```
<workspace>/
├── packages/              # 采集的 APK
├── system/lib64/          # 采集的 .so
├── vendor/lib64/
├── ...
├── all_comp.json          # ← 组件分析输出
├── accessible_comp.json   # ← 组件分析输出
├── service_aidl.txt       # ← Java AIDL 分析输出
└── native_aidl.txt        # ← Native AIDL 分析输出
```
