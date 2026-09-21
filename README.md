# Android Framework Attack Surface Explorer (ASE)

Android 固件攻击面分析工具，分四个阶段工作：

1. **collector** — 通过 adb 从 Android 设备 dump 固件（APK/APEX/二进制/SELinux 策略/init 脚本等）
2. **java_analyzer** — 基于 JADX 解析 dump 出的固件，分析 Java 层导出组件权限和 AIDL 服务接口
3. **native_analyzer** — 扫描 .so 文件中的 Native AIDL 接口（descriptor 字符串 + Bn/Bp 符号 + service_list 交叉引用）
4. **AttackSurfaceExplorer** — 设备端 APK，通过导出的 ContentProvider 让宿主（adb）实际探测 binder 服务能否被获取

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
└── AttackSurfaceExplorer/        # 设备端 Binder 探测 APK
    └── app/src/main/java/net/wrlu/ase/
        ├── MainActivity.java
        ├── binder/
        │   ├── ServiceManager.java       # getService / listServices（HiddenApiBypass）
        │   └── BinderInterface.java
        └── probe/
            ├── BinderProber.java         # 事务探测逻辑
            └── BinderProbeProvider.java  # 导出 ContentProvider
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
| `--ase-apk` | 用于安装的 AttackSurfaceExplorer APK 路径（每次采集都会重新安装，默认 `../AttackSurfaceExplorer/app/build/outputs/apk/debug/app-debug.apk`） |
| `--probe-only` | 仅运行 binder 探测流程，生成 `accessible_services.txt`，不 dump 固件 |
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
| 元数据 | `getprop.txt`, `lshal.txt`, `service_list.txt`, `accessible_services.txt`, `netstat.txt`, `settings_*.txt` |

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
| `service_aidl.txt` | 每个 AIDL 接口一行头（`接口名 [实现类]`），后跟方法签名列表；存在 `accessible_services.txt` 时头部追加 `[accessible=1\|0\|unknown]` |
| `accessible_service_aidl.txt` | 仅 `accessible=1` 的接口子集，格式与 `service_aidl.txt` 一致但不含 `[accessible=...]` 标记 |

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

读取 `service_list.txt`，仅保留已注册的 descriptor（默认行为）。`--ignore-registered` 可输出全部 server 接口。

### 输出文件

| 文件 | 说明 |
|------|------|
| `native_aidl.txt` | Native AIDL server 接口清单：`descriptor [so_path]`，多个 .so 以逗号分隔；存在 `accessible_services.txt` 时追加 `[accessible=1\|0\|unknown]` |
| `accessible_native_aidl.txt` | 仅 `accessible=1` 的 server 接口子集，格式与 `native_aidl.txt` 一致但不含 `[accessible=...]` 标记 |

**输出格式：**

```
android.gui.ISurfaceComposer [system/lib64/libandroid_gui.dylib.so] [accessible=1]
android.system.keystore2.IKeystoreService [system/lib64/android.system.keystore2-V6-ndk.so] [accessible=1]
```

若工作目录存在 `accessible_services.txt`（阶段 4 的实机探测结果），`native_aidl.txt` 保留 `[accessible=...]` 标记，并另行生成 `accessible_native_aidl.txt`（仅 `accessible=1`，无标记）。

## 阶段 4：设备端 Binder 探测（AttackSurfaceExplorer APK）

静态分析只能判断接口"存在"，无法判断在真实设备上**以当前身份能否拿到 binder 句柄**。AttackSurfaceExplorer 是一个安装到设备上的 APK，内部通过 `android.os.ServiceManager` 获取 binder，并以 **APK 自身的 uid/权限** 解析服务。宿主通过 adb 调用其导出的 ContentProvider（标准 `query` 接口）进行自动化探测。

> 只探测服务能否获取到 `IBinder`（是否可取到且存活），**不会读取 descriptor，更不会调用具体的 AIDL 接口方法**。

### 构建与安装

```bash
cd AttackSurfaceExplorer
./gradlew :app:assembleDebug
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

### 使用方式

`accessible_services.txt` 由 **collector 采集阶段自动生成**：collector 每次都重新安装 ASE APK（默认路径 `../AttackSurfaceExplorer/app/build/outputs/apk/debug/app-debug.apk`，可用 `--ase-apk` 指定），随后通过 provider 探测。

```bash
# 先构建 ASE APK
cd AttackSurfaceExplorer
./gradlew :app:assembleDebug

# 再采集（重新安装 APK + 生成 accessible_services.txt）
cd ../collector
python3 collect.py -o ~/firmware/pixel8
# 生成 ~/firmware/pixel8/accessible_services.txt
```

若 APK 不存在或 provider 不可用，会打印 warning 并跳过，分析器退化为无校验模式。

若已有固件 dump，只想单独生成/刷新探测文件（不重新 dump）：

```bash
cd collector
python3 collect.py -o ~/firmware/pixel8 --probe-only
```

也可手动触发单次探测（服务名通过 `--where` 传入，不传则遍历全部）：

```bash
# 探测全部服务
adb shell content query --uri content://net.wrlu.ase.probe

# 只探测单个服务
adb shell content query --uri content://net.wrlu.ase.probe --where "activity"
```

### Provider 接口

Provider 不使用 URI endpoint，URI 固定为 `content://net.wrlu.ase.probe`：

| 调用 | 行为 |
|------|------|
| 不传参数（`selection`/`selectionArgs` 均为空） | 枚举 `listServices()` 并逐个测试 |
| 传入服务名（`selectionArgs[0]` 或 `selection`） | 只测试该服务 |

**返回列：** `service, accessible`

| 列 | 含义 |
|----|------|
| `service` | 服务名 |
| `accessible` | `1` = 取到 `IBinder` 且存活；`0` = 取不到（未注册或无权获取） |

> `content query` 输出每行的 `Row: N` 前缀是 `content` 命令行工具自行添加的行号，不是 Provider 返回的列。

### 与分析流程的整合

`accessible_services.txt` 是分析器的**额外输入**：

- `service_list.txt`（`service list`）静态声明哪些服务已注册，并提供 `服务名 → descriptor` 映射；
- `accessible_services.txt`（ASE 实机探测）确认以 APK 身份能否真正拿到 `IBinder`。

两个分析器在按 `service_list.txt` 做 registered 过滤生成原有输出文件（`native_aidl.txt` / `service_aidl.txt`，保留 `[accessible=...]` 标记）的同时，若工作目录存在 `accessible_services.txt`，会把服务名映射回 descriptor，**另行生成** accessible 子集文件：

| 分析器 | 原文件（含标记） | 新增 accessible 文件（无标记） |
|--------|-----------------|-------------------------------|
| java_analyzer | `service_aidl.txt` | `accessible_service_aidl.txt` |
| native_analyzer | `native_aidl.txt` | `accessible_native_aidl.txt` |

accessible 文件只包含探测为 `accessible=1` 的接口，格式与原文件一致但不带标记；日志输出 `accessible / not_accessible / unknown` 汇总。未提供 `accessible_services.txt` 时原文件不带标记、也不生成 accessible 文件。

> 安全提示：`BinderProbeProvider` 虽为 `exported="true"`，但内部通过 `Binder.getCallingUid()` 校验，仅允许本应用自身、system（uid 1000）、adb shell（uid 2000）与 root（uid 0）调用，普通应用会被拒绝。

## 完整流程示例

```bash
# 0. 构建 ASE APK（collector 会自动安装）
cd AttackSurfaceExplorer
./gradlew :app:assembleDebug

# 1. 采集固件（自动安装 APK，生成 service_list.txt + accessible_services.txt）
cd ../collector
python3 collect.py -o ~/firmware/pixel8

# 2. Java 层分析（生成 service_aidl.txt 与 accessible_service_aidl.txt）
cd ../java_analyzer
./gradlew shadowJar
./analyzer.sh ~/firmware/pixel8

# 3. Native AIDL 分析（生成 native_aidl.txt 与 accessible_native_aidl.txt）
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
├── service_list.txt              # ← collector 采集
├── accessible_services.txt       # ← ASE 实机探测结果（可选）
├── all_comp.json                 # ← 组件分析输出
├── accessible_comp.json          # ← 组件分析输出
├── service_aidl.txt              # ← Java AIDL 分析输出
├── accessible_service_aidl.txt   # ← Java AIDL accessible 子集（可选）
├── native_aidl.txt               # ← Native AIDL 分析输出
└── accessible_native_aidl.txt    # ← Native AIDL accessible 子集（可选）
```
