# Android Framework Attack Surface Explorer (ASE)

Android 固件攻击面分析工具，覆盖「固件采集 → 静态分析 → 实机验证」完整链路：

- **collector** — 通过 adb dump 固件（APK / APEX / 二进制 / SELinux / init 等）与运行元数据
- **java_analyzer** — 基于 JADX 分析 Java 层导出组件权限与 AIDL 接口
- **native_analyzer** — 扫描 .so 中的 Native AIDL 接口
- **AttackSurfaceExplorer** — 设备端 APK，实机探测 binder 服务能否被获取

## 目录结构

```
.
├── collector/
│   └── collect.py                 # 固件采集
├── java_analyzer/
│   ├── analyzer.sh                # 启动脚本
│   └── src/main/java/net/wrlu/android/ase/
│       ├── AnalyzerMain.java      # CLI 入口
│       ├── components/            # 组件权限分析
│       ├── aidl/                  # Java AIDL 接口搜索
│       ├── jadx/                  # JADX 封装
│       └── workspace/
├── native_analyzer/
│   └── native_analyzer.py         # Native AIDL 扫描
└── AttackSurfaceExplorer/         # 设备端 Binder 探测与动态执行 APK
    ├── runner.py                  # 主机端动态脚本编译与执行工具
    ├── sample_scripts/            # 验证脚本示例
    └── app/src/main/java/net/wrlu/ase/
        ├── binder/                # ServiceManager（HiddenApiBypass）
        ├── data/                  # 通用 DataProvider & Handlers
        ├── probe/                 # BinderProber
        └── script/                # 动态执行前台服务（:runner 独立进程）
```

## 环境要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | 3.8+ | collector、native_analyzer |
| adb | 1.0.41+ | collector |
| JDK | 21+ | java_analyzer |
| Gradle | 8.5+ | java_analyzer（仓库自带 wrapper） |

## 阶段 1：固件采集（collector）

```bash
cd collector
python3 collect.py -o <output_dir> [-d <device_serial>] [-s | -3]
```

| 参数 | 说明 |
|------|------|
| `-o, --output` | 输出目录（默认当前目录） |
| `-d, --device` | adb 设备 serial（非交互选择） |
| `--ase-apk` | 探测用 AttackSurfaceExplorer APK 路径（默认 `../AttackSurfaceExplorer/app/build/outputs/apk/release/app-release.apk`） |
| `--probe-only` | 仅安装 APK 并生成 `accessible_services.txt`，不 dump 固件 |
| `-s, --system` | 仅 dump 系统包 |
| `-3, --third-party` | 仅 dump 第三方应用（跳过 apex/binaries/selinux） |

采集内容：

| 内容 | 输出 |
|------|------|
| 包（APK） | `packages/<pkg>/` |
| APEX / Overlay | `apex/`、`overlay/` |
| 二进制 | 各分区的 `bin` / `lib(64)` / `etc` |
| init 脚本 | `init/`（链接到各分区 `etc/init`） |
| SELinux / 权限策略 | `selinux/`、`permissions/` |
| 运行元数据 | `getprop.txt`、`lshal.txt`、`service_list.txt`、`accessible_services.txt`、`netstat.txt`、`settings_*.txt` |

`accessible_services.txt` 由 ASE APK 实机探测生成（服务名 → 是否可取到 `IBinder`）：

```
Row: 0 service=DockObserver, accessible=0
Row: 1 service=SurfaceFlinger, accessible=1
Row: 2 service=SurfaceFlingerAIDL, accessible=1
```

在已有 dump 上可用 `--probe-only` 只刷新该文件；APK 缺失或 provider 不可用时会跳过，不影响其余采集。

## 阶段 2：Java 层分析（java_analyzer）

```bash
cd java_analyzer
./gradlew shadowJar      # 产物 build/libs/analyzer-1.0.0-all.jar
./analyzer.sh <workspace_dir> [--components] [--aidl] [--ignore-registered]
```

| 参数 | 说明 |
|------|------|
| `<workspace_dir>` | 阶段 1 的 dump 目录 |
| `--components` | 仅运行组件权限分析 |
| `--aidl` | 仅运行 Java AIDL 接口搜索 |
| `--ignore-registered` | 不按 `service_list.txt` 过滤，输出全部 AIDL 接口 |
| （默认） | 两个分析都运行 |

JVM 默认 `-XX:MaxRAMPercentage=50.0`（分配当前设备内存的 50%），可用 `JAVA_OPTS` 覆盖：`JAVA_OPTS="-Xmx8g" ./analyzer.sh ...`

### 组件权限分析

扫描 `packages/` 下的 APK，解码 AndroidManifest.xml，识别导出的 activity / service / provider / receiver 及其权限保护级别。

| 输出 | 说明 |
|------|------|
| `all_comp.json` | 全量组件清单（包名、组件、定义权限、声明权限、protected-broadcast）；APK 路径为相对 workspace root 的相对路径 |
| `accessible_comp.json` | 问题组件清单，按组件类型（activity / service / provider / receiver）分组，每条含 `type` 字段标记 `undefined`（权限未定义）或 `unprivileged`（保护级别不足） |

```json
# all_comp.json
{
  "package": "com.example.app",
  "filename": "packages/com.example.app/base.apk",
  "components": [
    { "name": "com.example.app.MainActivity", "type": "activity", "permission": "" },
    { "name": "com.example.app.DataProvider", "type": "provider", "permission": "com.example.app.READ_DATA" }
  ],
  "defined_permissions": [
    { "name": "com.example.app.READ_DATA", "protectionLevel": "normal" }
  ],
  "uses_permissions": ["android.permission.INTERNET"],
  "protected_broadcasts": []
}

# accessible_comp.json
{
  "activity": [
    { "type": "unprivileged", "name": "com.example.app/.MainActivity", "permission": "" }
  ],
  "provider": [
    { "type": "undefined", "name": "com.example.app/.DataProvider", "writePermission": "",
      "readPermission": "", "permission": "com.example.app.READ_DATA", "path_permission": [] }
  ],
  "service": [],
  "receiver": []
}
```

保护级别判定（`PROTECTION_FLAG`）：`signature`(0x2)、`system`(0x10)、`privileged`(0x20)、`internal`(0x40)、`preinstalled`(0x4000) 视为 privileged；`normal`(0)、`dangerous`(0x1) 不予保护。支持组合名（`signature|privileged`）与十进制/十六进制整数。

导出且带 `BROWSABLE` 的 activity 会额外提取 deeplink（actions / categories / data：scheme、host、port、path、pathPrefix、pathPattern、mimeType）。

### Java AIDL 接口搜索

加载 `packages/android/` 下的 framework jar/apk，识别 AIDL 接口（Default + Stub + Stub.Proxy 三件套），沿父类链 BFS 查找实现类并提取方法签名，支持间接继承。

| 输出 | 说明 |
|------|------|
| `service_aidl.txt` | 每个接口一行 `接口名 [实现类]`，后跟方法签名；存在 `accessible_services.txt` 时头部追加 `[accessible=1\|0\|unknown]` |
| `accessible_service_aidl.txt` | 仅 `accessible=1` 的接口子集（无标记，存在 `accessible_services.txt` 时生成） |

```
# service_aidl.txt
android.app.ILocaleManager [com.android.server.locales.LocaleManagerService.LocaleManagerBinderService] [accessible=1]
android.os.IRecoverySystem [com.android.server.recoverysystem.RecoverySystemService] [accessible=0]

# accessible_service_aidl.txt
android.app.ILocaleManager [com.android.server.locales.LocaleManagerService.LocaleManagerBinderService]
android.app.ILocaleManager.getApplicationLocales(java.lang.String, int):android.os.LocaleList
```

`accessible_services.txt` 以服务名记录，分析时通过 `service_list.txt` 的 `服务名 → descriptor` 映射回 AIDL 接口。

## 阶段 3：Native AIDL 分析（native_analyzer）

```bash
cd native_analyzer
python3 native_analyzer.py <workspace_dir> [--ignore-registered]
```

无需构建、无外部依赖。扫描各分区 `lib(64)` 下的 `.so` 与 `bin` 下的 ELF：

1. **Descriptor 字符串** — 匹配 AIDL 名称模式（如 `android.frameworks.stats.IStats`），兼容 C++ 与 Rust v0 mangling；
2. **Bn/Bp 符号** — 按 `{len}Bn{Name}` / `{len}Bp{Name}` 判定服务端 / 客户端实现；
3. **service_list 交叉引用** — 默认仅保留已注册 descriptor，`--ignore-registered` 输出全部 server 接口。

| 输出 | 说明 |
|------|------|
| `native_aidl.txt` | `descriptor [so_path]`，多个 .so 以逗号分隔；存在 `accessible_services.txt` 时追加 `[accessible=1\|0\|unknown]` |
| `accessible_native_aidl.txt` | 仅 `accessible=1` 的 server 子集（无标记，存在 `accessible_services.txt` 时生成） |

```
# native_aidl.txt
android.gui.ISurfaceComposer [system/lib64/libandroid_gui.dylib.so] [accessible=1]
android.app.IActivityManagerStructured [system/lib64/libactivitymanager_structured_aidl.dylib.so] [accessible=0]

# accessible_native_aidl.txt
android.gui.ISurfaceComposer [system/lib64/libandroid_gui.dylib.so]
android.system.keystore2.IKeystoreService [system/lib64/android.system.keystore2-V6-ndk.so]
```

## 阶段 4：设备端 Binder 探测（AttackSurfaceExplorer）

静态分析只能判断接口存在，无法判断实机上能否真正拿到 binder 句柄。AttackSurfaceExplorer 以 **APK 自身 uid/权限** 通过 `android.os.ServiceManager` 获取服务，仅探测能否取到 `IBinder`——不读取 descriptor，也不调用 AIDL 方法。

APK 使用内置的 `ase-release.jks` 做 release 签名（匿名化信息）。collector 会自动编译并安装，也可手动操作：

```bash
cd AttackSurfaceExplorer
./gradlew :app:assembleRelease
adb install -r -g app/build/outputs/apk/release/app-release.apk
```

通过导出的通用 DataProvider 探测（当前端点 URI 为 `content://net.wrlu.ase.probe/binder_service`）：

```bash
# 全部服务
adb shell content query --uri content://net.wrlu.ase.probe/binder_service

# 单个服务（--where 传服务名）
adb shell content query --uri content://net.wrlu.ase.probe/binder_service --where "activity"
```

输出示例：

```
Row: 0 service=DockObserver, accessible=0
Row: 1 service=SurfaceFlinger, accessible=1
Row: 2 service=SurfaceFlingerAIDL, accessible=1
```

| 调用 | 行为 |
|------|------|
| 不传 | 枚举全部服务并逐个测试 |
| 传服务名 | 仅测试该服务 |

| 返回列 | 含义 |
|--------|------|
| `service` | 服务名 |
| `accessible` | `1` = 取到 `IBinder` 且存活；`0` = 取不到（未注册或无权获取） |

Provider 通过 `Binder.getCallingUid()` 限制调用方：仅本应用、system(1000)、adb shell(2000) 与 root(0) 可用。

### 动态脚本自主验证（runner.py）

针对深度攻击面探测与 AI 自主代码验证需求，AttackSurfaceExplorer 提供了**动态 DEX 加载与前台服务执行**能力。

#### 1. 背景与设计优势

传统实机验证通常需要开发独立测试 APK 并执行 `adb install`。在各类 OEM 设备（小米 MIUI/HyperOS、OPPO ColorOS、vivo OriginOS、华为 HarmonyOS 等）及受控 Android 14/15/17 设备上，`adb install` 极易触发系统的 USB 安装授权弹窗、锁屏密码或指纹验证，导致 AI 自主迭代流程被物理阻塞。

本方案将 AttackSurfaceExplorer 作为常驻测试宿主（固件采集阶段一次性安装）：
- **完全免安装、零弹窗阻断**：AI 或测试人员生成的 Java 逻辑由主机端工具自动编译为单文件 `.dex` 并推送到设备执行，彻底规避 PackageInstaller 交互。
- **极速秒级闭环**：`javac` + `d8` 编译与推送执行耗时通常在 1 秒以内，非常适合 AI 在报错后快速微调参数和重试。
- **进程级崩溃隔离**：执行端运行在独立的 `:runner` 前台服务进程（`ScriptExecutionService`）中，即便动态代码发生 Crash、OOM 或死循环，完全不影响主进程与 ContentProvider 的正常工作。
- **环境权限完全解禁**：`:runner` 进程在 `onCreate()` 时自动调用 `HiddenApiBypass.addHiddenApiExemptions("")`，动态脚本可直接、无限制反射和调用所有被 `@hide` 的系统私有 API 及 `ServiceManager`。
- **规避 SELinux W^X 保护**：服务接收到 DEX 后自动拷贝至受系统信任的应用私有代码缓存目录（`context.getCodeCacheDir()`），再使用 `PathClassLoader` 加载执行，完美符合 Android 8.0+ / 14+ 严格的 W^X 安全策略。
- **突破后台限制与超时**：通过 `am start-foreground-service` 配合 Android 14+ 声明的 `specialUse` 前台服务类型，不受后台广播超时或普通 ContentProvider 同步调用的 ANR 约束。

#### 2. 脚本编写规范

脚本支持两种编写模式：

##### 方式 A：实现标准契约接口（推荐）
实现 `AseScript` 接口，可直接获得 Service 的 `Context` 上下文及主机端传递的入参字符串：

```java
package net.wrlu.ase.payload;

import android.content.Context;
import android.os.IBinder;
import net.wrlu.ase.binder.ServiceManager;
import net.wrlu.ase.script.AseScript;

public class TestServiceProbe implements AseScript {
    @Override
    public String run(Context context, String args) throws Throwable {
        String name = (args != null && !args.isEmpty()) ? args : "activity";
        System.out.println("[Script] Probing service: " + name);
        IBinder binder = ServiceManager.getService(name);
        if (binder == null) {
            return "DENIED_OR_NOT_FOUND";
        }
        return "SUCCESS: alive=" + binder.isBinderAlive() + ", desc=" + binder.getInterfaceDescriptor();
    }
}
```

##### 方式 B：轻量无依赖模式（纯反射）
无需依赖 ASE 任何类库，仅依赖标准 Android SDK 即可编写。只需提供以下任一入口方法：
- `public static String run(Context context, String args)` / `public String run(Context context, String args)`
- `public static String run(String args)` / `public String run(String args)`
- `public static void main(String[] args)`

#### 3. 主机端执行工具（runner.py）

主机端提供一键自动化执行脚本 `AttackSurfaceExplorer/runner.py`。它会自动寻找本地 Android SDK 中的 `javac`、`d8` 和 `android.jar`，完成源码编译、DEX 打包、推送到真机、拉起前台服务、并以结构化 JSON 格式提取执行结果。

```bash
python3 AttackSurfaceExplorer/runner.py <script.java | script.dex> [选项]
```

| 参数 | 说明 |
|------|------|
| `script` | 待执行的 `.java` 源码文件或预编译 `.dex` 文件路径 |
| `-c, --entry-class` | 入口类的全限定名（传入 `.java` 时会自动从源码解析，可省略） |
| `-a, --args` | 传递给脚本 `run()` 方法的入参字符串（如 JSON 或服务名，默认空） |
| `-d, --device` | 指定 adb 设备 serial（多设备连接时使用） |
| `-t, --timeout` | 脚本执行最大超时时间，单位秒（默认 `30` 秒） |
| `-o, --output` | 将返回的结构化执行结果 JSON 保存到本地文件 |
| `--no-clean` | 执行完成后保留推送到设备上的临时 DEX 文件（默认自动清理） |

#### 4. 执行示例与输出格式

执行示例：

```bash
# 传入 Java 源码自动编译并在真机执行，入参指定探测 activity 服务
python3 AttackSurfaceExplorer/runner.py AttackSurfaceExplorer/sample_scripts/TestServiceProbe.java -a "activity"
```

控制台输出：

```text
[Target] Entry class: net.wrlu.ase.payload.TestServiceProbe
[Compile] javac: /opt/homebrew/opt/openjdk@21/bin/javac
[Compile] d8: /Users/xiaolu/Library/Android/sdk/build-tools/37.0.0/d8
[Compile] android.jar: /Users/xiaolu/Library/Android/sdk/platforms/android-37.0/android.jar
[Compile] DEX built successfully: 2084 bytes
[ADB] Push DEX to /data/local/tmp/ase_script.dex
[ADB] Start ScriptExecutionService (:runner process)
[Runner] Waiting for execution result (timeout 30s)...

==================== EXECUTION RESULT ====================
Status:     success
Elapsed:    15 ms
Return Val: SUCCESS: alive=true, desc=android.app.IActivityManager
Stdout:
[Script] Probing service: activity
==========================================================
```

返回的结构化 JSON 字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | `string` | 执行状态：`success` 或 `error` |
| `result` | `string` | 脚本入口方法的返回值（转字符串） |
| `stdout` | `string` | 脚本执行期间通过 `System.out` / `System.err` 输出的全部日志内容 |
| `error` | `string` | 发生异常时的完整 Java Exception 堆栈追踪信息 |
| `elapsed_ms` | `number` | 脚本实际执行耗时（毫秒） |

## 完整流程

```bash
# 0. 构建探测 APK（collector 也会自动编译安装）
cd AttackSurfaceExplorer && ./gradlew :app:assembleRelease

# 1. 采集固件（同时生成 accessible_services.txt）
cd ../collector && python3 collect.py -o ~/firmware/pixel8

# 2. Java 层分析
cd ../java_analyzer && ./gradlew shadowJar && ./analyzer.sh ~/firmware/pixel8

# 3. Native AIDL 分析
cd ../native_analyzer && python3 native_analyzer.py ~/firmware/pixel8
```

## 输出文件

```
<workspace>/
├── packages/                       # 采集的 APK
├── system/lib64/、vendor/lib64/…   # 采集的二进制
├── service_list.txt                # 采集：已注册服务
├── accessible_services.txt         # 采集：实机可达服务
├── all_comp.json                   # 组件分析
├── accessible_comp.json            # 组件分析：问题组件
├── service_aidl.txt                # Java AIDL
├── accessible_service_aidl.txt     # Java AIDL：accessible 子集
├── native_aidl.txt                 # Native AIDL
└── accessible_native_aidl.txt      # Native AIDL：accessible 子集
```
