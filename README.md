# Android Framework Attack Surface Explorer (ASE)

Android 固件攻击面分析工具，覆盖「固件采集 → 静态分析 → 实机验证」完整链路：

- **collector** — 通过 adb dump 固件（APK / APEX / 二进制 / SELinux / init 等）与运行元数据
- **java_analyzer** — 基于 JADX 分析 Java 层导出组件权限与 AIDL 接口
- **native_analyzer** — 扫描 .so 中的 Native AIDL 接口
- **post_analyzer** — 比对实机可访问服务与静态分析结果，提取未匹配 AIDL 的盲区服务差集
- **AttackSurfaceExplorer** — 设备端 APK，实机探测 binder 服务能否被获取

## 目录结构

```
.
├── run.sh                         # 一键全流程启动脚本（提取 + 全套分析）
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
├── post_analyzer/
│   └── post_analyzer.py           # 后处理：求差集与盲区服务分析
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
| Python | 3.8+ | collector、native_analyzer、post_analyzer |
| adb | 1.0.41+ | collector |
| JDK | 21+ | java_analyzer |
| Gradle | 8.5+ | java_analyzer（仓库自带 wrapper） |

## 一键全流程（One-Click Pipeline）

在项目根目录下通过 `run.sh` 脚本可完成从设备固件提取到组件、Java 服务、Native 服务及盲区对齐的完整端到端分析：

```bash
# 1. 全流程：从连接的 adb 设备采集固件并执行完整分析
./run.sh <workspace_dir>

# 2. 纯分析：对已有固件 dump 目录运行完整分析（跳过设备采集）
./run.sh <workspace_dir> --analyze-only

# 3. 仅重新探测实机可达性并分析
./run.sh <workspace_dir> --probe-only

# 4. 指定 adb 设备或仅采集系统包
./run.sh <workspace_dir> -d <device_serial> -s
```

`run.sh` 会自动检测设备连接状态、按需构建 Java Analyzer JAR 包，并依序执行全部分析阶段。

各阶段亦可独立单步执行：

## 阶段 1：固件采集（collector）

```bash
cd collector
python3 collect.py -o <output_dir> [-d <device_serial>] [-s | -3]
```

| 参数 | 说明 |
|------|------|
| `-o, --output` | 输出目录（默认当前目录） |
| `-d, --device` | adb 设备 serial（非交互选择） |
| `--ase-apk` | 探测用 AttackSurfaceExplorer APK 路径（默认优先使用预编译 `../AttackSurfaceExplorer/app-release.apk`） |
| `--probe-only` | 仅安装 APK 并生成 `accessible_services.txt`，不 dump 固件 |
| `--apex-only` | 仅 dump APEX 包并生成 `apex_index.csv` |
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

加载 `packages/android/` 下的 framework jar/apk 以及 `apex/*/javalib/` 下的 Mainline 模块核心 JAR 包（自动识别并跳过软链接/替身以防重复反编译），识别 AIDL 接口（Default + Stub + Stub.Proxy 三件套），沿父类链 BFS 查找实现类并提取方法签名，支持间接继承。

| 输出 | 说明 |
|------|------|
| `service_aidl.txt` | 每个接口一行 `接口名 [实现类] [service=服务名]`，后跟方法签名；存在 `accessible_services.txt` 时追加 `[accessible=1\|0\|unknown]` |
| `accessible_service_aidl.txt` | 仅 `accessible=1` 的接口子集（包含 `[service=服务名]`，无 accessible 标记） |

```
# service_aidl.txt
android.app.ILocaleManager [com.android.server.locales.LocaleManagerService.LocaleManagerBinderService] [service=locale] [accessible=1]
android.os.IRecoverySystem [com.android.server.recoverysystem.RecoverySystemService] [service=recovery] [accessible=0]

# accessible_service_aidl.txt
android.app.ILocaleManager [com.android.server.locales.LocaleManagerService.LocaleManagerBinderService] [service=locale]
android.app.ILocaleManager.getApplicationLocales(java.lang.String, int):android.os.LocaleList
```

`accessible_services.txt` 以服务名记录，分析时通过 `service_list.txt` 的 `服务名 → descriptor` 映射回 AIDL 接口并记录对应服务名。

## 阶段 3：Native AIDL 分析（native_analyzer）

```bash
cd native_analyzer
python3 native_analyzer.py <workspace_dir> [--ignore-registered]
```

无需构建、无外部依赖。扫描各分区 `lib(64)`、`bin`（含 `bin/hw`）以及 `apex/` 容器下的全部 ELF 二进制：

1. **Descriptor 提取** — 匹配标准 AIDL 字符串模式、C++ libbinder 的 UTF-16LE String16 常量（如 `SurfaceFlinger`、`IAudioFlingerService`、`SensorServer` 等）、非标准命名接口（如 `ConnectivityNative`）与 Rust v0 mangling 符号；
2. **多层服务端判定（解决 Strip 与 -fno-rtti 漏报）** — 结合 C++ Itanium ABI（`{len}Bn{Name}`）、Rust mangling、以及 ELF 动态符号表（`AIBinder_Class_define`、`AServiceManager_addService`、`defaultServiceManager` 等关键系统调用）；
3. **技术栈架构识别（Backend）** — 基于 `DT_NEEDED` 依赖库与导出符号，自动分类为 `libbinder`（旧式私有 C++）、`ndk`（基于 `libbinder_ndk` 的 Stable AIDL）或 `rust`；
4. **APEX 深度扫描与去重** — 自动覆盖 Android 10+ Mainline 模块，并在遍历时跳过软链接（Finder 替身），确保二进制去重且仅扫描真实实体；
5. **service_list 交叉引用** — 默认仅保留已注册 descriptor，`--ignore-registered` 输出全部 server 接口；
6. **AIDL 方法签名还原** — 自动交叉引用 Java 提取的 `service_aidl.txt`；对纯 Native 接口，解析 ELF 动态符号表中 `Bp{Name}` 客户端代理类导出符号，还原具体 AIDL 业务方法；
7. **onTransact 入口定位** — 匹配服务端 `Bn{Name}::onTransact`（C++）或 `on_transact`（Rust）函数虚地址偏移，输出 `[onTransact=0x...]` 标记。

| 输出 | 说明 |
|------|------|
| `native_aidl.txt` | `descriptor [so_path] [service=服务名] [backend=libbinder\|ndk\|rust] [onTransact=0x...]`，包含 AIDL 方法签名；存在 `accessible_services.txt` 时追加 `[accessible=1\|0\|unknown]` |
| `accessible_native_aidl.txt` | 仅 `accessible=1` 的 server 子集（包含 `[service=服务名]`、`[backend=...]`、`[onTransact=0x...]` 与还原的 AIDL 方法，无 accessible 标记） |

```
# native_aidl.txt
android.ui.ISurfaceComposer [system/lib64/libgui.so] [service=SurfaceFlinger] [backend=libbinder] [onTransact=0xc6be0] [accessible=1]
0xf80d0: android::gui::BpSurfaceComposer::addJankListener(android::sp<android::IBinder> const&, android::sp<android::gui::IJankListener> const&)
0xf8570: android::gui::BpSurfaceComposer::captureDisplay(android::gui::DisplayCaptureArgs const&, android::sp<android::gui::IScreenCaptureListener> const&)

# accessible_native_aidl.txt
android.net.connectivity.aidl.ConnectivityNative [apex/com.google.android.tetherin/lib64/libcom.android.tethering.connectivity_native.so] [service=connectivity_native] [backend=ndk]
0x8e00: aidl::android::net::connectivity::aidl::BpConnectivityNative::blockPortForBind(int)
0x8ee8: aidl::android::net::connectivity::aidl::BpConnectivityNative::unblockPortForBind(int)
0x9b64: aidl::android::net::connectivity::aidl::IConnectivityNativeDefault::unblockAllPortsForBind()
0x9ba0: aidl::android::net::connectivity::aidl::IConnectivityNativeDefault::getPortsBlockedForBind(std::vector<int>*)
```

## 阶段 4：后处理分析（post_analyzer）

```bash
cd post_analyzer
python3 post_analyzer.py <workspace_dir> [-o <output_file>]
```

自动比对实机可访问服务列表（`accessible_services.txt`）与 Java/Native 静态分析已解析的 AIDL 接口（`accessible_service_aidl.txt` 与 `accessible_native_aidl.txt`），执行差集运算，提取所有低权限可达但未能还原出 AIDL 实现的“盲区服务”：

| 输出 | 说明 |
|------|------|
| `unresolved_accessible_services.txt` | 实机可达但未匹配到 Java/Native AIDL 实现的服务列表，包含服务名、Descriptor 及原因（`no_aidl_matched` 或 `empty_descriptor`） |

```
# unresolved_accessible_services.txt
media.camera [android.hardware.ICameraService] [no_aidl_matched]
vendor.custom.daemon [] [empty_descriptor]
```

控制台同时输出对账汇总（覆盖率与分布统计）：

```text
=== Accessibility Reconciliation Summary ===
Total probed services:      400
Accessible services (ASE):  220
  ├─ Resolved:              217 (98.6%)
  │   ├─ Java AIDL:         193 (87.7%, accessible_service_aidl.txt)
  │   └─ Native AIDL:       53 (24.1%, accessible_native_aidl.txt)
  └─ Unresolved:            3 (1.4%) -> unresolved_accessible_services.txt
============================================
```

这些服务通常为**手写 Raw BBinder 实现（无标准 AIDL 接口）**、**Descriptor 为空的匿名服务**、或**实现在未扫描系统 App / APEX 中**，是安全研究员进行针对性人工逆向和动态测试（如使用 `runner.py`）的高价值目标。

## 阶段 5：设备端 Binder 探测（AttackSurfaceExplorer）

静态分析只能判断接口存在，无法判断实机上能否真正拿到 binder 句柄。AttackSurfaceExplorer 以 **APK 自身 uid/权限** 通过 `android.os.ServiceManager` 获取服务，仅探测能否取到 `IBinder`——不读取 descriptor，也不调用 AIDL 方法。

APK 使用内置的 `ase-release.jks` 做 release 签名（匿名化信息）。仓库根目录已包含预编译的 `AttackSurfaceExplorer/app-release.apk`，`collector/collect.py` 默认优先使用该预编译包并以覆盖安装（`adb install -r -g`）方式推送到设备。若需修改 ASE 源码并重新编译，也可手动操作：

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

基于动态 DEX 加载与独立进程前台服务（`:runner`），支持在真机上直接执行单文件测试脚本。

#### 1. 能力范围
- **框架私有 API 调用**：`:runner` 进程已全局注入 HiddenApi 豁免，可直接反射与调用所有 `@hide` 框架类及 `ServiceManager`。
- **持有 Service Context**：直接获取 Service 的 `Context` 上下文，可进行 Binder IPC 交互、动态注册广播接收器、发起 ContentProvider 查询等。
- **进程级崩溃隔离**：运行在独立的 `:runner` 前台服务进程中，脚本发生 Crash、OOM 或死循环完全不影响 ASE 主进程。
- **结构化结果回传**：自动捕获脚本返回值、`System.out` 输出及未捕获异常堆栈，以结构化 JSON 回传给主机端。

#### 2. 使用限制
- **不支持组件生命周期回调**：无法在运行时动态声明清单组件（Activity / Service / Provider 等），不支持依赖系统静态绑定的生命周期回调（如 AccessibilityService、DeviceAdminReceiver、NotificationListenerService 等）。
- **无法动态增减权限**：受限于宿主 ASE 已有的权限，无法动态声明新的 `<uses-permission>`，也无法获取厂商专有签名特权。
- **无打包资源表（Resources）**：DEX 不包含 `resources.arsc` 资源表，不支持 `R.layout.xxx` 等编译期资源，仅限纯代码逻辑。
- **普通应用沙箱**：运行身份为标准 App UID（`u0_aXXX`）与 `untrusted_app` SELinux 域，不具备 root 特权。

#### 3. 编写脚本
实现 `AseScript` 契约接口：

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

#### 4. 执行方式
主机端使用 `AttackSurfaceExplorer/runner.py`，自动调用本地 Android SDK（`javac` + `d8`）编译、推送到设备并拉起服务：

```bash
# 传入 Java 源码直接执行（自动编译并运行）
python3 AttackSurfaceExplorer/runner.py AttackSurfaceExplorer/sample_scripts/TestServiceProbe.java -a "activity"

# 传入预编译的 DEX 文件
python3 AttackSurfaceExplorer/runner.py payload.dex -c net.wrlu.ase.payload.TestServiceProbe
```

| 参数 | 说明 |
|------|------|
| `script` | 待执行的 `.java` 源码或 `.dex` 文件路径 |
| `-c, --entry-class` | 入口类全限定名（传入 `.java` 时自动从源码解析，可省略） |
| `-a, --args` | 传递给 `run()` 方法的入参字符串（如 JSON、服务名，默认空） |
| `-d, --device` | 指定 adb 设备 serial |
| `-t, --timeout` | 超时时间（默认 `30` 秒） |
| `-o, --output` | 保存结构化 JSON 结果到本地文件 |
| `--no-clean` | 保留推送到设备上的临时 DEX 文件（默认自动清理） |

#### 5. 结果输出格式
控制台会打印执行摘要，返回包含状态、耗时、标准输出及异常堆栈的结构化 JSON：

```json
{
  "status": "success",
  "result": "SUCCESS: alive=true, desc=android.app.IActivityManager",
  "stdout": "[Script] Probing service: activity\n",
  "error": "",
  "elapsed_ms": 15
}
```

## 完整流程

```bash
# 0. 构建探测 APK（可选，已内置预编译 AttackSurfaceExplorer/app-release.apk，仅修改源码时需要）
cd AttackSurfaceExplorer && ./gradlew :app:assembleRelease

# 1. 采集固件（同时生成 accessible_services.txt）
cd ../collector && python3 collect.py -o ~/firmware/pixel8

# 2. Java 层分析
cd ../java_analyzer && ./gradlew shadowJar && ./analyzer.sh ~/firmware/pixel8

# 3. Native AIDL 分析
cd ../native_analyzer && python3 native_analyzer.py ~/firmware/pixel8

# 4. 后处理（求差集，输出未匹配的实机可达服务）
cd ../post_analyzer && python3 post_analyzer.py ~/firmware/pixel8
```

## 输出文件

```
<workspace>/
├── packages/                       # 采集的 APK
├── apex/                           # 采集的 APEX 模块（含 lib/bin/javalib 等）
├── apex_index.csv                  # 采集：APEX 包名与挂载路径索引
├── system/lib64/、vendor/lib64/…   # 采集的二进制
├── service_list.txt                # 采集：已注册服务
├── accessible_services.txt         # 采集：实机可达服务
├── all_comp.json                   # 组件分析
├── accessible_comp.json            # 组件分析：问题组件
├── service_aidl.txt                   # Java AIDL（含 [service=...] 标注）
├── accessible_service_aidl.txt        # Java AIDL：accessible 子集
├── native_aidl.txt                    # Native AIDL（含 [service=...] 标注）
├── accessible_native_aidl.txt         # Native AIDL：accessible 子集
└── unresolved_accessible_services.txt # 后处理：未匹配 AIDL 的可达服务差集
```
