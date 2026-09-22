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
└── AttackSurfaceExplorer/         # 设备端 Binder 探测 APK
    └── app/src/main/java/net/wrlu/ase/
        ├── binder/                # ServiceManager（HiddenApiBypass）
        └── probe/                 # BinderProber + 导出 ContentProvider
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
| `--ase-apk` | 探测用 AttackSurfaceExplorer APK 路径（默认 `../AttackSurfaceExplorer/app/build/outputs/apk/debug/app-debug.apk`） |
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

JVM 默认 `-Xmx4g`，可用 `JAVA_OPTS` 覆盖：`JAVA_OPTS="-Xmx8g" ./analyzer.sh ...`

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

```bash
cd AttackSurfaceExplorer
./gradlew :app:assembleDebug
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

通过导出的 ContentProvider 探测（URI 固定为 `content://net.wrlu.ase.probe`）：

```bash
# 全部服务
adb shell content query --uri content://net.wrlu.ase.probe

# 单个服务（--where 传服务名）
adb shell content query --uri content://net.wrlu.ase.probe --where "activity"
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

## 完整流程

```bash
# 0. 构建探测 APK
cd AttackSurfaceExplorer && ./gradlew :app:assembleDebug

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
