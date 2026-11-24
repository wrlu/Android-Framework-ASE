# java_analyzer

Java 层静态分析模块：扫描 APK / framework jar / Mainline JAR，输出组件权限清单与 Java AIDL 接口清单。

同时包含 `net.wrlu.android.ase.classdiff.ClassDiffMain`（dexlib2），由 `diff_analyzer` 调用，用于比较组件类与 Binder impl 类的方法体。

---

## 构建与运行

```bash
cd java_analyzer
./gradlew shadowJar      # 产物 build/libs/analyzer-1.0.0-all.jar
./analyzer.sh <workspace_dir> [--components] [--aidl] [--ignore-registered]
```

也可以只构建：

```bash
./analyzer.sh --build
```

JVM 默认 `-XX:MaxRAMPercentage=50.0`（分配当前设备内存的 50%），可用 `JAVA_OPTS` 覆盖：

```bash
JAVA_OPTS="-Xmx8g" ./analyzer.sh <workspace_dir>
```

| 参数 | 说明 |
|------|------|
| `<workspace_dir>` | collector 产出的 dump 目录 |
| `--components` | 仅运行组件权限分析 |
| `--aidl` | 仅运行 Java AIDL 接口搜索 |
| `--ignore-registered` | 不按 `service_list.txt` 过滤，输出全部 AIDL 接口 |
| 默认 | 两个分析都运行 |

AIDL 实现类统一输出底层真实原生字节码类名（Raw Class Name，如 `$1`），避免 JADX 的 `AnonymousClass` 反混淆重命名，保证与 Frida、Xposed 及 Java 反射环境兼容。

---

## 组件权限分析

扫描 `packages/` 下的 APK，解码 AndroidManifest.xml，识别导出的 activity / service / provider / receiver 及其权限保护级别。

| 输出 | 说明 |
|------|------|
| `all_comp.json` | 全量组件清单（含 `exported`、`enabled` 字段，导出/非导出、启用/禁用组件均收录；包名、组件、定义权限、声明权限、protected-broadcast）；APK 路径为相对 workspace root 的相对路径 |
| `accessible_comp.json` | 问题组件清单（仅针对已导出且 `enabled != false` 的组件），按组件类型（activity / service / provider / receiver）分组，每条含 `type` 字段标记 `undefined`（权限未定义）或 `unprivileged`（保护级别不足） |

```json
// all_comp.json
{
  "package": "com.example.app",
  "filename": "packages/com.example.app/base.apk",
  "components": [
    { "name": "com.example.app.MainActivity", "type": "activity", "exported": true, "permission": "" },
    { "name": "com.example.app.InternalService", "type": "service", "exported": false, "permission": "" },
    { "name": "com.example.app.DataProvider", "type": "provider", "exported": true, "permission": "com.example.app.READ_DATA" }
  ],
  "defined_permissions": [
    { "name": "com.example.app.READ_DATA", "protectionLevel": "normal" }
  ],
  "uses_permissions": ["android.permission.INTERNET"],
  "protected_broadcasts": []
}
```

```json
// accessible_comp.json
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

### 保护级别判定

`PROTECTION_FLAG`：`signature`(0x2)、`system`(0x10)、`privileged`(0x20)、`internal`(0x40)、`preinstalled`(0x4000) 视为 privileged；`normal`(0)、`dangerous`(0x1) 不予保护。支持组合名（`signature|privileged`）与十进制/十六进制整数。

导出且带 `BROWSABLE` 的 activity 会额外提取 deeplink（actions / categories / data：scheme、host、port、path、pathPrefix、pathPattern、mimeType）。

`enabled="false"` 的组件仍保留在 `all_comp.json`，但不计入 `accessible_comp.json`。

---

## Java AIDL 接口搜索

加载 `packages/android/` 下的 framework jar/apk 以及 `apex/*/javalib/` 下的 Mainline 模块核心 JAR 包（自动识别并跳过软链接/替身以防重复反编译），识别 AIDL 接口（Default + Stub + Stub.Proxy 三件套），沿父类链 BFS 查找实现类并提取方法签名，支持间接继承。

| 输出 | 说明 |
|------|------|
| `service_aidl.txt` | 每个接口一行 `接口名 [实现类] [service=服务名]`，后跟方法签名；存在 `accessible_services.txt` 时追加 `[accessible=1\|0\|unknown]` |
| `accessible_service_aidl.txt` | 仅 `accessible=1` 的接口子集（包含 `[service=服务名]`，无 accessible 标记） |

```text
# service_aidl.txt
android.app.ILocaleManager [com.android.server.locales.LocaleManagerService.LocaleManagerBinderService] [service=locale] [accessible=1]
android.os.IRecoverySystem [com.android.server.recoverysystem.RecoverySystemService] [service=recovery] [accessible=0]

# accessible_service_aidl.txt
android.app.ILocaleManager [com.android.server.locales.LocaleManagerService.LocaleManagerBinderService] [service=locale]
android.app.ILocaleManager.getApplicationLocales(java.lang.String, int):android.os.LocaleList
```

`accessible_services.txt` 以服务名记录，分析时通过 `service_list.txt` 的“服务名 → descriptor”映射回 AIDL 接口并记录对应服务名。

---

## 类差异 helper（供 diff_analyzer 使用）

- 入口：`net.wrlu.android.ase.classdiff.ClassDiffMain`
- 依赖：`com.android.tools.smali:smali-dexlib2`
- 用途：对 APK、`packages/android/*.jar`、APEX `javalib/*.jar` 中的类做规范化方法体指纹比较
- 只比较方法体：方法签名、归一化指令、引用、字面量、分支/switch/try-catch；不比较字段、注解、继承关系、debug 信息、地址与寄存器
- 通过 `diff_analyzer` 自动调用；默认 `-Xmx4g`，可用 `ASE_CLASS_DIFF_XMX` 调整

---

## 相关文档

- [ASE 主 README](../README.md)
- [collector](../collector/README.md)
- [diff_analyzer](../diff_analyzer/README.md)
