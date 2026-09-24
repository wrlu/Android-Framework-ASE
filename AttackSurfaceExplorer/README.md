# AttackSurfaceExplorer (ASE)

设备端辅助 APK 与主机端动态执行工具，为固件攻击面分析提供**实机可达性探针**与**动态 PoC 验证**双重能力：

- **Binder 服务可达性探针（BinderProber）**：在真实设备上以普通 App 沙箱身份探测各系统服务是否对低权限开放，生成 `accessible_services.txt` 为静态分析提供过滤基准；
- **动态脚本验证框架（runner.py）**：在完成静态与盲区分析后，针对盲区服务或可疑 AIDL 接口，无需编写完整 Android 项目即可快速编译、推送并在独立进程中执行 Java/DEX 验证脚本。

---

## 模块一：Binder 服务可达性探针（BinderProber）

### 1. 探测原理
静态分析只能判断接口定义和实现是否存在，无法得知厂商定制的 SELinux 策略、SELinux ioctl 规则以及服务端的 UID 校验是否会在运行时阻断服务获取。

AttackSurfaceExplorer 以 **APK 自身 UID（普通 untrusted_app 沙箱）** 通过隐藏 API 反射调用 `android.os.ServiceManager.getService(name)` 获取服务：
- 仅探测能否成功获取到存活的 `IBinder` 句柄；
- **不读取 descriptor，也不主动发起 AIDL 事务调用**，最大程度避免在探测阶段触发系统服务异常或死锁；
- 探测结果通过通用的 `ContentProvider` 导出。

### 2. 配合 Collector 自动工作
在运行 `collector/collect.py` 或根目录 `run.sh` 时，工具会自动将预编译的 `app-release.apk` 覆盖安装（`adb install -r -g`）至目标设备，自动查询该 Provider 并保存为 `accessible_services.txt`，供后续 Java / Native AIDL 分析使用。

### 3. 手动调试与查询命令

端点 URI 为 `content://net.wrlu.ase.probe/binder_service`：

```bash
# 查询全部服务
adb shell content query --uri content://net.wrlu.ase.probe/binder_service

# 查询单个服务（--where 传服务名）
adb shell content query --uri content://net.wrlu.ase.probe/binder_service --where "activity"
```

输出示例：
```text
Row: 0 service=DockObserver, accessible=0
Row: 1 service=SurfaceFlinger, accessible=1
Row: 2 service=SurfaceFlingerAIDL, accessible=1
```

| 查询方式 | 行为 |
|---|---|
| 不传 `--where` | 遍历设备 ServiceManager 中已注册的全部服务并逐个探测 |
| 传 `--where "<service_name>"` | 仅探测指定的单个服务 |

| 返回字段 | 含义 |
|---|---|
| `service` | 服务名 |
| `accessible` | `1` = 成功取到有效 `IBinder` 且存活；`0` = 无法获取（无权访问或未注册） |

> **安全限制**：Provider 内部通过 `Binder.getCallingUid()` 限制调用方：仅本应用、system(1000)、adb shell(2000) 与 root(0) 可发起查询。

---

## 模块二：动态脚本自主验证（runner.py）

在静态分析（`java_analyzer`、`native_analyzer`）与后处理（`post_analyzer`）完成后，工具通常会暴露出若干**盲区服务**（`unresolved_accessible_services.txt`）或高危 AIDL 业务接口。`runner.py` 提供了一种免去开发打包完整测试 App 成本的轻量化实机验证机制。

### 1. 核心特性
- **框架私有 API 全面豁免**：测试进程已通过 `HiddenApiBypass` 注入全豁免策略，可直接反射或调用 `@hide` 的框架类与私有方法；
- **持有完整 Service Context 上下文**：脚本在执行时直接获取前台服务的 `Context` 实例，支持直接发起 Binder IPC 通信、动态注册 BroadcastReceiver、查询 ContentProvider 等；
- **进程级崩溃隔离**：脚本运行在专属的 `:runner` 前台服务子进程中。测试过程中发生 Crash、OOM 或死循环完全不影响 ASE 主应用；
- **主机端自动化工具链**：`runner.py` 自动搜寻本地 Android SDK（`javac` 与 `d8`），在主机端秒级完成编译并推送到设备执行；
- **结构化执行报告**：捕获脚本返回值、`System.out` / `System.err` 输出及未捕获异常堆栈，以 JSON 格式回传给主机。

### 2. 使用限制
- **不支持清单静态生命周期回调**：无法在运行时动态声明 AndroidManifest 组件，不支持强依赖系统静态绑定的组件（如 AccessibilityService、DeviceAdminReceiver、NotificationListenerService 等）；
- **无法突破宿主应用已有权限**：运行在普通 App 沙箱（`u0_aXXX`）和 `untrusted_app` SELinux 域内，无法动态增减 `<uses-permission>` 或获取厂商专有签名权限；
- **无打包资源表（Resources）**：动态 DEX 不包含 `resources.arsc`，不支持 `R.layout.xxx` 等编译期资源 ID，仅限纯 Java 代码逻辑。

### 3. 编写测试脚本
新建 Java 源码文件，实现 `AseScript` 契约接口：

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

更多示例可参考 [sample_scripts/](sample_scripts/) 目录。

### 4. 运行与参数

```bash
# 1. 传入 Java 源码直接执行（自动编译并运行）
python3 runner.py sample_scripts/TestServiceProbe.java -a "activity"

# 2. 传入预编译好的 DEX 文件直接执行
python3 runner.py payload.dex -c net.wrlu.ase.payload.TestServiceProbe -a "wifi"

# 3. 指定目标设备与结果输出文件
python3 runner.py sample_scripts/TestServiceProbe.java -d <serial> -o result.json
```

| 参数 | 说明 |
|---|---|
| `script` | 待执行的 `.java` 源码或已编译的 `.dex` 文件路径 |
| `-c, --entry-class` | 入口类全限定名（传入 `.java` 时自动从源码解析，可省略） |
| `-a, --args` | 传递给 `run(Context, String)` 方法的入参字符串（如 JSON、服务名，默认空） |
| `-d, --device` | 指定 adb 设备 serial |
| `-t, --timeout` | 超时时间（默认 `30` 秒） |
| `-o, --output` | 保存结构化 JSON 结果到指定本地文件 |
| `--no-clean` | 保留推送到设备上的临时 DEX 文件（默认自动清理） |

### 5. 结果回传格式
执行完成后，终端会打印格式化的摘要，并输出包含详细信息的 JSON：

```json
{
  "status": "success",
  "result": "SUCCESS: alive=true, desc=android.app.IActivityManager",
  "stdout": "[Script] Probing service: activity\n",
  "error": "",
  "elapsed_ms": 15
}
```

---

## 编译与签名

仓库已内置预编译好的 release 包：`AttackSurfaceExplorer/app-release.apk`，使用内置的 `ase-release.jks`（信息匿名化）进行签名。

若修改了 Java 源码需重新构建：

```bash
./gradlew :app:assembleRelease
adb install -r -g app/build/outputs/apk/release/app-release.apk
```
