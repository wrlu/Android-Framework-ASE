# collector

固件采集与实机 Binder 可达性探测模块，是 ASE 全流程的第一阶段。

- 通过 adb 将设备固件（APK / APEX / 二进制 / SELinux / init 等）与运行元数据 dump 到目标目录；
- 自动构建、安装 **AttackSurfaceExplorer** release APK，调用其 `BinderProber` 生成 `accessible_services.txt`；
- 为后续 `java_analyzer`、`native_analyzer`、`post_analyzer` 提供统一输入。

---

## 使用

```bash
cd collector
python3 collect.py -o <output_dir> [-d <device_serial>] [-s | -3]
```

| 参数 | 说明 |
|------|------|
| `-o, --output` | 输出目录（默认当前目录） |
| `-d, --device` | adb 设备 serial（非交互选择） |
| `--ase-apk` | 探测用 AttackSurfaceExplorer APK 路径（默认自动复用/构建 `../AttackSurfaceExplorer/app/build/outputs/apk/release/app-release.apk`） |
| `--probe-only` | 仅安装 APK 并生成 `accessible_services.txt`，不 dump 固件 |
| `--apex-only` | 仅 dump APEX 包并生成 `apex_index.csv` |
| `-s, --system` | 仅 dump 系统包 |
| `-3, --third-party` | 仅 dump 第三方应用（跳过 apex/binaries/selinux） |

`-s` 与 `-3` 互斥。

---

## 采集内容

| 内容 | 输出 |
|------|------|
| 包（APK） | `packages/<pkg>/` |
| APEX / Overlay | `apex/`、`overlay/` |
| 二进制 | 各分区的 `bin` / `lib(64)` / `etc`（支持非 root 自动容错拉取） |
| init 脚本 | `init/`（链接到各分区 `etc/init`） |
| SELinux / 权限策略 | `selinux/`、`permissions/` |
| 运行元数据 | `getprop.txt`、`lshal.txt`、`service_list.txt`、`accessible_services.txt`、`netstat.txt`、`settings_*.txt` |

采集完成后，`packages/` 下会按包名保存 APK；`apex/` 保存 APEX 容器内容，并生成 `apex_index.csv` 记录包名与挂载路径。

---

## 实机 Binder 服务可达性探针（BinderProber）

静态分析只能识别系统镜像中存在哪些 AIDL 接口与实现类，无法得知真实设备上厂商定制的 SELinux 策略、ioctl 规则、UID/GID 校验是否会在底层阻断三方普通应用获取系统服务。

因此 `collector` 在采集运行元数据阶段会：

1. 首次或 ASE 源码变更时，通过 Gradle wrapper 构建 AttackSurfaceExplorer release APK；
2. 使用 `adb install -r -g` 覆盖安装；
3. 调用 APK 内置的 `BinderProber`。

### 探测原理

- 以普通应用沙箱身份（`untrusted_app`，标准 App UID）通过私有 API 反射调用 `ServiceManager.getService(name)`；
- 仅探测 Binder 句柄可达性与存活性（`binder != null && binder.isBinderAlive()`）；
- **不读取 descriptor，也不主动发起 AIDL 事务方法调用**，避免探测阶段因非法传参诱发系统服务异常、死锁或崩溃。

### 结果回传

探测结果通过通用 `ContentProvider`（`content://net.wrlu.ase.probe/binder_service`）回传，并写入 `accessible_services.txt`。该文件是后续 Java/Native 分析筛选可达服务、`post_analyzer` 求盲区差集的核心基准。

### 手动查询

```bash
# 查询全部已注册服务的可达性
adb shell content query --uri content://net.wrlu.ase.probe/binder_service

# 查询指定单个服务（例如 activity）
adb shell content query --uri content://net.wrlu.ase.probe/binder_service --where "activity"
```

输出示例：

```text
Row: 0 service=DockObserver, accessible=0
Row: 1 service=SurfaceFlinger, accessible=1
Row: 2 service=SurfaceFlingerAIDL, accessible=1
```

| 字段 | 含义 |
|------|------|
| `service` | 服务注册名 |
| `accessible=1` | 当前应用沙箱能成功取得该 Binder 句柄且存活 |
| `accessible=0` | 权限受阻（SELinux/UID）或服务未注册 |

### 降级行为

在已有固件 dump 上可用 `--probe-only` 仅刷新该可达性文件。若 APK 缺失或 provider 不可用，collector 会跳过探针，此时后续分析退化为无实机验证的全量静态分析。

---

## 相关文档

- [ASE 主 README](../README.md)
- [AttackSurfaceExplorer（设备端探针与动态验证）](../AttackSurfaceExplorer/README.md)
- [java_analyzer](../java_analyzer/README.md)
- [native_analyzer](../native_analyzer/README.md)
- [post_analyzer](../post_analyzer/README.md)
