# Android Framework Attack Surface Explorer (ASE)

Android 固件攻击面分析工具，覆盖「固件采集 → 静态分析 → 盲区对齐 → 动态验证」完整链路。

---

## 架构

```text
                    ┌─────────────────────────────┐
                    │ collector                   │
                    │  adb dump + BinderProber    │
                    └──────────────┬──────────────┘
                                   │ firmware dump
                 ┌─────────────────┴─────────────────┐
                 │                                   │
        ┌────────▼────────┐                 ┌────────▼────────┐
        │ java_analyzer   │                 │ native_analyzer │
        │ components/AIDL │                 │ Native AIDL     │
        └────────┬────────┘                 └────────┬────────┘
                 └─────────────────┬─────────────────┘
                                   │
                          ┌────────▼────────┐
                          │ post_analyzer   │
                          │ 盲区服务对账    │
                          └────────┬────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 │                                   │
        ┌────────▼────────┐                 ┌────────▼────────┐
        │ AttackSurface   │                 │ diff_analyzer   │
        │ Explorer        │                 │ 双 dump 差异    │
        │ 动态 PoC        │                 │                 │
        └─────────────────┘                 └─────────────────┘

        ase_shell：对分析与差异结果做交互式检索
```

- **静态链路**：`collector` → `java_analyzer` / `native_analyzer` → `post_analyzer`
- **差异分析**：对两个已完成分析的 dump 运行 `diff_analyzer`
- **动态验证**：用 `AttackSurfaceExplorer` 的 `runner.py` 对盲区/高危接口做实测
- **交互检索**：用 `ase_shell` 按包、服务、AIDL 查询 dump

---

## 模块

| 模块 | 职责 | 文档 |
|------|------|------|
| `collector` | adb 采集固件与运行元数据；调用 BinderProber 生成 `accessible_services.txt` | [collector/README.md](collector/README.md) |
| `java_analyzer` | JADX/dexlib2 分析组件权限、Java AIDL，并提供类差异 helper | [java_analyzer/README.md](java_analyzer/README.md) |
| `native_analyzer` | 扫描 ELF 二进制，提取 Native AIDL、backend、so、onTransact | [native_analyzer/README.md](native_analyzer/README.md) |
| `post_analyzer` | 对账实机可达服务与 Java/Native 结果，提取盲区服务 | [post_analyzer/README.md](post_analyzer/README.md) |
| `diff_analyzer` | 比较两个 dump，输出 `diff.json`（包/组件/权限/Binder/APEX/方法体） | [diff_analyzer/README.md](diff_analyzer/README.md) |
| `ase_shell` | dump 目录交互式检索 | [ase_shell/README.md](ase_shell/README.md) |
| `AttackSurfaceExplorer` | 设备端 Binder 探测 + 动态 Java/DEX 脚本验证 | [AttackSurfaceExplorer/README.md](AttackSurfaceExplorer/README.md) |

---

## 环境要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | 3.9+ | collector、native_analyzer、post_analyzer、diff_analyzer、ase_shell |
| adb | 1.0.41+ | collector |
| JDK | 21+ | java_analyzer、AttackSurfaceExplorer 构建 |
| Gradle | 8.5+ | java_analyzer、AttackSurfaceExplorer（仓库自带 wrapper） |
| Android SDK | platform 37 / build-tools 37 | AttackSurfaceExplorer 构建 |
| c++filt / llvm-cxxfilt | 任选其一（可选） | native_analyzer 还原 C++ 方法签名 |

---

## 快速开始

### 一键全流程

```bash
# 采集 + Java + Native + 后处理
./run.sh <workspace_dir>

# 对已有 dump 只做分析
./run.sh <workspace_dir> --analyze-only

# 只刷新实机可达性后重新分析
./run.sh <workspace_dir> --probe-only

# 只采集
./run.sh <workspace_dir> --collect-only
```

`run.sh` 会自动检测设备、按需构建 Java Analyzer JAR，并依序执行各阶段。

### 常用选项

| 选项 | 说明 |
|------|------|
| `-d, --device <serial>` | 指定 adb 设备 |
| `-s / -3` | 仅系统包 / 仅第三方应用 |
| `--ase-apk <path>` | 指定 AttackSurfaceExplorer APK |
| `--components-only` / `--aidl-only` | 只跑组件或只跑 Java AIDL |
| `--ignore-registered` | 输出全部 AIDL，不按 `service_list.txt` 过滤 |
| `--skip-components` / `--skip-java` / `--skip-native` / `--skip-post` | 跳过对应阶段 |

完整参数见 `./run.sh --help`。

---

## 分步执行

```bash
# 1. 采集固件 + 实机可达性
cd collector
python3 collect.py -o <workspace_dir>

# 2. Java 层分析
cd ../java_analyzer
./gradlew shadowJar
./analyzer.sh <workspace_dir>

# 3. Native AIDL 分析
cd ../native_analyzer
python3 native_analyzer.py <workspace_dir>

# 4. 后处理：提取盲区服务
cd ../post_analyzer
python3 post_analyzer.py <workspace_dir>
```

各阶段的参数、输出格式与实现细节见对应模块 README。

### 镜像差异

```bash
python3 diff_analyzer/diff.py <baseline_dump> <candidate_dump>
# 默认输出 <candidate>/diff.json
```

差异报告结构、类级方法体检测、缺失产物策略见 [diff_analyzer/README.md](diff_analyzer/README.md)。

### 动态验证

```bash
python3 AttackSurfaceExplorer/runner.py \
  AttackSurfaceExplorer/sample_scripts/TestServiceProbe.java -a "activity"
```

探针查询、脚本契约接口、执行限制见 [AttackSurfaceExplorer/README.md](AttackSurfaceExplorer/README.md)。

---

## 目录结构

```text
.
├── run.sh                    # 一键全流程
├── collector/                # 固件采集 + BinderProber
├── java_analyzer/            # 组件权限 + Java AIDL + 类差异 helper
├── native_analyzer/          # Native AIDL 扫描
├── post_analyzer/            # 盲区服务对账
├── diff_analyzer/            # 双 dump 差异
├── ase_shell/                # dump 交互式检索
└── AttackSurfaceExplorer/    # 设备端探针与动态验证
```

---

## 输出文件

```text
<workspace>/
├── packages/                           # APK
├── apex/                               # APEX 模块
├── apex_index.csv                      # APEX 包名与挂载路径
├── system/lib64/、vendor/lib64/…       # 二进制
├── service_list.txt                    # 已注册服务
├── accessible_services.txt             # 实机可达服务
├── all_comp.json                       # 全量组件
├── accessible_comp.json                # 弱权限可达组件
├── service_aidl.txt                    # Java AIDL
├── accessible_service_aidl.txt         # Java AIDL：可达子集
├── native_aidl.txt                     # Native AIDL
├── accessible_native_aidl.txt          # Native AIDL：可达子集
├── unresolved_accessible_services.txt  # 盲区服务
└── diff.json                           # 可选：镜像差异
```

---

## 文档

- [系统架构设计](ARCHITECTURE.md)
- [collector](collector/README.md)
- [java_analyzer](java_analyzer/README.md)
- [native_analyzer](native_analyzer/README.md)
- [post_analyzer](post_analyzer/README.md)
- [diff_analyzer](diff_analyzer/README.md)
- [ase_shell](ase_shell/README.md)
- [AttackSurfaceExplorer](AttackSurfaceExplorer/README.md)
