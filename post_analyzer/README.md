# post_analyzer

后处理模块：对账实机可达服务与 Java/Native 静态分析结果，提取“可达但未还原出 AIDL 实现”的盲区服务。

---

## 使用

```bash
cd post_analyzer
python3 post_analyzer.py <workspace_dir> [-o <output_file>]
```

| 参数 | 说明 |
|------|------|
| `<workspace_dir>` | ASE dump 目录（默认当前目录） |
| `-o, --output` | 输出文件路径（默认 `<workspace>/unresolved_accessible_services.txt`） |

无 Python 第三方依赖。

---

## 对账逻辑

读取：

- `accessible_services.txt`：实机可达服务列表；
- `accessible_service_aidl.txt`：Java 侧可达 AIDL；
- `accessible_native_aidl.txt`：Native 侧可达 AIDL。

执行差集运算，提取所有低权限可达但未能匹配 Java/Native AIDL 实现的服务。

---

## 输出

| 输出 | 说明 |
|------|------|
| `unresolved_accessible_services.txt` | 实机可达但未匹配到 Java/Native AIDL 实现的服务列表，包含服务名、Descriptor 及原因（`no_aidl_matched` 或 `empty_descriptor`） |

```text
# unresolved_accessible_services.txt
media.camera [android.hardware.ICameraService] [no_aidl_matched]
vendor.custom.daemon [] [empty_descriptor]
```

控制台同时输出对账汇总：

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

---

## 盲区服务的意义

这些服务通常属于：

- 手写 Raw BBinder 实现（无标准 AIDL 接口）；
- Descriptor 为空的匿名服务；
- 实现在未扫描系统 App / APEX 中。

它们是安全研究员进行人工逆向和动态验证的高价值目标，可配合 [AttackSurfaceExplorer](../AttackSurfaceExplorer/README.md) 的 `runner.py` 做进一步验证。

---

## 相关文档

- [ASE 主 README](../README.md)
- [java_analyzer](../java_analyzer/README.md)
- [native_analyzer](../native_analyzer/README.md)
- [diff_analyzer](../diff_analyzer/README.md)
