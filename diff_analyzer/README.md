# diff_analyzer

比较两个已完成分析的 ASE dump，输出镜像差异报告。默认写入：

```text
<candidate>/diff.json
```

用于回答：新固件新增/删除了哪些包、组件、权限、Binder 接口，以及哪些实现类方法体发生了变化。

---

## 使用

```bash
# 全量差异（packages + permissions + binder + apex + 类方法体）
python3 diff_analyzer/diff.py <baseline_dump> <candidate_dump>

# 指定输出路径
python3 diff_analyzer/diff.py <baseline_dump> <candidate_dump> -o report.json

# 某侧产物缺失时仍继续（对应区段标记 unavailable，退出码 0）
python3 diff_analyzer/diff.py <baseline_dump> <candidate_dump> --ignore-missing
```

| 参数 | 说明 |
|------|------|
| `baseline` | 基线（旧）dump 目录 |
| `candidate` | 候选（新）dump 目录 |
| `-o, --output` | 输出路径（默认 `<candidate>/diff.json`） |
| `--workers` | APK 哈希线程数（默认 8） |
| `--quiet` | 不打印终端摘要 |
| `--ignore-missing` | 产物缺失时继续，受影响区段标记 `unavailable` |

---

## 输入与前置条件

两个目录都应是已完成 `collector`、`java_analyzer`、`native_analyzer`、`post_analyzer` 的 ASE dump。

类级方法体检测依赖 `java_analyzer` 构建的 helper：

```bash
cd java_analyzer && ./gradlew shadowJar
# 产物：build/libs/analyzer-1.0.0-all.jar
```

默认 `-Xmx4g`，可用环境变量调整：

```bash
ASE_CLASS_DIFF_XMX=8g python3 diff_analyzer/diff.py <baseline> <candidate>
```

### 缺失产物策略

默认情况下，任一侧缺少所请求区段所需的产物会直接报错退出（exit 2），避免把“没跑分析”误判为“组件/接口全删”：

- 空文件按缺失处理；
- APEX 还会用 `apex_index.csv` 校验模块是否真正落盘；
- 不对 `system/framework/*.jar` 或 APEX 内 `javalib` 做 sha256。

只有显式 `--ignore-missing` 才会继续；对应区段标记为不可用（`packages` / `binder` / `apex` 的 `availability.available=false`，`permissions.available=false`），缺失项记录在 `reasons` / 顶层 `missing_artifacts`。

---

## 输出结构

```text
schema_version
generated_at
files
packages
permissions
binder
apex
```

```json
"files": {
  "baseline": "/path/to/baseline_dump",
  "candidate": "/path/to/candidate_dump"
}
```

---

### packages

```json
"packages": {
  "availability": {"available": true, "reasons": []},
  "added": ["com.example.new"],
  "removed": ["com.example.old"],
  "uid_changed": [
    {"package": "com.example", "value": "1000", "old": "10123"}
  ],
  "changed": [
    {
      "package": "com.example",
      "uses_permissions_added": ["android.permission.CAMERA"],
      "uses_permissions_removed": [],
      "protected_broadcasts_added": [],
      "protected_broadcasts_removed": [],
      "unresolved_classes": [],
      "components": {
        "added": ["com.example/com.example.New"],
        "removed": [],
        "changed": ["com.example/com.example.Svc"],
        "newly_exported": ["com.example/com.example.New"],
        "newly_hidden": [],
        "permission_changed": [],
        "provider_permission_changed": [],
        "newly_accessible": [],
        "no_longer_accessible": [],
        "intent_filter_changed": [],
        "path_permission_changed": []
      }
    }
  ]
}
```

- `added` / `removed`：只列包名。
- `uid_changed`：只记录跨 `10000`（系统/应用 UID 分界）或双方都 `< 10000` 的变化；双方都 `>= 10000` 的应用 UID 重分配忽略。字段为 `value`（当前 UID）和 `old`（旧 UID）。
- 包内 `components`：组件变化分类，值为名字数组。
- 包级 `uses_permissions_*` / `protected_broadcasts_*` / `unresolved_classes` 与 `components` 平级。
- `added` / `removed` 包不展开组件明细；下游需按包名回查候选/基线的 `all_comp.json`。

#### components 分类

| 字段 | 含义 |
|------|------|
| `added` / `removed` | 组件新增/删除 |
| `changed` | 任一组件属性变化 |
| `newly_exported` / `newly_hidden` | `exported` 变为 true/false |
| `permission_changed` | 组件 `android:permission` 变化 |
| `provider_permission_changed` | provider 读/写权限变化 |
| `newly_accessible` / `no_longer_accessible` | 最终可达性状态变化 |
| `intent_filter_changed` | intent-filter/action/category/data 变化 |
| `path_permission_changed` | provider `path_permission` 变化 |

`enabled="false"` 组件仍保留在 `all_comp.json`，但不计入 `accessible_comp.json`，diff 也不会把它视为 accessible。

---

### permissions

```json
"permissions": {
  "available": true,
  "reasons": [],
  "definitions": {
    "added": ["android.permission.NEW_PERMISSION"],
    "removed": ["com.example.OLD_PERMISSION"],
    "changed": [
      {
        "name": "android.permission.EXECUTE_APP_FUNCTIONS",
        "protectionLevel": {
          "value": "normal",
          "old": "internal|privileged|knownSigner"
        }
      }
    ]
  }
}
```

- `definitions.added` / `removed`：只列权限名。
- `definitions.changed`：只列出实际变化字段，使用 `value`（当前）和 `old`（旧值）。
- 不再输出 `summary` / `files`。

---

### binder

```json
"binder": {
  "availability": {
    "registry": true,
    "accessibility": true,
    "aidl": true,
    "reasons": []
  },
  "added": ["app_interaction"],
  "removed": ["selection_toolbar"],
  "newly_accessible": ["app_interaction"],
  "newly_blocked": [],
  "unresolved_classes": [],
  "changed": [
    {
      "name": "activity_task",
      "type": "java",
      "descriptor": "android.app.IActivityTaskManager",
      "impl": {
        "name": "com.android.server.wm.ActivityTaskManagerService",
        "status": "body_changed"
      },
      "methods_added": ["..."],
      "methods_removed": ["..."]
    }
  ]
}
```

- `added` / `removed`：只列服务注册名，不展开接口/方法。
- `newly_accessible` / `newly_blocked`：最终可达性状态集合，包含新增可达、变更可达、移除不可达、变更不可达；不等同于单纯的 `False→True` / `True→False`。
- `changed`：接口级明细，不再带冗余的 `status` 字段。
- 已有服务上的接口新增/删除也进入 `changed`，通过 `methods_added` / `methods_removed` 表达；AIDL 签名未变但 `impl` 类方法体发生变化的 Java 接口（纯 `body_changed`）同样进入 `changed`，且不输出 `methods_added` / `methods_removed`。
- `type`：`java` / `native`；native 条目没有 `impl`。
- `impl.status`：`body_changed` / `unchanged` / `added` / `removed` / `unresolved`；impl 类被替换时额外输出 `old`；若薄壳内部类（如 `$BinderService` / `$Stub`）本身未变但其外部类（enclosing class）方法体发生变化，也会标为 `body_changed` 并额外输出 `enclosing` 指向发生变化的外部类。
- Native 接口的 `.so` / `backend` 变化：

```json
"so": {"value": ["system/lib64/libfoo.so"], "old": ["vendor/lib64/libfoo.so"]},
"backend": {"value": ["ndk"], "old": ["libbinder"]}
```

- `onTransact` 地址不参与比较；方法名中的地址前缀会被归一化。
- `binder.summary` 已移除。

---

### apex

```json
"apex": {
  "availability": {"available": true, "reasons": []},
  "apex": {
    "added": [
      {
        "name": "com.example.module",
        "version": 1,
        "digest": "...",
        "files": {"added": ["..."], "removed": []}
      }
    ],
    "removed": []
  }
}
```

- 只展开 APEX 模块新增/删除；共同模块的 version/digest 变化不展开、不计数。
- 不再输出 `signature` / `summary`。

---

## 类级方法体差异

类差异不单独输出 `bytecode`，而是并入 `packages` 与 `binder`：

- 组件类按 `all_comp.json` 的声明类解析（activity-alias 用 `targetActivity`）；若内部类组件本身未变，但方法体中实际引用了其外部类（调用外部类方法或访问外部类字段）且该外部类发生变化，也会记入变更；
- 组件新增/删除时，类状态固定为 `added` / `removed`（即使该类在另一侧已存在）；只有两侧都存在的组件才比较方法体；
- Binder impl 类来自 `service_aidl.txt`，所有 impl 都执行真实类检测；有 `methods_added/removed` 也不跳过；
- 内部类 `$` / `.` 自动归一化；只输出变化和无解析结果，未变化的类不展开。

指纹只包含：

- 方法签名；
- 归一化指令（归并 `/range`、`/2addr`、`/lit8`、`/lit16`、`const-string/jumbo`、`goto/*`、`const/*`、`const-wide/*` 等编码宽度变体，跳过 `nop` 与寄存器间 `move*`）、规范化引用（归一化 `$$ExternalSynthetic*`、`lambda$...$N`、`access$N`、`$r8$*`、`-$$Nest$*` 合成符号）、字面量（Android `0x01`/`0x7f` 资源 ID 归一化为 `#RES`）、分支/switch keys、try/catch；
- 排除 debug 信息、地址、寄存器、synthetic 方法（`lambda$`、`$$ExternalSynthetic`、`access$`、`$r8$`、`-$$Nest$`）；
- 字段、注解、类继承关系等结构变化不计入。

APK sha256 只在运行期用于判断包是否变化、跳过未变包的类检测，不写入最终 `diff.json`。

---

## 下游使用约定

- `packages.added/removed`：按包名回查候选/基线 `all_comp.json`、`package_index.csv`。
- `packages.changed[].components`：组件名为 `package/Class`；类型与完整属性可在 `all_comp.json` 按名字查。
- `binder.added/removed`：按服务注册名回查 `service_list.txt`、`service_aidl.txt`、`native_aidl.txt`。
- `binder.changed`：直接包含接口/方法/impl 明细。
- 不要只查 `accessible_comp.json`：它只包含弱权限可达组件，会漏掉非导出/受保护组件。

---

## 相关文档

- [ASE 主 README](../README.md)
- [java_analyzer](../java_analyzer/README.md)
- [collector](../collector/README.md)
- [native_analyzer](../native_analyzer/README.md)
- [post_analyzer](../post_analyzer/README.md)
