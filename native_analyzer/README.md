# native_analyzer

Native AIDL 接口扫描模块：从各分区 `lib(64)`、`bin`（含 `bin/hw`）以及 `apex/` 容器中的 ELF 二进制提取 Native Binder 服务。

---

## 使用

```bash
cd native_analyzer
python3 native_analyzer.py <workspace_dir> [--ignore-registered]
```

| 参数 | 说明 |
|------|------|
| `<workspace_dir>` | collector 产出的 dump 目录 |
| `--ignore-registered` | 不按 `service_list.txt` 过滤，输出全部 Native server 接口 |

无需构建、无 Python 第三方依赖。C++ 方法签名还原可选依赖系统 `c++filt`（binutils）或 `llvm-cxxfilt`。

---

## 扫描内容

1. **Descriptor 提取**
   - 标准 AIDL 字符串模式；
   - C++ libbinder 的 UTF-16LE String16 常量（如 `SurfaceFlinger`、`IAudioFlingerService`、`SensorServer`）；
   - 非标准命名接口（如 `ConnectivityNative`）；
   - Rust v0 mangling 符号。

2. **多层服务端判定（解决 Strip 与 `-fno-rtti` 漏报）**
   - C++ Itanium ABI（`{len}Bn{Name}`）；
   - Rust mangling；
   - ELF 动态符号表（`AIBinder_Class_define`、`AServiceManager_addService`、`defaultServiceManager` 等关键系统调用）。

3. **技术栈架构识别（Backend）**
   - 基于 `DT_NEEDED` 依赖库与导出符号，分类为 `libbinder`（旧式私有 C++）、`ndk`（基于 `libbinder_ndk` 的 Stable AIDL）或 `rust`。

4. **APEX 深度扫描与去重**
   - 覆盖 Android 10+ Mainline 模块；
   - 遍历时跳过软链接（Finder 替身），确保二进制去重且仅扫描真实实体。

5. **service_list 交叉引用**
   - 默认仅保留已注册 descriptor；
   - `--ignore-registered` 输出全部 server 接口。

6. **AIDL 方法签名还原**
   - 自动交叉引用 Java 提取的 `service_aidl.txt`；
   - 对纯 Native 接口，解析 ELF 动态符号表中 `Bp{Name}` 客户端代理类导出符号，还原具体 AIDL 业务方法。

7. **onTransact 入口定位**
   - 匹配服务端 `Bn{Name}::onTransact`（C++）或 `on_transact`（Rust）函数虚地址偏移，输出 `[onTransact=0x...]`。

> 若 `c++filt` 与 `llvm-cxxfilt` 都缺失，会告警并跳过方法签名还原，不影响 descriptor 与服务端判定。

---

## 输出

| 输出 | 说明 |
|------|------|
| `native_aidl.txt` | `descriptor [so_path] [service=服务名] [backend=libbinder\|ndk\|rust] [onTransact=0x...]`，包含 AIDL 方法签名；存在 `accessible_services.txt` 时追加 `[accessible=1\|0\|unknown]` |
| `accessible_native_aidl.txt` | 仅 `accessible=1` 的 server 子集（包含 `[service=服务名]`、`[backend=...]`、`[onTransact=0x...]` 与还原的 AIDL 方法，无 accessible 标记） |

```text
# native_aidl.txt
android.ui.ISurfaceComposer [system/lib64/libgui.so] [service=SurfaceFlinger] [backend=libbinder] [onTransact=0xc6be0] [accessible=1]
0xf80d0: android::gui::BpSurfaceComposer::addJankListener(android::sp<android::IBinder> const&, android::sp<android::gui::IJankListener> const&)
0xf8570: android::gui::BpSurfaceComposer::captureDisplay(android::gui::DisplayCaptureArgs const&, android::sp<android::gui::IScreenCaptureListener> const&)
```

```text
# accessible_native_aidl.txt
android.net.connectivity.aidl.ConnectivityNative [apex/com.google.android.tetherin/lib64/libcom.android.tethering.connectivity_native.so] [service=connectivity_native] [backend=ndk]
0x8e00: aidl::android::net::connectivity::aidl::BpConnectivityNative::blockPortForBind(int)
0x8ee8: aidl::android::net::connectivity::aidl::BpConnectivityNative::unblockPortForBind(int)
0x9b64: aidl::android::net::connectivity::aidl::IConnectivityNativeDefault::unblockAllPortsForBind()
0x9ba0: aidl::android::net::connectivity::aidl::IConnectivityNativeDefault::getPortsBlockedForBind(std::vector<int>*)
```

---

## 相关文档

- [ASE 主 README](../README.md)
- [collector](../collector/README.md)
- [post_analyzer](../post_analyzer/README.md)
