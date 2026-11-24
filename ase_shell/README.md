# ase_shell

针对 ASE dump 目录的交互式检索框架，交互风格模仿 gdb。

当前提供 REPL、命令注册、命令名 Tab 补全、历史记录，以及仅限 ASE 产物的路径范围校验。

---

## 使用

```bash
python3 ase_shell/ase_shell.py <dump_dir>
```

| 参数 | 说明 |
|------|------|
| `dump` | ASE dump 目录（默认当前目录） |
| `-c, --command` | 非交互执行命令后退出，可重复 |
| `--history-file` | readline 历史文件（默认 `~/.ase_shell_history`） |
| `--no-history` | 不读写历史 |
| `--debug` | 出错时打印 traceback |

示例：

```bash
python3 ase_shell/ase_shell.py ~/firmware/pixel8
python3 ase_shell/ase_shell.py ~/firmware/pixel8 -c 'service list activity'
```

---

## 当前命令

| 命令 | 说明 |
|------|------|
| `help` / `?` | 查看全部命令或单个命令帮助 |
| `quit` / `exit` / `q` | 退出 |
| `pm list` / `pm list packages [filter]` | 列出包（`package:<name>`） |
| `pm list <package>` | 显示包详情（APK、组件、问题组件、权限） |
| `pm uninstall <package>` | 删除本地 `packages/<package>/` 及对应记录（`package_index.csv`、`all_comp.json`、`accessible_comp.json`） |
| `service list` | 列出全部系统服务（`Found N services:`，格式仿 adb） |
| `service list <service>` | 显示单个服务信息：descriptor、可访问性、Java/Native AIDL（impl/so、backend、onTransact、展开的方法签名） |

新增命令：

```python
@command('example', summary='...', usage='example <arg>')
def cmd_example(ctx, argv):
    ...
```

命令内通过 `ctx.resolve()` 取路径，确保只访问 ASE 产物。

---

## 相关文档

- [ASE 主 README](../README.md)
- [diff_analyzer](../diff_analyzer/README.md)
