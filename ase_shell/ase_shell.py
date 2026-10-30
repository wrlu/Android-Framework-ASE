#!/usr/bin/env python3
"""
ASE dump shell — interactive framework for exploring ASE output directories.

No search commands are implemented yet; the command set is built incrementally
in adb style and will be extended separately. Currently implemented: `pm`
(list/uninstall) and `service` (list), plus the framework commands `help` and
`quit`.

Add a command with the @command decorator:

    @command('example', summary='...', usage='example <arg>')
    def cmd_example(ctx: Context, argv: List[str]) -> None:
        ...

Handlers receive (ctx, argv), where argv is the shlex-split argument list with
the command name removed. Raise CommandError for user-facing failures. Commands
must resolve paths through ctx.resolve() so they stay inside ASE artifacts.

Scope: the shell is meant to expose only artifacts produced by this project
(collector + analyzers), not arbitrary files in the dump directory.
"""

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

try:
    import readline
except ImportError:  # readline is available on macOS/Linux; keep a fallback
    readline = None


# --------------------------------------------------------------------------- #
# ASE artifact scope (framework helper; commands should use ctx.resolve)
# --------------------------------------------------------------------------- #

ASE_TOP_FILES = {
    'accessible_comp.json',
    'accessible_native_aidl.txt',
    'accessible_service_aidl.txt',
    'accessible_services.txt',
    'all_comp.json',
    'apex_index.csv',
    'getprop.txt',
    'lshal.txt',
    'native_aidl.txt',
    'netstat.txt',
    'overlay_index.csv',
    'package_index.csv',
    'service_aidl.txt',
    'service_list.txt',
    'settings_global.txt',
    'settings_secure.txt',
    'settings_system.txt',
    'unresolved_accessible_services.txt',
}

ASE_TOP_DIRS = {
    'apex',
    'init',
    'odm',
    'overlay',
    'packages',
    'permissions',
    'product',
    'selinux',
    'system',
    'system_ext',
    'vendor',
}


# --------------------------------------------------------------------------- #
# Framework
# --------------------------------------------------------------------------- #

class CommandError(Exception):
    """User-facing command failure."""


class ExitShell(Exception):
    """Raised by the quit command to leave the REPL."""


@dataclass
class Context:
    """Shared state passed to every command."""

    root: Path
    debug: bool = False
    cwd: Path = field(init=False)
    cache: Dict[str, object] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.root = self.root.resolve()
        self.cwd = self.root

    # -- path helpers ------------------------------------------------------ #

    @staticmethod
    def _normalize(path: Path) -> Path:
        """Lexically normalize (resolve '..' but never follow symlinks)."""
        return Path(os.path.normpath(os.path.abspath(str(path))))

    def rel(self, path: Path) -> str:
        try:
            rel = self._normalize(path).relative_to(self.root)
        except ValueError:
            return str(path)
        text = str(rel)
        return '.' if text in ('', '.') else text

    def is_allowed(self, path: Path) -> bool:
        path = self._normalize(path)
        if path == self.root:
            return True
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return False
        parts = rel.parts
        if not parts:
            return True
        if len(parts) == 1:
            return parts[0] in ASE_TOP_FILES or parts[0] in ASE_TOP_DIRS
        return parts[0] in ASE_TOP_DIRS

    def resolve(self, arg: str, base: Optional[Path] = None) -> Path:
        raw = Path(os.path.expanduser(arg))
        candidate = raw if raw.is_absolute() else (base or self.cwd) / raw
        path = self._normalize(candidate)
        if not self.is_allowed(path):
            raise CommandError(f'path is outside the ASE dump artifacts: {arg}')
        return path

    # -- cached data helpers (for future commands) ------------------------- #

    def load_json(self, name: str):
        key = f'json:{name}'
        if key not in self.cache:
            path = self.root / name
            data = None
            if path.is_file():
                try:
                    data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
                except (OSError, json.JSONDecodeError):
                    data = None
            self.cache[key] = data
        return self.cache[key]

    def load_csv(self, name: str) -> List[dict]:
        key = f'csv:{name}'
        if key not in self.cache:
            path = self.root / name
            rows: List[dict] = []
            if path.is_file():
                try:
                    with path.open(newline='', encoding='utf-8', errors='replace') as handle:
                        rows = list(csv.DictReader(handle))
                except OSError:
                    rows = []
            self.cache[key] = rows
        return self.cache[key]

    def services(self) -> List[dict]:
        key = 'services'
        if key not in self.cache:
            result: List[dict] = []
            path = self.root / 'service_list.txt'
            if path.is_file():
                for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                    text = line.strip()
                    if not text or text.startswith('Found'):
                        continue
                    match = re.match(r'^(\d+)\s+(.+?):\s*\[(.*)\]\s*$', text)
                    if match:
                        result.append({
                            'index': match.group(1),
                            'name': match.group(2).strip(),
                            'descriptor': match.group(3).strip(),
                        })
            self.cache[key] = result
        return self.cache[key]

    def accessible_services(self) -> Dict[str, bool]:
        key = 'accessible_services'
        if key not in self.cache:
            result: Dict[str, bool] = {}
            path = self.root / 'accessible_services.txt'
            if path.is_file():
                for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                    match = re.search(r'service=(.*?),\s*accessible=(\d+)', line)
                    if match:
                        result[match.group(1).strip()] = match.group(2) == '1'
            self.cache[key] = result
        return self.cache[key]

    def clear_cache(self) -> None:
        self.cache.clear()


@dataclass
class Command:
    name: str
    aliases: Tuple[str, ...]
    summary: str
    usage: str
    handler: Callable[[Context, List[str]], None]


REGISTRY: Dict[str, Command] = {}
ALIASES: Dict[str, Command] = {}


def command(name: str, *, aliases: Sequence[str] = (), summary: str = '',
            usage: Optional[str] = None):
    def decorator(func: Callable[[Context, List[str]], None]):
        cmd = Command(name=name, aliases=tuple(aliases), summary=summary,
                      usage=usage or name, handler=func)
        REGISTRY[name] = cmd
        for alias in aliases:
            ALIASES[alias] = cmd
        return func
    return decorator


def lookup(name: str) -> Optional[Command]:
    return REGISTRY.get(name) or ALIASES.get(name)


# --------------------------------------------------------------------------- #
# Framework commands only (no domain/search commands yet)
# --------------------------------------------------------------------------- #

@command('help', aliases=('?',), summary='Show help (all commands or one command)',
         usage='help [command]')
def cmd_help(ctx: Context, argv: List[str]) -> None:
    if argv:
        target = lookup(argv[0])
        if target is None:
            raise CommandError(f'unknown command: {argv[0]}')
        print(f'{target.name} — {target.summary}')
        print(f'usage: {target.usage}')
        if target.aliases:
            print(f'aliases: {", ".join(target.aliases)}')
        return

    if not REGISTRY:
        print('no commands registered')
        return
    print('Commands:')
    for name in sorted(REGISTRY):
        cmd = REGISTRY[name]
        alias_text = f' ({", ".join(cmd.aliases)})' if cmd.aliases else ''
        print(f'  {name:<12}{cmd.summary}{alias_text}')


@command('quit', aliases=('exit', 'q'), summary='Exit the shell')
def cmd_quit(ctx: Context, argv: List[str]) -> None:
    if argv:
        raise CommandError('usage: quit')
    raise ExitShell()


# --------------------------------------------------------------------------- #
# pm — package management (adb-style)
# --------------------------------------------------------------------------- #

PACKAGE_NAME_RE = re.compile(r'^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$')

MAX_DETAIL_LINES = 200


@command('pm', summary='Package management (mimics adb pm)',
         usage='pm list [package] | pm list packages [filter] | pm uninstall <package>')
def cmd_pm(ctx: Context, argv: List[str]) -> None:
    if not argv:
        raise CommandError('usage: pm <list|uninstall> ...')
    subcommand, rest = argv[0], argv[1:]
    if subcommand == 'list':
        pm_list(ctx, rest)
    elif subcommand == 'uninstall':
        pm_uninstall(ctx, rest)
    else:
        raise CommandError(f'unknown pm subcommand: {subcommand} (expected list|uninstall)')


def package_names(ctx: Context) -> List[str]:
    names = set()
    for row in ctx.load_csv('package_index.csv'):
        name = (row.get('package_name') or '').strip()
        if name:
            names.add(name)
    if not names:
        data = ctx.load_json('all_comp.json')
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('package'):
                    names.add(item['package'])
    return sorted(names)


def package_index_row(ctx: Context, package: str) -> Optional[dict]:
    for row in ctx.load_csv('package_index.csv'):
        if (row.get('package_name') or '').strip() == package:
            return row
    return None


def package_component_entry(ctx: Context, package: str) -> Optional[dict]:
    data = ctx.load_json('all_comp.json')
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get('package') == package:
                return item
    return None


def package_flagged_entries(ctx: Context, package: str) -> List[Tuple[str, dict]]:
    data = ctx.load_json('accessible_comp.json')
    result: List[Tuple[str, dict]] = []
    if isinstance(data, dict):
        prefix = package + '/'
        for component_type in ('activity', 'service', 'provider', 'receiver'):
            for entry in data.get(component_type) or []:
                if isinstance(entry, dict) and str(entry.get('name', '')).startswith(prefix):
                    result.append((component_type, entry))
    return result


def pm_list(ctx: Context, argv: List[str]) -> None:
    # adb-compatible form: pm list packages [filter]
    if argv and argv[0] == 'packages':
        if len(argv) > 2:
            raise CommandError('usage: pm list packages [filter]')
        substring = argv[1] if len(argv) == 2 else ''
        names = [name for name in package_names(ctx) if substring in name]
        for name in names:
            print(f'package:{name}')
        return

    if not argv:
        for name in package_names(ctx):
            print(f'package:{name}')
        return

    if len(argv) != 1:
        raise CommandError('usage: pm list [package] | pm list packages [filter]')

    package = argv[0]
    row = package_index_row(ctx, package)
    entry = package_component_entry(ctx, package)
    flagged = package_flagged_entries(ctx, package)
    local_dir = ctx.root / 'packages' / package
    if row is None and entry is None and not flagged and not local_dir.is_dir():
        raise CommandError(f'package not found: {package}')

    print(f'package: {package}')
    print(f'  uid:    {row.get("uid", "?") if row else "?"}')
    print(f'  device: {row.get("path", "?") if row else "?"}')
    print(f'  local:  {ctx.rel(local_dir)}{"" if local_dir.is_dir() else "  (missing)"}')

    if isinstance(entry, dict):
        filename = entry.get('filename')
        if filename:
            print(f'  apk:    {filename}')
        components = entry.get('components') or []
        counts: Dict[str, int] = {}
        for component in components:
            counts[component.get('type', '?')] = counts.get(component.get('type', '?'), 0) + 1
        count_text = ', '.join(f'{key}={value}' for key, value in sorted(counts.items())) or '-'
        print(f'  components ({len(components)}): {count_text}')
        for component in components[:MAX_DETAIL_LINES]:
            component_type = component.get('type', '?')
            permission = component.get('permission') or ''
            extra = ''
            if component_type == 'provider':
                read = component.get('readPermission') or ''
                write = component.get('writePermission') or ''
                if read or write:
                    extra = f' read={read or "-"} write={write or "-"}'
            suffix = f' permission={permission}' if permission else ''
            print(f'    {component_type:<9} {component.get("name", "")}{suffix}{extra}')
        if len(components) > MAX_DETAIL_LINES:
            print(f'    ... (+{len(components) - MAX_DETAIL_LINES} more)')

        defined = entry.get('defined_permissions') or []
        if defined:
            print(f'  defined permissions ({len(defined)}):')
            for item in defined[:MAX_DETAIL_LINES]:
                print(f'    {item.get("name", "")} ({item.get("protectionLevel", "")})')
            if len(defined) > MAX_DETAIL_LINES:
                print(f'    ... (+{len(defined) - MAX_DETAIL_LINES} more)')

        uses = entry.get('uses_permissions') or []
        if uses:
            print(f'  uses permissions ({len(uses)}):')
            for item in uses[:MAX_DETAIL_LINES]:
                print(f'    {item}')
            if len(uses) > MAX_DETAIL_LINES:
                print(f'    ... (+{len(uses) - MAX_DETAIL_LINES} more)')
    else:
        print('  components: (not found in all_comp.json)')

    if flagged:
        print(f'  flagged components ({len(flagged)}):')
        for component_type, item in flagged:
            print(f'    [{item.get("type", "?")}] {component_type} {item.get("name", "")}')
    else:
        print('  flagged components: none')


def pm_uninstall(ctx: Context, argv: List[str]) -> None:
    if len(argv) != 1:
        raise CommandError('usage: pm uninstall <package>')

    package = argv[0]
    if not PACKAGE_NAME_RE.match(package):
        raise CommandError(f'invalid package name: {package}')

    row = package_index_row(ctx, package)
    entry = package_component_entry(ctx, package)
    flagged = package_flagged_entries(ctx, package)
    package_dir = ctx.root / 'packages' / package
    has_dir = package_dir.is_dir()

    if row is None and entry is None and not flagged and not has_dir:
        raise CommandError(f'package not found: {package}')

    print(f'Uninstall {package} from {ctx.root}:')
    if has_dir:
        print(f'  - remove directory {ctx.rel(package_dir)}')
    if row is not None:
        print('  - remove row from package_index.csv')
    if entry is not None:
        print('  - remove entry from all_comp.json')
    if flagged:
        print(f'  - remove {len(flagged)} component(s) from accessible_comp.json')

    if has_dir:
        shutil.rmtree(package_dir)
    if row is not None:
        remove_csv_rows(ctx.root / 'package_index.csv', 'package_name', package)
    if entry is not None:
        remove_json_array_entry(
            ctx.root / 'all_comp.json',
            lambda item: isinstance(item, dict) and item.get('package') == package)
    if flagged:
        remove_accessible_components(ctx.root / 'accessible_comp.json', package)

    ctx.clear_cache()
    print(f'uninstalled {package}')


def remove_csv_rows(path: Path, column: str, value: str) -> bool:
    if not path.is_file():
        return False
    try:
        with path.open(newline='', encoding='utf-8', errors='replace') as handle:
            rows = list(csv.reader(handle))
    except OSError:
        return False
    if not rows:
        return False
    header = rows[0]
    try:
        index = header.index(column)
    except ValueError:
        return False
    kept = [row for row in rows[1:] if len(row) <= index or row[index] != value]
    if len(kept) == len(rows) - 1:
        return False
    write_atomic(path, lambda handle: csv.writer(handle).writerows([header] + kept))
    return True


def remove_json_array_entry(path: Path, predicate) -> bool:
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, list):
        return False
    kept = [item for item in data if not predicate(item)]
    if len(kept) == len(data):
        return False
    write_json(path, kept)
    return True


def remove_accessible_components(path: Path, package: str) -> int:
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(data, dict):
        return 0
    prefix = package + '/'
    removed = 0
    for key, value in list(data.items()):
        if not isinstance(value, list):
            continue
        kept = [item for item in value
                if not (isinstance(item, dict) and str(item.get('name', '')).startswith(prefix))]
        removed += len(value) - len(kept)
        data[key] = kept
    if removed:
        write_json(path, data)
    return removed


def write_atomic(path: Path, writer) -> None:
    temp = path.with_name(path.name + '.tmp')
    with temp.open('w', encoding='utf-8', newline='') as handle:
        writer(handle)
    os.replace(temp, path)


def write_json(path: Path, data) -> None:
    def dump(handle):
        json.dump(data, handle, ensure_ascii=False, separators=(',', ':'))
    write_atomic(path, dump)


# --------------------------------------------------------------------------- #
# service — system services (adb-style `service list`)
# --------------------------------------------------------------------------- #

def iter_aidl_blocks(path: Path):
    """Yield (header, method_lines) blocks separated by blank lines."""
    if not path.is_file():
        return
    header: Optional[str] = None
    methods: List[str] = []
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not raw.strip():
            if header is not None:
                yield header, methods
            header, methods = None, []
        elif header is None:
            header = raw.rstrip()
        else:
            methods.append(raw.rstrip())
    if header is not None:
        yield header, methods


def parse_header(header: str) -> Tuple[str, List[str]]:
    match = re.match(r'^\s*(\S+)\s*(.*)$', header)
    descriptor = match.group(1) if match else header.strip()
    return descriptor, re.findall(r'\[([^\]]*)\]', header)


def bracket_tags(brackets: Sequence[str]) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for item in brackets:
        if '=' in item:
            key, value = item.split('=', 1)
            tags[key.strip()] = value.strip()
    return tags


def bracket_impl(brackets: Sequence[str]) -> str:
    for item in brackets:
        if '=' not in item and '/' not in item:
            return item.strip()
    return ''


def bracket_sos(brackets: Sequence[str]) -> str:
    for item in brackets:
        if '/' in item:
            return item.strip()
    return ''


def service_blocks(ctx: Context, name: str) -> List[dict]:
    blocks: List[dict] = []
    seen = set()
    sources = [
        ('java', 'service_aidl.txt'),
        ('java', 'accessible_service_aidl.txt'),
        ('native', 'native_aidl.txt'),
        ('native', 'accessible_native_aidl.txt'),
    ]
    for kind, filename in sources:
        for header, methods in iter_aidl_blocks(ctx.root / filename):
            descriptor, brackets = parse_header(header)
            if bracket_tags(brackets).get('service') != name:
                continue
            key = (descriptor,
                   tuple(item for item in brackets if not item.startswith('accessible=')))
            if key in seen:
                continue
            seen.add(key)
            blocks.append({
                'kind': kind,
                'descriptor': descriptor,
                'brackets': brackets,
                'methods': methods,
            })
    return blocks


@command('service', summary='System services (mimics adb service list)',
         usage='service list [service]')
def cmd_service(ctx: Context, argv: List[str]) -> None:
    if not argv or argv[0] != 'list':
        raise CommandError('usage: service list [service]')
    rest = argv[1:]
    if not rest:
        services = ctx.services()
        print(f'Found {len(services)} services:')
        for service in services:
            print(f"{service['index']}\t{service['name']}: [{service['descriptor']}]")
        return
    if len(rest) != 1:
        raise CommandError('usage: service list [service]')
    service_detail(ctx, rest[0])


def service_detail(ctx: Context, name: str) -> None:
    entry = next((service for service in ctx.services() if service['name'] == name), None)
    accessible = ctx.accessible_services().get(name)
    blocks = service_blocks(ctx, name)
    if entry is None and accessible is None and not blocks:
        raise CommandError(f'unknown service: {name}')

    print(f'service: {name}')
    descriptor = entry['descriptor'] if entry else ''
    if not descriptor and blocks:
        descriptor = blocks[0]['descriptor']
    print(f'  descriptor: {descriptor or "?"}')
    if accessible is True:
        print('  accessible: 1')
    elif accessible is False:
        print('  accessible: 0')
    else:
        print('  accessible: unknown')

    if not blocks:
        print('  AIDL: no matching implementation in ASE output')
        return
    for block in blocks:
        print(f"  {block['kind']} AIDL:")
        print(f"    descriptor: {block['descriptor']}")
        if block['kind'] == 'java':
            impl = bracket_impl(block['brackets'])
            if impl:
                print(f'    impl: {impl}')
        else:
            sos = bracket_sos(block['brackets'])
            if sos:
                print(f'    so: {sos}')
            tags = bracket_tags(block['brackets'])
            for key in ('backend', 'onTransact'):
                if key in tags:
                    print(f'    {key}: {tags[key]}')
        methods = block['methods']
        print(f'    methods ({len(methods)}):')
        for method in methods:
            print(f'      {method}')


# --------------------------------------------------------------------------- #
# REPL
# --------------------------------------------------------------------------- #

def make_prompt(ctx: Context) -> str:
    rel = ctx.rel(ctx.cwd)
    where = '' if rel == '.' else f'/{rel}'
    return f'ase{where}> '


def dispatch(ctx: Context, line: str) -> None:
    text = line.strip()
    if not text:
        return
    try:
        argv = shlex.split(text)
    except ValueError as exc:
        print(f'parse error: {exc}', file=sys.stderr)
        return
    if not argv:
        return
    cmd = lookup(argv[0])
    if cmd is None:
        print(f'unknown command: {argv[0]}', file=sys.stderr)
        return
    try:
        cmd.handler(ctx, argv[1:])
    except ExitShell:
        raise
    except CommandError as exc:
        print(f'error: {exc}', file=sys.stderr)
    except KeyboardInterrupt:
        print('interrupted', file=sys.stderr)
    except BrokenPipeError:
        raise
    except Exception as exc:  # keep the REPL alive
        if ctx.debug:
            traceback.print_exc()
        else:
            print(f'error: {exc} (use --debug for traceback)', file=sys.stderr)


def make_completer():
    def completer(text: str, state: int):
        buffer = readline.get_line_buffer() if readline else ''
        if ' ' not in buffer.rstrip():
            options = [name for name in sorted(REGISTRY) if name.startswith(text)]
        else:
            options = []
        return options[state] if state < len(options) else None
    return completer


def run_repl(ctx: Context, history_path: Optional[Path]) -> None:
    if readline is not None:
        readline.set_completer(make_completer())
        readline.set_completer_delims(' \t\n')
        readline.parse_and_bind('tab: complete')
        readline.set_history_length(1000)
        if history_path:
            try:
                readline.read_history_file(str(history_path))
            except (FileNotFoundError, OSError):
                pass

    print(f'ASE dump shell  |  {ctx.root}')
    print('Type `help` for commands, `quit` to exit.')
    try:
        while True:
            try:
                line = input(make_prompt(ctx))
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue
            try:
                dispatch(ctx, line)
            except ExitShell:
                break
    finally:
        if readline is not None and history_path:
            try:
                history_path.parent.mkdir(parents=True, exist_ok=True)
                readline.write_history_file(str(history_path))
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='ase_shell',
        description='Interactive framework for ASE dump directories.')
    parser.add_argument('dump', nargs='?', default='.',
                        help='ASE dump directory (default: current directory)')
    parser.add_argument('-c', '--command', action='append', default=[],
                        help='run command(s) non-interactively and exit (repeatable)')
    parser.add_argument('--history-file', default='~/.ase_shell_history',
                        help='readline history file (default: ~/.ase_shell_history)')
    parser.add_argument('--no-history', action='store_true', help='do not read/write history')
    parser.add_argument('--debug', action='store_true', help='show tracebacks on errors')
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    root = Path(os.path.expanduser(args.dump))
    if not root.is_dir():
        print(f'error: not a directory: {root}', file=sys.stderr)
        return 2

    ctx = Context(root=root, debug=args.debug)

    history_path = None
    if not args.no_history and args.history_file:
        history_path = Path(os.path.expanduser(args.history_file))

    if args.command:
        try:
            for line in args.command:
                dispatch(ctx, line)
        except ExitShell:
            pass
        return 0

    try:
        run_repl(ctx, history_path)
    except BrokenPipeError:
        return 0
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
