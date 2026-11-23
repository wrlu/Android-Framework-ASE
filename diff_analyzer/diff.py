#!/usr/bin/env python3
"""
ASE image diff — compare two ASE dump directories.

Sections:
  components  packages, APK sha256, version/signature, components, permissions
  services    Binder service registry, accessibility, AIDL interfaces
  apex        APEX modules (extracted directories)

The baseline (A) is the reference, the candidate (B) is the new image. Every
"added" entry exists in B only, every "removed" entry exists in A only.

Default output is <candidate>/diff.json. Only JSON is produced.

Usage:
    python3 diff_analyzer/diff.py <baseline> <candidate>
    python3 diff_analyzer/diff.py <baseline> <candidate> -o report.json
    python3 diff_analyzer/diff.py <baseline> <candidate> --ignore-missing
"""

import argparse
import csv
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

SKIP_NAMES = {'.DS_Store'}

COMPONENT_TYPES = ('activity', 'service', 'provider', 'receiver')
AIDL_FILES = (
    ('java', 'service_aidl.txt'),
    ('native', 'native_aidl.txt'),
)
AIDL_FALLBACK_FILES = (
    ('java', 'accessible_service_aidl.txt'),
    ('native', 'accessible_native_aidl.txt'),
)

RES_VERSION_CODE = 0x0101021B
RES_VERSION_NAME = 0x0101021C

ARTIFACTS = {
    'comp': ('package_index.csv', 'all_comp.json', 'accessible_comp.json'),
    'service': ('service_list.txt', 'accessible_services.txt',
                'service_aidl.txt', 'native_aidl.txt'),
    'apex': ('apex', 'apex_index.csv'),
}

SECTIONS = ('comp', 'service', 'apex')


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path):
    if not path.is_file():
        return None
    try:
        with path.open(encoding='utf-8', errors='replace') as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def load_csv(path):
    if not path.is_file():
        return []
    try:
        with path.open(newline='', encoding='utf-8', errors='replace') as handle:
            return list(csv.DictReader(handle))
    except OSError:
        return []


def read_lines(path):
    if not path.is_file():
        return []
    try:
        return path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []


def load_apex_index(dump):
    modules = set()
    for row in load_csv(dump / 'apex_index.csv'):
        name = (row.get('apex_name') or '').strip()
        if name:
            modules.add(name)
    return modules


def apex_missing_modules(dump):
    """Modules listed in apex_index.csv but absent from apex/ (partial pull)."""
    modules = load_apex_index(dump)
    if not modules:
        return set()
    apex_dir = dump / 'apex'
    present = set()
    if apex_dir.is_dir():
        for entry in apex_dir.iterdir():
            if entry.name in SKIP_NAMES:
                continue
            present.add(entry.name)
            present.add(entry.name.split('@')[0])
    return modules - present


def artifact_issue(dump, section, name):
    """Return a human-readable problem for one required artifact, or None."""
    path = dump / name
    if section == 'apex' and name == 'apex':
        if not path.is_dir():
            return 'directory missing'
        if not any(entry.name not in SKIP_NAMES for entry in path.iterdir()):
            return 'directory is empty'
        missing = apex_missing_modules(dump)
        if missing:
            return (f'{len(missing)} module(s) from apex_index.csv have no '
                    f'apex/ directory')
        return None
    if not path.is_file():
        return 'file missing'
    try:
        if path.stat().st_size == 0:
            return 'file is empty'
    except OSError:
        return 'file unreadable'
    if name == 'accessible_services.txt':
        _services, available = parse_accessible_services(read_lines(path))
        if not available:
            return 'not an ASE accessibility probe result'
    return None


def section_missing(dump, section):
    issues = []
    for name in ARTIFACTS[section]:
        issue = artifact_issue(dump, section, name)
        if issue:
            issues.append({'artifact': name, 'reason': issue})
    return issues


def sorted_unique(values):
    return sorted({v for v in values if v is not None})


def dump_label(path):
    return path.name


# --------------------------------------------------------------------------- #
# APK metadata: version / signature / manifest (AXML)
# --------------------------------------------------------------------------- #

def _u8(data, pos):
    """Read an Android UTF-8 string length (1 or 2 bytes)."""
    value = data[pos]
    pos += 1
    if value & 0x80:
        value = ((value & 0x7F) << 8) | data[pos]
        pos += 1
    return value, pos


def _string_pool(data, pos):
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        '<IIIII', data, pos + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from('<%dI' % string_count, data, pos + 28) if string_count else ()
    base = pos + strings_start
    strings = []
    for offset in offsets:
        cursor = base + offset
        if utf8:
            _, cursor = _u8(data, cursor)   # UTF-16 length
            length, cursor = _u8(data, cursor)
            strings.append(data[cursor:cursor + length].decode('utf-8', 'replace'))
        else:
            length = struct.unpack_from('<H', data, cursor)[0]
            cursor += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, cursor)[0]
                cursor += 2
            strings.append(data[cursor:cursor + length * 2].decode('utf-16-le', 'replace'))
    return strings


def parse_axml_manifest(raw):
    """Extract manifest attributes from a binary AndroidManifest.xml."""
    chunk_type, header_size, _size = struct.unpack_from('<HHI', raw, 0)
    if chunk_type != 0x0003:
        raise ValueError('not a binary XML document')

    strings, resource_map = [], []
    pos = header_size
    while pos + 8 <= len(raw):
        chunk_type, chunk_header, chunk_size = struct.unpack_from('<HHI', raw, pos)
        if chunk_size < 8:
            break
        if chunk_type == 0x0001:            # string pool
            strings = _string_pool(raw, pos)
        elif chunk_type == 0x0180:          # resource map
            count = (chunk_size - chunk_header) // 4
            if count:
                resource_map = list(struct.unpack_from('<%dI' % count, raw, pos + chunk_header))
        elif chunk_type == 0x0102:          # start element
            _ns, _name = struct.unpack_from('<II', raw, pos + 16)
            attr_start, attr_size, attr_count = struct.unpack_from('<HHH', raw, pos + 24)
            attrs = pos + 16 + attr_start
            values = {}
            for index in range(attr_count):
                base = attrs + index * attr_size
                _ans, name_idx, raw_idx = struct.unpack_from('<III', raw, base)
                _tsize, _res0, data_type, data_value = struct.unpack_from('<HBBI', raw, base + 12)
                key = strings[name_idx] if name_idx < len(strings) else ''
                resource_id = resource_map[name_idx] if name_idx < len(resource_map) else 0

                value = None
                if data_type == 0x03:           # string reference
                    value = strings[data_value] if data_value < len(strings) else None
                elif data_type in (0x10, 0x11):  # int dec / int hex
                    value = data_value if data_value < 0x80000000 else data_value - 0x100000000
                elif data_type == 0x12:         # boolean
                    value = bool(data_value)
                elif raw_idx != 0xFFFFFFFF and raw_idx < len(strings):
                    value = strings[raw_idx]

                if resource_id == RES_VERSION_CODE or key == 'versionCode':
                    values['versionCode'] = value
                elif resource_id == RES_VERSION_NAME or key == 'versionName':
                    values['versionName'] = value
            return values
        pos += chunk_size
    return {}


class ApkInspector:
    """Resolve versionName/versionCode and signer certificate digests."""

    def __init__(self):
        self.aapt2 = self._find_tool('aapt2')
        self.apksigner = self._find_tool('apksigner')
        self.apkanalyzer = self._find_apkanalyzer()
        self._version_cache = {}
        self._signature_cache = {}

    @staticmethod
    def _sdk_roots():
        roots = []
        for env in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
            value = os.environ.get(env)
            if value:
                roots.append(Path(value))
        roots.append(Path.home() / 'Library' / 'Android' / 'sdk')
        roots.append(Path.home() / 'Android' / 'Sdk')
        return roots

    def _find_tool(self, name):
        for root in self._sdk_roots():
            build_tools = root / 'build-tools'
            if not build_tools.is_dir():
                continue
            versions = sorted((p for p in build_tools.iterdir() if p.is_dir()),
                              key=lambda p: p.name, reverse=True)
            for version in versions:
                candidate = version / name
                if candidate.is_file():
                    return str(candidate)
        return None

    def _find_apkanalyzer(self):
        for root in self._sdk_roots():
            for candidate in (root / 'cmdline-tools' / 'latest' / 'bin' / 'apkanalyzer',
                              root / 'tools' / 'bin' / 'apkanalyzer'):
                if candidate.is_file():
                    return str(candidate)
        return None

    def version(self, apk):
        key = str(apk)
        if key in self._version_cache:
            return self._version_cache[key]

        result = {'versionCode': None, 'versionName': None}
        if self.aapt2:
            result = self._version_aapt2(apk) or result
        if result['versionCode'] is None and result['versionName'] is None and self.apkanalyzer:
            result = self._version_apkanalyzer(apk) or result
        if result['versionCode'] is None and result['versionName'] is None:
            result = self._version_axml(apk) or result

        self._version_cache[key] = result
        return result

    def _version_aapt2(self, apk):
        try:
            proc = subprocess.run([self.aapt2, 'dump', 'badging', str(apk)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, errors='replace', timeout=120)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        code = re.search(r"versionCode='([^']*)'", proc.stdout)
        name = re.search(r"versionName='([^']*)'", proc.stdout)
        if not code and not name:
            return None
        return {
            'versionCode': code.group(1) if code else None,
            'versionName': name.group(1) if name else None,
        }

    def _version_apkanalyzer(self, apk):
        def run(argument):
            try:
                proc = subprocess.run([self.apkanalyzer, 'manifest', argument, str(apk)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, errors='replace', timeout=120)
            except (OSError, subprocess.SubprocessError):
                return None
            return proc.stdout.strip() if proc.returncode == 0 else None

        code = run('version-code')
        name = run('version-name')
        if code is None and name is None:
            return None
        return {'versionCode': code, 'versionName': name}

    @staticmethod
    def _version_axml(apk):
        try:
            with zipfile.ZipFile(apk) as archive:
                raw = archive.read('AndroidManifest.xml')
            values = parse_axml_manifest(raw)
        except (OSError, KeyError, ValueError, zipfile.BadZipFile, struct.error):
            return None
        if not values:
            return None
        return {
            'versionCode': values.get('versionCode'),
            'versionName': values.get('versionName'),
        }

    def signature(self, apk):
        key = str(apk)
        if key in self._signature_cache:
            return self._signature_cache[key]

        if not self.apksigner:
            result = {'certificates': None, 'reason': 'apksigner not found'}
        else:
            try:
                proc = subprocess.run([self.apksigner, 'verify', '--print-certs', str(apk)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, errors='replace', timeout=180)
            except (OSError, subprocess.SubprocessError) as exc:
                result = {'certificates': None, 'reason': f'apksigner failed: {exc}'}
            else:
                certificates = sorted_unique(
                    item.lower() for item in
                    re.findall(r'certificate SHA-256 digest:\s*([0-9a-fA-F]+)', proc.stdout))
                if certificates:
                    result = {'certificates': certificates, 'reason': None}
                else:
                    detail = (proc.stderr or proc.stdout or '').strip().splitlines()
                    result = {
                        'certificates': None,
                        'reason': detail[0] if detail else 'no signer certificate found',
                    }

        self._signature_cache[key] = result
        return result


# --------------------------------------------------------------------------- #
# Components section
# --------------------------------------------------------------------------- #

def collect_apks(dump):
    """package -> {relative apk name: path}."""
    packages_dir = dump / 'packages'
    result = {}
    if not packages_dir.is_dir():
        return result
    for package_dir in sorted(packages_dir.iterdir()):
        if not package_dir.is_dir() or package_dir.name in SKIP_NAMES:
            continue
        files = {}
        for path in sorted(package_dir.rglob('*.apk')):
            if path.is_file():
                files[str(path.relative_to(package_dir))] = path
        if files:
            result[package_dir.name] = files
    return result


def hash_apks(apks, workers):
    """package -> {relative name: sha256}."""
    tasks = []
    for package, files in apks.items():
        for name, path in files.items():
            tasks.append((package, name, path))

    result = {package: {} for package in apks}
    if not tasks:
        return result

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(sha256_file, path): (package, name)
                   for package, name, path in tasks}
        for future in as_completed(futures):
            package, name = futures[future]
            try:
                result[package][name] = future.result()
            except OSError:
                result[package][name] = None
    return result


def load_package_index(dump):
    """package -> {uid, path}."""
    result = {}
    for row in load_csv(dump / 'package_index.csv'):
        name = (row.get('package_name') or '').strip()
        if not name:
            continue
        result[name] = {
            'uid': (row.get('uid') or '').strip(),
            'path': (row.get('path') or '').strip(),
        }
    return result


def load_component_data(dump):
    """package -> {components: [...], defined: [...], filenames: [...]}."""
    result = {}
    data = load_json(dump / 'all_comp.json')
    if not isinstance(data, list):
        return result
    for entry in data:
        if not isinstance(entry, dict):
            continue
        package = entry.get('package')
        if not package:
            continue
        bucket = result.setdefault(
            package, {'components': [], 'defined': [], 'filenames': [],
                      'uses': [], 'protected': []})
        bucket['components'].extend(
            item for item in entry.get('components') or [] if isinstance(item, dict))
        bucket['defined'].extend(
            item for item in entry.get('defined_permissions') or [] if isinstance(item, dict))
        bucket['uses'].extend(
            item for item in entry.get('uses_permissions') or [] if isinstance(item, str))
        bucket['protected'].extend(
            item for item in entry.get('protected_broadcasts') or [] if isinstance(item, str))
        filename = entry.get('filename')
        if filename:
            bucket['filenames'].append(filename)
    return result


def load_accessible_components(dump):
    """(component_type, name) -> issue type ('undefined'/'unprivileged')."""
    result = {}
    data = load_json(dump / 'accessible_comp.json')
    if not isinstance(data, dict):
        return result
    for component_type in COMPONENT_TYPES:
        for entry in data.get(component_type) or []:
            if isinstance(entry, dict) and entry.get('name'):
                name = entry['name']
                package = name.split('/', 1)[0]
                result[(component_type, canonical_component_name(package, name))] = \
                    entry.get('type')
    return result


def collect_permission_files(dump):
    base = dump / 'permissions'
    result = {}
    if not base.is_dir():
        return result
    for path in sorted(base.rglob('*')):
        relative = path.relative_to(base)
        if any(part in SKIP_NAMES for part in relative.parts):
            continue
        if path.is_file():
            result[str(relative)] = sha256_file(path)
    return result


def diff_permission_files(dump_a, dump_b):
    files_a = collect_permission_files(dump_a)
    files_b = collect_permission_files(dump_b)
    added = sorted(set(files_b) - set(files_a))
    removed = sorted(set(files_a) - set(files_b))
    return {'added': added, 'removed': removed}


def load_permission_definitions(dump):
    """Parse permissions/permissions.txt (`pm list permissions -f` style)."""
    path = dump / 'permissions' / 'permissions.txt'
    if not path.is_file():
        return None
    entries = {}
    current = None
    for line in read_lines(path):
        match = re.match(r'^\+\s+permission:(\S+)\s*$', line)
        if match:
            current = {'name': match.group(1), 'package': None, 'protectionLevel': None}
            entries[current['name']] = current
            continue
        if current is None:
            continue
        match = re.match(r'^\s+package:(.*)$', line)
        if match:
            value = match.group(1).strip()
            current['package'] = value if value and value != 'null' else None
            continue
        match = re.match(r'^\s+protectionLevel:(.*)$', line)
        if match:
            value = match.group(1).strip()
            current['protectionLevel'] = value if value and value != 'null' else None
    return entries


def diff_permission_definitions(dump_a, dump_b):
    defs_a = load_permission_definitions(dump_a)
    defs_b = load_permission_definitions(dump_b)
    reasons = []
    if defs_a is None:
        reasons.append({'side': 'baseline', 'artifact': 'permissions/permissions.txt',
                        'reason': 'file missing'})
    if defs_b is None:
        reasons.append({'side': 'candidate', 'artifact': 'permissions/permissions.txt',
                        'reason': 'file missing'})

    result = {
        'available': not reasons,
        'reasons': reasons,
        'summary': None,
        'definitions': {'added': [], 'removed': [], 'changed': []},
        'files': {'added': [], 'removed': [], 'changed': []},
    }
    if reasons:
        return result

    added, removed, changed = [], [], []
    for name in sorted(set(defs_a) | set(defs_b)):
        item_a = defs_a.get(name)
        item_b = defs_b.get(name)
        if item_b and not item_a:
            added.append(item_b)
        elif item_a and not item_b:
            removed.append(item_a)
        elif (item_a['protectionLevel'] != item_b['protectionLevel']
              or item_a['package'] != item_b['package']):
            changed.append({
                'name': name,
                'package': {'from': item_a['package'], 'to': item_b['package']},
                'protectionLevel': {'from': item_a['protectionLevel'],
                                    'to': item_b['protectionLevel']},
            })

    files = diff_permission_files(dump_a, dump_b)
    result['definitions'] = {'added': added, 'removed': removed, 'changed': changed}
    result['files'] = {'added': files['added'], 'removed': files['removed']}
    result['summary'] = {
        'added': len(added), 'removed': len(removed), 'changed': len(changed),
        'files_added': len(files['added']), 'files_removed': len(files['removed']),
    }
    return result


def diff_apk_files(files_a, hashes_a, files_b, hashes_b):
    entries = []
    for name in sorted(set(files_a) | set(files_b)):
        sha_a = hashes_a.get(name)
        sha_b = hashes_b.get(name)
        entries.append({
            'name': name,
            'sha256_a': sha_a,
            'sha256_b': sha_b,
            'changed': sha_a != sha_b,
        })
    return entries


def meaningful_uid_change(uid_a, uid_b):
    """Report a uid change only when it is security-relevant.

    App uids (>= 10000) are reassigned freely on update/reinstall, so a change
    between two app uids carries no signal. A change is meaningful when it
    crosses the system/app boundary (10000) or stays within system uids
    (< 10000, e.g. a package moving between system/priv-app or OEM uids).
    """
    if uid_a == uid_b:
        return False
    try:
        value_a = int(uid_a)
        value_b = int(uid_b)
    except (TypeError, ValueError):
        return True
    if value_a >= 10000 and value_b >= 10000:
        return False
    return True


def canonical_filter(intent_filter):
    """Normalize one intent-filter for stable set comparison."""
    actions = tuple(sorted(set(intent_filter.get('actions') or [])))
    categories = tuple(sorted(set(intent_filter.get('categories') or [])))
    data = set()
    for item in intent_filter.get('data') or []:
        if isinstance(item, dict):
            data.add(tuple(sorted((key, str(value)) for key, value in item.items()
                                  if value not in (None, ''))))
    return actions, categories, tuple(sorted(data))


def filter_to_dict(canonical):
    actions, categories, data = canonical
    return {
        'actions': list(actions),
        'categories': list(categories),
        'data': [dict(item) for item in data],
    }


def component_actions(component):
    actions = set(component.get('actions') or [])
    for intent_filter in component.get('intentFilters') or []:
        actions.update(intent_filter.get('actions') or [])
    return actions


def component_categories(component):
    categories = set()
    for intent_filter in component.get('intentFilters') or []:
        categories.update(intent_filter.get('categories') or [])
    return categories


def component_data(component):
    data = set()
    for intent_filter in component.get('intentFilters') or []:
        _actions, _categories, entries = canonical_filter(intent_filter)
        data.update(entries)
    return data


def canonical_component_name(package, name):
    """Resolve AndroidManifest relative class names to a fully qualified name.

    ``.Foo`` and ``Foo`` are equivalent to ``<package>.Foo``; builds sometimes
    rewrite manifests between the two forms without changing the component.
    """
    if not name or '/' not in name:
        return name
    pkg, _, class_name = name.partition('/')
    if not class_name:
        return name
    if class_name.startswith('.'):
        class_name = pkg + class_name
    elif '.' not in class_name:
        class_name = pkg + '.' + class_name
    return f'{pkg}/{class_name}'


def canonical_path_permissions(component):
    entries = set()
    for item in component.get('path_permission') or []:
        if isinstance(item, dict):
            entries.add(tuple(sorted((key, str(value)) for key, value in item.items()
                                     if value not in (None, ''))))
    return entries


def diff_components(dump_a, dump_b, workers):
    reasons = []
    for side, dump in (('baseline', dump_a), ('candidate', dump_b)):
        for issue in section_missing(dump, 'comp'):
            reasons.append({'side': side, **issue})
    if reasons:
        return {
            'availability': {'available': False, 'reasons': reasons},
            'summary': None,
            'packages': {'added': [], 'removed': [], 'changed': []},
            'components': {
                'added': [], 'removed': [], 'export_changed': [],
                'permission_changed': [], 'provider_permission_changed': [],
                'accessibility_changed': [], 'intent_filter_changed': [],
                'path_permission_changed': [],
            },
            'permissions': {
                'defined_added': [], 'defined_removed': [], 'defined_changed': [],
            },
            'uses_permissions': {'added': [], 'removed': []},
            'protected_broadcasts': {'added': [], 'removed': []},
        }

    apks_a = collect_apks(dump_a)
    apks_b = collect_apks(dump_b)
    hashes_a = hash_apks(apks_a, workers)
    hashes_b = hash_apks(apks_b, workers)

    index_a = load_package_index(dump_a)
    index_b = load_package_index(dump_b)
    comp_a = load_component_data(dump_a)
    comp_b = load_component_data(dump_b)
    acc_a = load_accessible_components(dump_a)
    acc_b = load_accessible_components(dump_b)

    packages = sorted(set(apks_a) | set(apks_b) | set(index_a) | set(index_b)
                      | set(comp_a) | set(comp_b))
    inspector = ApkInspector()

    added, removed, changed = [], [], []
    pending = []
    for package in packages:
        in_a = package in apks_a or package in index_a or package in comp_a
        in_b = package in apks_b or package in index_b or package in comp_b
        if in_b and not in_a:
            added.append({
                'package': package,
                'uid': index_b.get(package, {}).get('uid'),
                'apk': diff_apk_files({}, {}, apks_b.get(package, {}), hashes_b.get(package, {})),
            })
            continue
        if in_a and not in_b:
            removed.append({
                'package': package,
                'uid': index_a.get(package, {}).get('uid'),
                'apk': diff_apk_files(apks_a.get(package, {}), hashes_a.get(package, {}), {}, {}),
            })
            continue

        entry = {'package': package}
        dirty = False

        uid_a = index_a.get(package, {}).get('uid')
        uid_b = index_b.get(package, {}).get('uid')
        if meaningful_uid_change(uid_a, uid_b):
            entry['uid'] = {'from': uid_a, 'to': uid_b}
            dirty = True

        apk_files = diff_apk_files(apks_a.get(package, {}), hashes_a.get(package, {}),
                                   apks_b.get(package, {}), hashes_b.get(package, {}))
        apk_changed = any(item['changed'] for item in apk_files)
        if apk_changed:
            entry['apk'] = {'files': apk_files, 'changed': True}
            dirty = True
            base_a = apks_a.get(package, {}).get('base.apk') or next(
                iter(apks_a.get(package, {}).values()), None)
            base_b = apks_b.get(package, {}).get('base.apk') or next(
                iter(apks_b.get(package, {}).values()), None)
            pending.append((entry, base_a, base_b))

        if dirty:
            changed.append(entry)

    def inspect_pair(item):
        entry, base_a, base_b = item
        version_a = inspector.version(base_a) if base_a else None
        version_b = inspector.version(base_b) if base_b else None
        signature_a = inspector.signature(base_a) if base_a else None
        signature_b = inspector.signature(base_b) if base_b else None
        return entry, version_a, version_b, signature_a, signature_b

    if pending:
        # aapt2/apksigner are separate processes; probing them in parallel keeps
        # large images (hundreds of changed APKs) within a reasonable runtime.
        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as executor:
            for entry, version_a, version_b, signature_a, signature_b in executor.map(
                    inspect_pair, pending):
                if version_a or version_b:
                    entry['version'] = {
                        'from': version_a,
                        'to': version_b,
                        'changed': (
                            (version_a or {}).get('versionCode'),
                            (version_a or {}).get('versionName'),
                        ) != (
                            (version_b or {}).get('versionCode'),
                            (version_b or {}).get('versionName'),
                        ),
                    }
                if signature_a or signature_b:
                    entry['signature'] = {
                        'from': (signature_a or {}).get('certificates'),
                        'to': (signature_b or {}).get('certificates'),
                        'changed': (signature_a or {}).get('certificates')
                        != (signature_b or {}).get('certificates'),
                        'reason': (signature_b or signature_a or {}).get('reason'),
                    }

    # component level
    components_added, components_removed = [], []
    export_changed, permission_changed, provider_permission_changed = [], [], []
    path_permission_changed = []
    accessibility_changed = []

    def component_map(data):
        mapping = {}
        for package, bucket in data.items():
            for component in bucket['components']:
                name = canonical_component_name(package, component.get('name'))
                key = (package, component.get('type'), name)
                if key[1] and key[2]:
                    mapping[key] = component
        return mapping

    map_a = component_map(comp_a)
    map_b = component_map(comp_b)

    # android:enabled="false" components stay in all_comp but are not reachable;
    # drop them from the accessible sets even if an older cache still lists them.
    def disabled_component_keys(mapping):
        return {(key[1], key[2]) for key, component in mapping.items()
                if component.get('enabled') is False}

    disabled_a = disabled_component_keys(map_a)
    disabled_b = disabled_component_keys(map_b)
    acc_a = {key: value for key, value in acc_a.items() if key not in disabled_a}
    acc_b = {key: value for key, value in acc_b.items() if key not in disabled_b}

    for key in sorted(set(map_a) | set(map_b)):
        package, component_type, name = key
        item_a = map_a.get(key)
        item_b = map_b.get(key)
        if item_b and not item_a:
            components_added.append({
                'package': package, 'type': component_type, 'name': name,
                'exported': item_b.get('exported'),
                'permission': item_b.get('permission'),
            })
            continue
        if item_a and not item_b:
            components_removed.append({
                'package': package, 'type': component_type, 'name': name,
                'exported': item_a.get('exported'),
                'permission': item_a.get('permission'),
            })
            continue

        exported_a = item_a.get('exported')
        exported_b = item_b.get('exported')
        if exported_a is not None and exported_b is not None and exported_a != exported_b:
            export_changed.append({
                'package': package, 'type': component_type, 'name': name,
                'from': exported_a, 'to': exported_b,
            })

        permission_a = item_a.get('permission')
        permission_b = item_b.get('permission')
        if permission_a != permission_b:
            permission_changed.append({
                'package': package, 'type': component_type, 'name': name,
                'from': permission_a, 'to': permission_b,
            })

        if component_type == 'provider':
            read_a, read_b = item_a.get('readPermission'), item_b.get('readPermission')
            write_a, write_b = item_a.get('writePermission'), item_b.get('writePermission')
            if read_a != read_b or write_a != write_b:
                provider_permission_changed.append({
                    'package': package, 'name': name,
                    'read': {'from': read_a, 'to': read_b},
                    'write': {'from': write_a, 'to': write_b},
                })

        path_a = canonical_path_permissions(item_a)
        path_b = canonical_path_permissions(item_b)
        if path_a != path_b:
            path_permission_changed.append({
                'package': package, 'name': name,
                'added': [dict(item) for item in sorted(path_b - path_a)],
                'removed': [dict(item) for item in sorted(path_a - path_b)],
            })

    for key in sorted(set(acc_a) | set(acc_b)):
        component_type, name = key
        issue_a = acc_a.get(key)
        issue_b = acc_b.get(key)
        if issue_a != issue_b:
            accessibility_changed.append({
                'type': component_type, 'name': name,
                'from': issue_a, 'to': issue_b,
            })

    # intent-filter / action changes on components present on both sides
    intent_filter_changed = []
    for key in sorted(set(map_a) & set(map_b)):
        package, component_type, name = key
        item_a = map_a[key]
        item_b = map_b[key]
        filters_a = {canonical_filter(item) for item in item_a.get('intentFilters') or []}
        filters_b = {canonical_filter(item) for item in item_b.get('intentFilters') or []}
        actions_a = component_actions(item_a)
        actions_b = component_actions(item_b)
        categories_a = component_categories(item_a)
        categories_b = component_categories(item_b)
        data_a = component_data(item_a)
        data_b = component_data(item_b)

        entry = {'package': package, 'type': component_type, 'name': name}
        removed_filters = filters_a - filters_b
        added_filters = filters_b - filters_a
        if removed_filters:
            entry['filters_removed'] = [filter_to_dict(item) for item in sorted(removed_filters)]
        if added_filters:
            entry['filters_added'] = [filter_to_dict(item) for item in sorted(added_filters)]
        if actions_b - actions_a:
            entry['actions_added'] = sorted(actions_b - actions_a)
        if actions_a - actions_b:
            entry['actions_removed'] = sorted(actions_a - actions_b)
        if categories_b - categories_a:
            entry['categories_added'] = sorted(categories_b - categories_a)
        if categories_a - categories_b:
            entry['categories_removed'] = sorted(categories_a - categories_b)
        if data_b - data_a:
            entry['data_added'] = [dict(item) for item in sorted(data_b - data_a)]
        if data_a - data_b:
            entry['data_removed'] = [dict(item) for item in sorted(data_a - data_b)]
        if len(entry) > 3:
            intent_filter_changed.append(entry)

    # uses-permissions / protected-broadcasts on packages present on both sides
    uses_added, uses_removed = [], []
    protected_added, protected_removed = [], []
    for package in sorted(set(comp_a) & set(comp_b)):
        uses_a = set(comp_a[package].get('uses') or [])
        uses_b = set(comp_b[package].get('uses') or [])
        uses_added.extend({'package': package, 'permission': value}
                          for value in sorted(uses_b - uses_a))
        uses_removed.extend({'package': package, 'permission': value}
                            for value in sorted(uses_a - uses_b))

        protected_a = set(comp_a[package].get('protected') or [])
        protected_b = set(comp_b[package].get('protected') or [])
        protected_added.extend({'package': package, 'action': value}
                               for value in sorted(protected_b - protected_a))
        protected_removed.extend({'package': package, 'action': value}
                                 for value in sorted(protected_a - protected_b))

    # permission definitions
    defined_added, defined_removed, defined_changed = [], [], []

    def defined_map(data):
        mapping = {}
        for package, bucket in data.items():
            for item in bucket['defined']:
                name = item.get('name')
                if name:
                    mapping[(package, name)] = item.get('protectionLevel')
        return mapping

    defs_a = defined_map(comp_a)
    defs_b = defined_map(comp_b)
    for key in sorted(set(defs_a) | set(defs_b)):
        package, name = key
        level_a = defs_a.get(key)
        level_b = defs_b.get(key)
        if level_b is not None and level_a is None:
            defined_added.append({'package': package, 'name': name, 'protectionLevel': level_b})
        elif level_a is not None and level_b is None:
            defined_removed.append({'package': package, 'name': name, 'protectionLevel': level_a})
        elif level_a != level_b:
            defined_changed.append({
                'package': package, 'name': name,
                'from': level_a, 'to': level_b,
            })

    newly_exported = sum(1 for item in export_changed if item['to'] is True)
    newly_hidden = sum(1 for item in export_changed if item['to'] is False)
    newly_accessible = sum(1 for item in accessibility_changed if item['from'] is None)
    no_longer_accessible = sum(1 for item in accessibility_changed if item['to'] is None)

    return {
        'availability': {'available': True, 'reasons': []},
        'summary': {
            'packages': {
                'baseline': len(set(apks_a) | set(index_a) | set(comp_a)),
                'candidate': len(set(apks_b) | set(index_b) | set(comp_b)),
                'added': len(added), 'removed': len(removed), 'changed': len(changed),
            },
            'components': {
                'baseline': len(map_a), 'candidate': len(map_b),
                'added': len(components_added), 'removed': len(components_removed),
                'newly_exported': newly_exported, 'newly_hidden': newly_hidden,
                'permission_changed': len(permission_changed),
                'provider_permission_changed': len(provider_permission_changed),
                'newly_accessible': newly_accessible,
                'no_longer_accessible': no_longer_accessible,
                'intent_filter_changed': len(intent_filter_changed),
                'path_permission_changed': len(path_permission_changed),
                'uses_permissions_added': len(uses_added),
                'uses_permissions_removed': len(uses_removed),
                'protected_broadcasts_added': len(protected_added),
                'protected_broadcasts_removed': len(protected_removed),
            },
        },
        'packages': {'added': added, 'removed': removed, 'changed': changed},
        'components': {
            'added': components_added,
            'removed': components_removed,
            'export_changed': export_changed,
            'permission_changed': permission_changed,
            'provider_permission_changed': provider_permission_changed,
            'accessibility_changed': accessibility_changed,
            'intent_filter_changed': intent_filter_changed,
            'path_permission_changed': path_permission_changed,
        },
        'permissions': {
            'defined_added': defined_added,
            'defined_removed': defined_removed,
            'defined_changed': defined_changed,
        },
        'uses_permissions': {'added': uses_added, 'removed': uses_removed},
        'protected_broadcasts': {'added': protected_added, 'removed': protected_removed},
    }


# --------------------------------------------------------------------------- #
# Services section
# --------------------------------------------------------------------------- #

def parse_service_list(lines):
    services = {}
    for line in lines:
        match = re.match(r'^(\d+)\s+(.+?):\s*\[(.*)\]\s*$', line.strip())
        if match:
            services[match.group(2).strip()] = match.group(3).strip()
    return services


def parse_accessible_services(lines):
    """Return (service -> bool, available).

    Older dumps may store a plain service list in accessible_services.txt; such a
    file is not an accessibility probe result and must not be treated as "all 0".
    """
    services = {}
    matched = 0
    for line in lines:
        match = re.search(r'service=(.*?),\s*accessible=(\d+)', line)
        if match:
            services[match.group(1).strip()] = match.group(2) == '1'
            matched += 1
    return services, matched > 0


def iter_aidl_blocks(path):
    """Yield (header, [method lines]) blocks separated by blank lines."""
    if not path.is_file():
        return
    header = None
    methods = []
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


def parse_aidl_header(header):
    descriptor = header.strip().split()[0] if header.strip() else ''
    brackets = re.findall(r'\[([^\]]*)\]', header)
    impl = None
    shared_objects = []
    tags = {}
    for item in brackets:
        if '=' in item:
            key, value = item.split('=', 1)
            tags[key.strip()] = value.strip()
        elif '/' in item:
            shared_objects = [part.strip() for part in item.split(',') if part.strip()]
        elif item.strip():
            impl = item.strip()
    return descriptor, impl, shared_objects, tags


def load_aidl(dump):
    """Return (service -> {(kind, descriptor): block}, available)."""
    sources = [(kind, dump / name) for kind, name in AIDL_FILES]
    available = any(path.is_file() for _kind, path in sources)
    if not available:
        sources = [(kind, dump / name) for kind, name in AIDL_FALLBACK_FILES]
        available = any(path.is_file() for _kind, path in sources)

    result = {}
    for kind, path in sources:
        for header, methods in iter_aidl_blocks(path):
            descriptor, impl, shared_objects, tags = parse_aidl_header(header)
            service_tag = tags.get('service')
            if not service_tag:
                continue
            # One interface can be registered under several service names,
            # e.g. [service=android.hardware.drm.IDrmFactory/clearkey, .../widevine].
            services = [item.strip() for item in service_tag.split(',') if item.strip()]
            key = (kind, descriptor)
            # Native AIDL method lines are prefixed with a build-specific address
            # (0x...:); strip it so only the signature participates in the diff.
            normalized_methods = [
                re.sub(r'^0x[0-9a-fA-F]+:\s*', '', method.strip())
                for method in methods
            ]
            block = {
                'kind': kind,
                'descriptor': descriptor,
                'impl': impl,
                'so': shared_objects,
                'backend': [part.strip() for part in tags.get('backend', '').split(',')
                            if part.strip()],
                'on_transact': [part.strip() for part in tags.get('onTransact', '').split(',')
                                if part.strip()],
                'methods': sorted(set(normalized_methods)),
                'accessible': tags.get('accessible'),
            }
            for service in services:
                result.setdefault(service, {}).setdefault(key, block)
    return result, available and bool(result)


def diff_services(dump_a, dump_b):
    registry_a = parse_service_list(read_lines(dump_a / 'service_list.txt'))
    registry_b = parse_service_list(read_lines(dump_b / 'service_list.txt'))
    access_a, access_avail_a = parse_accessible_services(
        read_lines(dump_a / 'accessible_services.txt'))
    access_b, access_avail_b = parse_accessible_services(
        read_lines(dump_b / 'accessible_services.txt'))
    aidl_a, aidl_avail_a = load_aidl(dump_a)
    aidl_b, aidl_avail_b = load_aidl(dump_b)

    registry_available = bool(registry_a) and bool(registry_b)
    accessibility_available = access_avail_a and access_avail_b
    aidl_available = aidl_avail_a and aidl_avail_b

    names = sorted(set(registry_a) | set(registry_b) | set(aidl_a) | set(aidl_b))
    added, removed, accessibility_changed = [], [], []

    if registry_available:
        for name in names:
            registered_a = name in registry_a
            registered_b = name in registry_b
            if registered_b and not registered_a:
                added.append({
                    'name': name,
                    'descriptor': registry_b.get(name),
                    'accessible': access_b.get(name) if accessibility_available else None,
                    'aidl': sorted({descriptor for _kind, descriptor in aidl_b.get(name, {})}),
                })
            elif registered_a and not registered_b:
                removed.append({
                    'name': name,
                    'descriptor': registry_a.get(name),
                    'accessible': access_a.get(name) if accessibility_available else None,
                    'aidl': sorted({descriptor for _kind, descriptor in aidl_a.get(name, {})}),
                })

    if accessibility_available:
        for name in names:
            accessible_a = access_a.get(name)
            accessible_b = access_b.get(name)
            if accessible_a != accessible_b:
                accessibility_changed.append({
                    'name': name, 'from': accessible_a, 'to': accessible_b,
                })

    interfaces_added, interfaces_removed, interfaces_changed = [], [], []
    if aidl_available:
        for name in names:
            blocks_a = aidl_a.get(name, {})
            blocks_b = aidl_b.get(name, {})
            for key in sorted(set(blocks_a) | set(blocks_b)):
                kind, descriptor = key
                block_a = blocks_a.get(key)
                block_b = blocks_b.get(key)
                if block_b and not block_a:
                    interfaces_added.append({
                        'service': name, 'kind': kind, 'descriptor': descriptor,
                        'impl': block_b.get('impl'),
                    })
                    continue
                if block_a and not block_b:
                    interfaces_removed.append({
                        'service': name, 'kind': kind, 'descriptor': descriptor,
                        'impl': block_a.get('impl'),
                    })
                    continue

                methods_a = set(block_a.get('methods') or [])
                methods_b = set(block_b.get('methods') or [])
                changes = {}
                if block_a.get('kind') != block_b.get('kind'):
                    changes['kind_changed'] = {
                        'from': block_a.get('kind'), 'to': block_b.get('kind')}
                if block_a.get('impl') != block_b.get('impl'):
                    changes['impl'] = {'from': block_a.get('impl'), 'to': block_b.get('impl')}
                if block_a.get('so') != block_b.get('so'):
                    changes['so'] = {'from': block_a.get('so'), 'to': block_b.get('so')}
                if block_a.get('backend') != block_b.get('backend'):
                    changes['backend'] = {
                        'from': block_a.get('backend'), 'to': block_b.get('backend')}
                methods_added = sorted(methods_b - methods_a)
                methods_removed = sorted(methods_a - methods_b)
                if methods_added:
                    changes['methods_added'] = methods_added
                if methods_removed:
                    changes['methods_removed'] = methods_removed
                if changes:
                    interfaces_changed.append({
                        'service': name, 'kind': kind, 'descriptor': descriptor, **changes,
                    })

    newly_accessible = sum(1 for item in accessibility_changed
                           if item['from'] is False and item['to'] is True)
    newly_blocked = sum(1 for item in accessibility_changed
                        if item['from'] is True and item['to'] is False)

    reasons = []
    for side, dump in (('baseline', dump_a), ('candidate', dump_b)):
        for issue in section_missing(dump, 'service'):
            reasons.append({'side': side, **issue})

    return {
        'availability': {
            'registry': registry_available,
            'accessibility': accessibility_available,
            'aidl': aidl_available,
            'reasons': reasons,
        },
        'summary': {
            'services': {
                'baseline': len(set(registry_a) | set(aidl_a)),
                'candidate': len(set(registry_b) | set(aidl_b)),
                'added': len(added) if registry_available else None,
                'removed': len(removed) if registry_available else None,
                'newly_accessible': newly_accessible if accessibility_available else None,
                'newly_blocked': newly_blocked if accessibility_available else None,
            },
            'interfaces': {
                'added': len(interfaces_added) if aidl_available else None,
                'removed': len(interfaces_removed) if aidl_available else None,
                'changed': len(interfaces_changed) if aidl_available else None,
            },
        },
        'services': {
            'added': added,
            'removed': removed,
            'accessibility_changed': accessibility_changed,
        },
        'interfaces': {
            'added': interfaces_added,
            'removed': interfaces_removed,
            'changed': interfaces_changed,
        },
    }


# --------------------------------------------------------------------------- #
# APEX section
# --------------------------------------------------------------------------- #

def apex_version(manifest):
    """Read field 2 (version) from apex_manifest.pb without protobuf deps."""
    if not manifest.is_file():
        return None
    try:
        data = manifest.read_bytes()
    except OSError:
        return None

    def varint(buffer, index):
        value = shift = 0
        while index < len(buffer):
            byte = buffer[index]
            index += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value, index
        raise ValueError('truncated varint')

    index = 0
    version = None
    try:
        while index < len(data):
            tag, index = varint(data, index)
            field, wire_type = tag >> 3, tag & 7
            if wire_type == 0:
                value, index = varint(data, index)
                if field == 2:
                    version = value
            elif wire_type == 2:
                length, index = varint(data, index)
                index += length
            elif wire_type == 5:
                index += 4
            elif wire_type == 1:
                index += 8
            else:
                break
    except (ValueError, IndexError):
        return version
    return version


def apex_tree(base):
    """Deterministic digest plus per-file records for an extracted APEX.

    Some dumps contain a duplicated nested directory named after the module
    (an adb pull artifact, e.g. <module>/<module>/lib64/...). The duplicate
    prefix is stripped so the same module compares equal across dumps.
    """
    module = base.name
    files = {}
    entries = []
    for path in sorted(base.rglob('*')):
        relative = path.relative_to(base)
        parts = relative.parts
        if any(part in SKIP_NAMES for part in parts):
            continue
        if any(part == 'lost+found' for part in parts):
            continue
        if len(parts) > 1 and parts[0] == module:
            relative = Path(*parts[1:])
        name = str(relative)
        if name in files:
            continue
        if path.is_symlink():
            target = os.readlink(path)
            files[name] = {'symlink': target}
            entries.append(f'{name}\0link:{target}')
        elif path.is_file():
            digest = sha256_file(path)
            files[name] = {'sha256': digest, 'size': path.stat().st_size}
            entries.append(f'{name}\0{digest}')
    tree = hashlib.sha256('\n'.join(entries).encode('utf-8')).hexdigest()
    return tree, files


def collect_apex(dump):
    apex_dir = dump / 'apex'
    result = {}
    if not apex_dir.is_dir():
        return result
    for path in sorted(apex_dir.iterdir()):
        if path.name in SKIP_NAMES:
            continue
        if path.is_dir():
            result[path.name] = path
    return result


def diff_apex(dump_a, dump_b):
    reasons = []
    for side, dump in (('baseline', dump_a), ('candidate', dump_b)):
        for issue in section_missing(dump, 'apex'):
            reasons.append({'side': side, **issue})
    if reasons:
        return {
            'availability': {'available': False, 'reasons': reasons},
            'summary': None,
            'apex': {'added': [], 'removed': []},
        }

    apex_a = collect_apex(dump_a)
    apex_b = collect_apex(dump_b)

    added, removed = [], []
    changed_count = 0
    for name in sorted(set(apex_a) | set(apex_b)):
        if name in apex_b and name not in apex_a:
            tree, files = apex_tree(apex_b[name])
            added.append({
                'name': name,
                'version': apex_version(apex_b[name] / 'apex_manifest.pb'),
                'digest': tree,
                'files': {'added': sorted(files), 'removed': []},
                'signature': {'certificates': None,
                              'reason': 'apex container not captured'},
            })
            continue
        if name in apex_a and name not in apex_b:
            tree, files = apex_tree(apex_a[name])
            removed.append({
                'name': name,
                'version': apex_version(apex_a[name] / 'apex_manifest.pb'),
                'digest': tree,
                'files': {'added': [], 'removed': sorted(files)},
                'signature': {'certificates': None,
                              'reason': 'apex container not captured'},
            })
            continue

        digest_a, _ = apex_tree(apex_a[name])
        digest_b, _ = apex_tree(apex_b[name])
        version_a = apex_version(apex_a[name] / 'apex_manifest.pb')
        version_b = apex_version(apex_b[name] / 'apex_manifest.pb')
        # Module-level changes are counted but not expanded: version/digest churn
        # carries no direct security signal.
        if digest_a != digest_b or version_a != version_b:
            changed_count += 1

    return {
        'availability': {'available': True, 'reasons': []},
        'summary': {
            'apex': {
                'baseline': len(apex_a), 'candidate': len(apex_b),
                'added': len(added), 'removed': len(removed), 'changed': changed_count,
            },
        },
        'apex': {'added': added, 'removed': removed},
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    os.replace(temporary, path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='ase_diff',
        description='Compare two ASE dump directories and write diff.json.')
    parser.add_argument('baseline', help='baseline (old) ASE dump directory')
    parser.add_argument('candidate', help='candidate (new) ASE dump directory')
    parser.add_argument('-o', '--output',
                        help='output path (default: <candidate>/diff.json)')
    parser.add_argument('--workers', type=int, default=8,
                        help='hashing worker threads (default: 8)')
    parser.add_argument('--quiet', action='store_true', help='do not print the summary')
    parser.add_argument('--ignore-missing', action='store_true',
                        help='continue when one side is missing required artifacts '
                             '(affected sections are marked unavailable)')
    args = parser.parse_args(argv)

    baseline = Path(os.path.expanduser(args.baseline)).resolve()
    candidate = Path(os.path.expanduser(args.candidate)).resolve()
    for label, path in (('baseline', baseline), ('candidate', candidate)):
        if not path.is_dir():
            parser.error(f'{label} is not a directory: {path}')

    output = Path(os.path.expanduser(args.output)).resolve() if args.output \
        else candidate / 'diff.json'

    report = {
        'schema_version': 1,
        'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
        'baseline': {'path': str(baseline), 'label': dump_label(baseline)},
        'candidate': {'path': str(candidate), 'label': dump_label(candidate)},
    }

    missing = []
    for section in SECTIONS:
        for side, dump in (('baseline', baseline), ('candidate', candidate)):
            for issue in section_missing(dump, section):
                missing.append({'section': section, 'side': side, **issue})
    for side, dump in (('baseline', baseline), ('candidate', candidate)):
        if not (dump / 'permissions' / 'permissions.txt').is_file():
            missing.append({'section': 'permissions', 'side': side,
                            'artifact': 'permissions/permissions.txt',
                            'reason': 'file missing'})

    if missing and not args.ignore_missing:
        print('error: missing ASE artifacts, aborting '
              '(use --ignore-missing to continue):', file=sys.stderr)
        for item in missing:
            print(f"  {item['side']}: {item['section']}: "
                  f"{item['artifact']} ({item['reason']})", file=sys.stderr)
        return 2
    if missing:
        report['missing_artifacts'] = missing

    report['components'] = diff_components(baseline, candidate, args.workers)
    report['permissions'] = diff_permission_definitions(baseline, candidate)
    report['services'] = diff_services(baseline, candidate)
    report['apex'] = diff_apex(baseline, candidate)

    write_json(output, report)

    if not args.quiet:
        print(f'ASE image diff')
        print(f'  baseline:  {baseline}')
        print(f'  candidate: {candidate}')
        if not report['components']['availability']['available']:
            print('  components: unavailable, skipped (missing artifacts)')
        else:
            component_summary = report['components']['summary']
            packages = component_summary['packages']
            components = component_summary['components']
            print(f"  packages:  {packages['baseline']} -> {packages['candidate']} "
                  f"(+{packages['added']} / -{packages['removed']})")
            print(f"  components:{components['baseline']} -> {components['candidate']} "
                  f"(+{components['added']} / -{components['removed']})")
            print(f"  newly exported:   {components['newly_exported']}")
            print(f"  newly accessible: {components['newly_accessible']}")
            print(f"  intent filters changed: {components['intent_filter_changed']}")
            print(f"  uses-permissions:      +{components['uses_permissions_added']} "
                  f"/ -{components['uses_permissions_removed']}")
            print(f"  protected-broadcasts:  +{components['protected_broadcasts_added']} "
                  f"/ -{components['protected_broadcasts_removed']}")

        permissions = report['permissions']
        if not permissions['available']:
            print('  permissions: unavailable, skipped (missing artifacts)')
        else:
            permission_summary = permissions['summary']
            print(f"  permissions: +{permission_summary['added']} "
                  f"/ -{permission_summary['removed']} "
                  f"/ ~{permission_summary['changed']}")

        service_summary = report['services']['summary']
        availability = report['services']['availability']
        services = service_summary['services']
        if not availability['registry']:
            print('  services: unavailable, skipped (missing artifacts)')
        else:
            print(f"  services:  {services['baseline']} -> {services['candidate']} "
                  f"(+{services['added']} / -{services['removed']})")
        if availability['accessibility']:
            print(f"  newly accessible services: {services['newly_accessible']}")
        else:
            print('  accessibility: unavailable on one side, skipped')
        if availability['aidl']:
            interfaces = service_summary['interfaces']
            print(f"  interfaces: +{interfaces['added']} / -{interfaces['removed']} "
                  f"/ ~{interfaces['changed']}")
        else:
            print('  AIDL: unavailable on one side, skipped')

        if not report['apex']['availability']['available']:
            print('  apex: unavailable, skipped (missing artifacts)')
        else:
            apex_summary = report['apex']['summary']['apex']
            print(f"  apex:      {apex_summary['baseline']} -> {apex_summary['candidate']} "
                  f"(+{apex_summary['added']} / -{apex_summary['removed']} "
                  f"/ ~{apex_summary['changed']})")
        print(f'  wrote: {output}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
