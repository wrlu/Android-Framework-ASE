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
import shutil
import subprocess
import sys
import tempfile
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
    """Set of package names from package_index.csv."""
    result = set()
    for row in load_csv(dump / 'package_index.csv'):
        name = (row.get('package_name') or '').strip()
        if name:
            result.add(name)
    return result


def load_package_uids(dump):
    """package -> uid from package_index.csv."""
    result = {}
    for row in load_csv(dump / 'package_index.csv'):
        name = (row.get('package_name') or '').strip()
        if name:
            result[name] = (row.get('uid') or '').strip()
    return result


def meaningful_uid_change(uid_a, uid_b):
    """Report a uid change only when it crosses the system/app boundary."""
    if uid_a == uid_b:
        return False
    try:
        value_a = int(uid_a)
        value_b = int(uid_b)
    except (TypeError, ValueError):
        return True
    return not (value_a >= 10000 and value_b >= 10000)


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
        'definitions': {'added': [], 'removed': [], 'changed': []},
    }
    if reasons:
        return result

    added, removed, changed = [], [], []
    for name in sorted(set(defs_a) | set(defs_b)):
        item_a = defs_a.get(name)
        item_b = defs_b.get(name)
        if item_b and not item_a:
            added.append(name)
        elif item_a and not item_b:
            removed.append(name)
        elif (item_a['protectionLevel'] != item_b['protectionLevel']
              or item_a['package'] != item_b['package']):
            entry = {'name': name}
            if item_a['package'] != item_b['package']:
                entry['package'] = {'value': item_b['package'], 'old': item_a['package']}
            if item_a['protectionLevel'] != item_b['protectionLevel']:
                entry['protectionLevel'] = {
                    'value': item_b['protectionLevel'],
                    'old': item_a['protectionLevel'],
                }
            changed.append(entry)

    result['definitions'] = {'added': added, 'removed': removed, 'changed': changed}
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
            'uid_changed': [],
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
    uids_a = load_package_uids(dump_a)
    uids_b = load_package_uids(dump_b)
    comp_a = load_component_data(dump_a)
    comp_b = load_component_data(dump_b)
    acc_a = load_accessible_components(dump_a)
    acc_b = load_accessible_components(dump_b)

    packages = sorted(set(apks_a) | set(apks_b) | set(index_a) | set(index_b)
                      | set(comp_a) | set(comp_b))
    added, removed, changed = [], [], []
    uid_changed = []
    for package in packages:
        in_a = package in apks_a or package in index_a or package in comp_a
        in_b = package in apks_b or package in index_b or package in comp_b
        if in_b and not in_a:
            added.append({
                'package': package,
                'apk': diff_apk_files({}, {}, apks_b.get(package, {}), hashes_b.get(package, {})),
            })
            continue
        if in_a and not in_b:
            removed.append({
                'package': package,
                'apk': diff_apk_files(apks_a.get(package, {}), hashes_a.get(package, {}), {}, {}),
            })
            continue

        entry = {'package': package}
        dirty = False

        uid_a = uids_a.get(package)
        uid_b = uids_b.get(package)
        if meaningful_uid_change(uid_a, uid_b):
            uid_changed.append({'package': package, 'value': uid_b, 'old': uid_a})

        apk_files = diff_apk_files(apks_a.get(package, {}), hashes_a.get(package, {}),
                                   apks_b.get(package, {}), hashes_b.get(package, {}))
        apk_changed = any(item['changed'] for item in apk_files)
        if apk_changed:
            # Kept only for the runtime skip decision; stripped before output.
            entry['apk'] = {'files': apk_files, 'changed': True}
            dirty = True

        if dirty:
            changed.append(entry)

    uid_changed.sort(key=lambda item: item['package'])

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
        'uid_changed': uid_changed,
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
            'apex': {'added': [], 'removed': []},
        }

    apex_a = collect_apex(dump_a)
    apex_b = collect_apex(dump_b)

    added, removed = [], []
    for name in sorted(set(apex_a) | set(apex_b)):
        if name in apex_b and name not in apex_a:
            tree, files = apex_tree(apex_b[name])
            added.append({
                'name': name,
                'version': apex_version(apex_b[name] / 'apex_manifest.pb'),
                'digest': tree,
                'files': {'added': sorted(files), 'removed': []},
            })
            continue
        if name in apex_a and name not in apex_b:
            tree, files = apex_tree(apex_a[name])
            removed.append({
                'name': name,
                'version': apex_version(apex_a[name] / 'apex_manifest.pb'),
                'digest': tree,
                'files': {'added': [], 'removed': sorted(files)},
            })
            continue

    return {
        'availability': {'available': True, 'reasons': []},
        'apex': {'added': added, 'removed': removed},
    }


# --------------------------------------------------------------------------- #
# Bytecode class diff (component classes / Binder Impl classes)
# --------------------------------------------------------------------------- #

CLASS_DIFF_ENTRY = 'net.wrlu.android.ase.classdiff.ClassDiffMain'
CLASS_DIFF_JAR = (Path(__file__).resolve().parent.parent
                  / 'java_analyzer' / 'build' / 'libs' / 'analyzer-1.0.0-all.jar')


def load_component_targets(dump):
    """(package, type, canonical name) -> {component, filename}."""
    result = {}
    data = load_json(dump / 'all_comp.json')
    if not isinstance(data, list):
        return result
    for entry in data:
        if not isinstance(entry, dict):
            continue
        package = entry.get('package')
        filename = entry.get('filename')
        for component in entry.get('components') or []:
            if not isinstance(component, dict):
                continue
            name = canonical_component_name(package, component.get('name'))
            if name:
                result[(package, component.get('type'), name)] = {
                    'component': component,
                    'filename': filename,
                }
    return result


def load_service_impls(dump):
    """Java Binder implementation classes from service_aidl.txt."""
    result = set()
    for line in read_lines(dump / 'service_aidl.txt'):
        if not line.strip() or line.startswith(' '):
            continue
        for item in re.findall(r'\[([^\]]*)\]', line):
            value = item.strip()
            if '=' not in value and '/' not in value and value and value != 'null':
                result.add(value)
    return result


def diff_bytecode(baseline, candidate, components_result=None):
    """Compare component classes and Binder Impl classes between two dumps."""
    result = {
        'available': False,
        'error': None,
        'components': None,
        'binder_impl': None,
    }
    if not (baseline / 'all_comp.json').is_file() or not (candidate / 'all_comp.json').is_file():
        result['error'] = 'all_comp.json missing'
        return result

    java = shutil.which('java')
    if not java:
        result['error'] = 'java not found'
        return result
    if not CLASS_DIFF_JAR.is_file():
        result['error'] = f'analyzer jar not found: {CLASS_DIFF_JAR}'
        return result

    baseline_components = load_component_targets(baseline)
    candidate_components = load_component_targets(candidate)
    allowed_packages = None
    if components_result:
        allowed_packages = set()
        for status in ('added', 'removed'):
            for item in components_result['packages'][status]:
                allowed_packages.add(item['package'])
        for item in components_result['packages']['changed']:
            if (item.get('apk') or {}).get('changed'):
                allowed_packages.add(item['package'])
    targets = {}
    for key in sorted(set(baseline_components) | set(candidate_components)):
        if allowed_packages is not None and key[0] not in allowed_packages:
            continue
        package, component_type, name = key
        in_baseline = key in baseline_components
        in_candidate = key in candidate_components
        entry = candidate_components.get(key) or baseline_components[key]
        component = entry['component']
        target = component.get('targetActivity')
        if target:
            target = target.replace('/', '.')
        else:
            target = name.split('/', 1)[-1].replace('$', '.')
        if not target:
            continue
        score = 2 if target.startswith(package + '.') else 0
        if target not in targets:
            targets[target] = {
                'package': package,
                'type': component_type,
                'className': target,
                'apkHint': entry.get('filename') or '',
                'inBaseline': in_baseline,
                'inCandidate': in_candidate,
                'score': score,
            }
        else:
            targets[target]['inBaseline'] = targets[target]['inBaseline'] or in_baseline
            targets[target]['inCandidate'] = targets[target]['inCandidate'] or in_candidate
            if score > targets[target]['score']:
                targets[target].update({
                    'package': package,
                    'type': component_type,
                    'apkHint': entry.get('filename') or '',
                    'score': score,
                })

    baseline_impls = load_service_impls(baseline)
    candidate_impls = load_service_impls(candidate)
    binder_impl = [
        {'className': name, 'inBaseline': True, 'inCandidate': True}
        for name in sorted(baseline_impls | candidate_impls)
    ]

    request = {
        'baselineRoot': str(baseline),
        'candidateRoot': str(candidate),
        'body': True,
        'components': [
            {key: value for key, value in item.items() if key != 'score'}
            for item in targets.values()
        ],
        'binderImpl': binder_impl,
    }

    xmx = os.environ.get('ASE_CLASS_DIFF_XMX', '4g')
    with tempfile.TemporaryDirectory(prefix='ase_classdiff_') as tmp:
        request_path = Path(tmp) / 'request.json'
        response_path = Path(tmp) / 'response.json'
        request_path.write_text(json.dumps(request), encoding='utf-8')
        try:
            proc = subprocess.run(
                [java, f'-Xmx{xmx}', '-cp', str(CLASS_DIFF_JAR), CLASS_DIFF_ENTRY,
                 str(request_path), str(response_path)],
                capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.SubprocessError) as exc:
            result['error'] = f'class diff failed: {exc}'
            return result
        if not response_path.is_file():
            detail = (proc.stderr or '').strip().splitlines()
            result['error'] = detail[-1] if detail else f'class diff exited {proc.returncode}'
            return result
        try:
            response = json.loads(response_path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            result['error'] = f'invalid class diff output: {exc}'
            return result

    response.setdefault('available', True)
    return response


def component_class_name(name):
    return name.split('/', 1)[-1].replace('$', '.')


def bytecode_class_maps(bytecode, section):
    maps = {'added': {}, 'removed': {}, 'changed': {}, 'unresolved': {}}
    section_data = (bytecode or {}).get(section) or {}
    for status in maps:
        for item in section_data.get(status) or []:
            key = (item.get('class') or '').replace('$', '.')
            if key:
                maps[status][key] = item
    return maps


def class_status(className, maps):
    if not className:
        return None
    key = className.replace('$', '.')
    item = maps['changed'].get(key)
    if item:
        return {
            'status': 'changed',
            'body_changed': item.get('body_changed'),
            'baseline': item.get('baseline'),
            'candidate': item.get('candidate'),
        }
    item = maps['added'].get(key)
    if item:
        return {'status': 'added', 'container': item.get('container')}
    item = maps['removed'].get(key)
    if item:
        return {'status': 'removed', 'container': item.get('container')}
    item = maps['unresolved'].get(key)
    if item:
        return {'status': 'unresolved', 'reason': item.get('reason')}
    return None


def component_keys_by_class(baseline, candidate):
    result = {}
    for dump in (baseline, candidate):
        for key in load_component_targets(dump):
            result.setdefault(component_class_name(key[2]), set()).add(key)
    return result


def merge_components(old, bytecode, baseline, candidate):
    maps = bytecode_class_maps(bytecode, 'components')
    result = {
        'availability': old['availability'],
        'summary': dict(old['summary']) if old.get('summary') else None,
        'added': [],
        'removed': [],
        'changed': [],
        'packages': old['packages'],
        'uid_changed': list(old.get('uid_changed') or []),
        'permissions': old['permissions'],
        'uses_permissions': old['uses_permissions'],
        'protected_broadcasts': old['protected_broadcasts'],
        'unresolved_classes': list(((bytecode or {}).get('components') or {}).get('unresolved') or []),
    }

    accessibility = {item['name']: {'from': item['from'], 'to': item['to']}
                     for item in old['components']['accessibility_changed']}
    excluded = set()
    for status in ('added', 'removed'):
        for item in old['components'][status]:
            entry = {key: item.get(key) for key in
                     ('package', 'type', 'name', 'exported', 'permission')}
            if item['name'] in accessibility:
                entry['accessibility'] = accessibility[item['name']]
            className = component_class_name(item['name'])
            info = {'status': status}
            own = maps[status].get(className)
            if own and own.get('container'):
                info['container'] = own['container']
            changed_class = maps['changed'].get(className)
            if changed_class:
                info.update({
                    'body_changed': changed_class.get('body_changed'),
                    'baseline': changed_class.get('baseline'),
                    'candidate': changed_class.get('candidate'),
                })
            unresolved_class = maps['unresolved'].get(className)
            if unresolved_class:
                info['reason'] = unresolved_class.get('reason')
            entry['class'] = info
            result[status].append(entry)
            excluded.add((item.get('package'), item.get('type'), item.get('name')))

    changed = {}

    def changed_entry(package, component_type, name):
        key = (package, component_type, name)
        if key not in changed:
            changed[key] = {'package': package, 'type': component_type, 'name': name}
        return changed[key]

    for item in old['components']['export_changed']:
        changed_entry(item['package'], item['type'], item['name'])['exported'] = {
            'from': item['from'], 'to': item['to']}
    for item in old['components']['permission_changed']:
        changed_entry(item['package'], item['type'], item['name'])['permission'] = {
            'from': item['from'], 'to': item['to']}
    for item in old['components']['provider_permission_changed']:
        changed_entry(item['package'], 'provider', item['name'])['provider_permissions'] = {
            'read': item['read'], 'write': item['write']}
    for item in old['components']['path_permission_changed']:
        changed_entry(item['package'], 'provider', item['name'])['path_permission'] = {
            'added': item['added'], 'removed': item['removed']}
    for item in old['components']['accessibility_changed']:
        package = item['name'].split('/', 1)[0]
        changed_entry(package, item['type'], item['name'])['accessibility'] = {
            'from': item['from'], 'to': item['to']}
    for item in old['components']['intent_filter_changed']:
        payload = {key: value for key, value in item.items()
                   if key not in ('package', 'type', 'name')}
        changed_entry(item['package'], item['type'], item['name'])['intent_filters'] = payload

    baseline_keys = set(load_component_targets(baseline))
    candidate_keys = set(load_component_targets(candidate))
    common_keys = baseline_keys & candidate_keys
    keys_by_class = component_keys_by_class(baseline, candidate)
    for className in maps['changed']:
        for key in keys_by_class.get(className, ()):
            if key not in common_keys:
                continue
            changed_entry(key[0], key[1], key[2])['class'] = class_status(className, maps)

    result['changed'] = [changed[key] for key in sorted(changed)
                         if key not in excluded]

    packages = {}

    def package_entry(name):
        if name not in packages:
            packages[name] = {'name': name}
        return packages[name]

    for status in ('added', 'removed', 'changed'):
        for item in old['packages'][status]:
            entry = package_entry(item['package'])
            entry['status'] = status

    for status in ('added', 'removed', 'changed'):
        for item in result[status]:
            entry = package_entry(item['package'])
            component = {key: value for key, value in item.items() if key != 'package'}
            entry.setdefault(status, []).append(component)

    grouped = {}

    def package_entry(name):
        if name not in grouped:
            grouped[name] = {'name': name}
        return grouped[name]

    def add(package, key, value):
        package_entry(package).setdefault(key, []).append(value)

    for name in sorted(packages):
        entry = packages[name]
        target = package_entry(name)
        if 'status' in entry:
            target['status'] = entry['status']
        for status in ('added', 'removed'):
            for component in entry.get(status, []):
                add(name, status, component['name'])
                accessibility = component.get('accessibility') or {}
                if status == 'added' and accessibility.get('to') is not None:
                    add(name, 'newly_accessible', component['name'])
                if status == 'removed' and accessibility.get('from') is not None:
                    add(name, 'no_longer_accessible', component['name'])
        for component in entry.get('changed', []):
            add(name, 'changed', component['name'])
            exported = component.get('exported') or {}
            if exported.get('to') is True:
                add(name, 'newly_exported', component['name'])
            if exported.get('to') is False:
                add(name, 'newly_hidden', component['name'])
            if 'permission' in component:
                add(name, 'permission_changed', component['name'])
            if 'provider_permissions' in component:
                add(name, 'provider_permission_changed', component['name'])
            accessibility = component.get('accessibility') or {}
            if accessibility.get('from') is None and accessibility.get('to') is not None:
                add(name, 'newly_accessible', component['name'])
            if accessibility.get('to') is None and accessibility.get('from') is not None:
                add(name, 'no_longer_accessible', component['name'])
            if 'intent_filters' in component:
                add(name, 'intent_filter_changed', component['name'])
            if 'path_permission' in component:
                add(name, 'path_permission_changed', component['name'])

    for item in result['uses_permissions']['added']:
        add(item['package'], 'uses_permissions_added', item['permission'])
    for item in result['uses_permissions']['removed']:
        add(item['package'], 'uses_permissions_removed', item['permission'])
    for item in result['protected_broadcasts']['added']:
        add(item['package'], 'protected_broadcasts_added', item['action'])
    for item in result['protected_broadcasts']['removed']:
        add(item['package'], 'protected_broadcasts_removed', item['action'])
    for item in result['unresolved_classes']:
        package = item.get('package')
        if package:
            add(package, 'unresolved_classes', item.get('class'))

    array_keys = {
        'added', 'removed', 'changed', 'newly_exported', 'newly_hidden',
        'permission_changed', 'provider_permission_changed',
        'newly_accessible', 'no_longer_accessible',
        'intent_filter_changed', 'path_permission_changed',
        'uses_permissions_added', 'uses_permissions_removed',
        'protected_broadcasts_added', 'protected_broadcasts_removed',
        'unresolved_classes',
    }
    result_packages = []
    for name in sorted(grouped):
        entry = grouped[name]
        # An APK hash change alone is a runtime skip signal, not a finding.
        if entry.get('status') == 'changed' and set(entry) <= {'name', 'status'}:
            continue
        for key in array_keys:
            if key in entry:
                entry[key] = sorted(set(entry[key]))
        result_packages.append(entry)

    added_packages = []
    removed_packages = []
    changed_packages = []
    for entry in result_packages:
        status = entry.get('status')
        if status == 'added':
            added_packages.append(entry['name'])
        elif status == 'removed':
            removed_packages.append(entry['name'])
        else:
            detail = {'package': entry['name']}
            for key in ('uses_permissions_added', 'uses_permissions_removed',
                        'protected_broadcasts_added', 'protected_broadcasts_removed',
                        'unresolved_classes'):
                if key in entry:
                    detail[key] = entry[key]
            component_keys = array_keys - {
                'uses_permissions_added', 'uses_permissions_removed',
                'protected_broadcasts_added', 'protected_broadcasts_removed',
                'unresolved_classes'}
            detail['components'] = {
                key: value for key, value in entry.items() if key in component_keys}
            changed_packages.append(detail)

    return {
        'availability': result['availability'],
        'added': sorted(added_packages),
        'removed': sorted(removed_packages),
        'uid_changed': result['uid_changed'],
        'changed': sorted(changed_packages, key=lambda x: x['package']),
    }


def merge_services(old, bytecode, baseline, candidate):
    maps = bytecode_class_maps(bytecode, 'binder_impl')
    aidl_a, _ = load_aidl(baseline)
    aidl_b, _ = load_aidl(candidate)

    def block_of(aidl, service, kind, descriptor):
        return aidl.get(service, {}).get((kind, descriptor)) or {}

    def methods_of(aidl, service, kind, descriptor):
        return list(block_of(aidl, service, kind, descriptor).get('methods') or [])

    def impl_status(impl):
        info = class_status(impl, maps)
        if not info:
            return 'unchanged'
        status = info.get('status') or 'unchanged'
        return 'body_changed' if status == 'changed' else status

    def entry(service, kind, descriptor, impl, old=None, added=None, removed=None):
        item = {'name': service, 'type': kind, 'descriptor': descriptor}
        if impl:
            impl_obj = {'name': impl}
            if old and old != impl:
                impl_obj['old'] = old
            impl_obj['status'] = impl_status(impl)
            item['impl'] = impl_obj
        if added:
            item['methods_added'] = added
        if removed:
            item['methods_removed'] = removed
        return item

    result = {
        'availability': old['availability'],
        'added': [],
        'removed': [],
        'newly_accessible': [],
        'newly_blocked': [],
        'unresolved_classes': list(((bytecode or {}).get('binder_impl') or {}).get('unresolved') or []),
    }

    added_services = {item['name'] for item in old['services']['added']}
    removed_services = {item['name'] for item in old['services']['removed']}
    result['added'] = sorted(added_services)
    result['removed'] = sorted(removed_services)
    changed_entries = []
    result['newly_accessible'] = sorted({
        item['name'] for item in old['services']['accessibility_changed']
        if item.get('to') is True})
    result['newly_blocked'] = sorted({
        item['name'] for item in old['services']['accessibility_changed']
        if item.get('to') is False})

    for item in old['interfaces']['added']:
        if item['service'] in added_services:
            continue
        name, kind, descriptor = item['service'], item['kind'], item['descriptor']
        block = block_of(aidl_b, name, kind, descriptor)
        changed_entries.append(entry(
            name, kind, descriptor, block.get('impl') or item.get('impl'),
            added=methods_of(aidl_b, name, kind, descriptor)))
    for item in old['interfaces']['removed']:
        if item['service'] in removed_services:
            continue
        name, kind, descriptor = item['service'], item['kind'], item['descriptor']
        block = block_of(aidl_a, name, kind, descriptor)
        changed_entries.append(entry(
            name, kind, descriptor, block.get('impl') or item.get('impl'),
            removed=methods_of(aidl_a, name, kind, descriptor)))
    for item in old['interfaces']['changed']:
        name, kind, descriptor = item['service'], item['kind'], item['descriptor']
        candidate_impl = block_of(aidl_b, name, kind, descriptor).get('impl')
        baseline_impl = block_of(aidl_a, name, kind, descriptor).get('impl')
        if isinstance(item.get('impl'), dict):
            baseline_impl = item['impl'].get('from') or baseline_impl
            candidate_impl = item['impl'].get('to') or candidate_impl
        changed_entry = entry(
            name, kind, descriptor, candidate_impl, old=baseline_impl,
            added=item.get('methods_added') or None,
            removed=item.get('methods_removed') or None)
        if isinstance(item.get('so'), dict):
            changed_entry['so'] = {
                'value': item['so'].get('to'), 'old': item['so'].get('from')}
        if isinstance(item.get('backend'), dict):
            changed_entry['backend'] = {
                'value': item['backend'].get('to'), 'old': item['backend'].get('from')}
        changed_entries.append(changed_entry)

    result['changed'] = sorted(changed_entries, key=lambda x: (x['name'], x['descriptor']))
    return result


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
        'schema_version': 2,
        'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
        'files': {'baseline': str(baseline), 'candidate': str(candidate)},
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

    components_result = diff_components(baseline, candidate, args.workers)
    services_result = diff_services(baseline, candidate)
    bytecode = diff_bytecode(baseline, candidate, components_result)

    report['packages'] = merge_components(components_result, bytecode, baseline, candidate)
    report['permissions'] = diff_permission_definitions(baseline, candidate)
    report['binder'] = merge_services(services_result, bytecode, baseline, candidate)
    report['apex'] = diff_apex(baseline, candidate)

    write_json(output, report)

    if not args.quiet:
        print(f'ASE image diff')
        print(f'  baseline:  {baseline}')
        print(f'  candidate: {candidate}')
        if not components_result['availability']['available']:
            print('  components: unavailable, skipped (missing artifacts)')
        else:
            component_summary = components_result['summary']
            packages = component_summary['packages']
            components = component_summary['components']
            changed_components = sum(
                len((package.get('components') or {}).get('changed') or [])
                for package in report['packages']['changed'])
            print(f"  packages:  {packages['baseline']} -> {packages['candidate']} "
                  f"(+{packages['added']} / -{packages['removed']})")
            print(f"  components:{components['baseline']} -> {components['candidate']} "
                  f"(+{components['added']} / -{components['removed']})")
            print(f"  changed components: {changed_components}")
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
            definitions = permissions['definitions']
            print(f"  permissions: +{len(definitions['added'])} "
                  f"/ -{len(definitions['removed'])} "
                  f"/ ~{len(definitions['changed'])}")

        binder = report['binder']
        availability = binder['availability']
        if not availability['registry']:
            print('  services: unavailable, skipped (missing artifacts)')
        else:
            print(f"  services:  +{len(binder['added'])} / -{len(binder['removed'])}")
        if availability['accessibility']:
            print(f"  newly accessible services: {len(binder['newly_accessible'])} "
                  f"/ newly blocked: {len(binder['newly_blocked'])}")
        else:
            print('  accessibility: unavailable on one side, skipped')
        if availability['aidl']:
            print(f"  changed interfaces: {len(binder['changed'])}")
        else:
            print('  AIDL: unavailable on one side, skipped')

        if not report['apex']['availability']['available']:
            print('  apex: unavailable, skipped (missing artifacts)')
        else:
            apex = report['apex']['apex']
            print(f"  apex:      +{len(apex['added'])} / -{len(apex['removed'])}")

        if bytecode.get('available'):
            components = bytecode.get('components') or {}
            binder_impl = bytecode.get('binder_impl') or {}
            print(f"  class diff: components {components.get('changed_count', 0)} changed "
                  f"(+{components.get('added_count', 0)} / -{components.get('removed_count', 0)}) "
                  f"/ {components.get('resolved', 0)} resolved; "
                  f"binder impl {binder_impl.get('changed_count', 0)} changed "
                  f"(+{binder_impl.get('added_count', 0)} / -{binder_impl.get('removed_count', 0)}) "
                  f"/ {binder_impl.get('resolved', 0)} resolved")
        else:
            print(f"  class diff: unavailable ({bytecode.get('error', '')})")
        print(f'  wrote: {output}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
