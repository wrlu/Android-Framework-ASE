#!/usr/bin/env python3
"""
Post-Analysis Service Reconciliation Tool

Compares ASE on-device accessible services (accessible_services.txt) against
Java AIDL interfaces (accessible_service_aidl.txt) and Native AIDL interfaces
(accessible_native_aidl.txt), and generates unresolved_accessible_services.txt
for services confirmed accessible on-device but missing AIDL definitions.
"""

import os
import sys
import re
import logging
import argparse
import zipfile
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('post_analyzer')

SERVICE_TAG_PATTERN = re.compile(r'\[service=([^\]]+)\]')
ELF_MAGIC = b'\x7fELF'
ELF_SCAN_DIRS = (
    ('system/lib', '*.so'), ('system/lib64', '*.so'),
    ('vendor/lib', '*.so'), ('vendor/lib64', '*.so'),
    ('odm/lib', '*.so'), ('odm/lib64', '*.so'),
    ('product/lib', '*.so'), ('product/lib64', '*.so'),
    ('system_ext/lib', '*.so'), ('system_ext/lib64', '*.so'),
    ('apex', '**/*.so'),
    ('system/bin', '*'), ('system/bin/hw', '*'),
    ('vendor/bin', '*'), ('vendor/bin/hw', '*'),
    ('odm/bin', '*'), ('odm/bin/hw', '*'),
    ('product/bin', '*'), ('product/bin/hw', '*'),
    ('system_ext/bin', '*'), ('system_ext/bin/hw', '*'),
    ('apex', '**/bin/*'),
)


def parse_service_list(workspace):
    """Parse service_list.txt.

    Returns:
        service_to_desc: dict mapping service name -> descriptor
        desc_to_services: dict mapping descriptor -> set of service names
    """
    service_file = Path(workspace) / 'service_list.txt'
    service_to_desc = {}
    desc_to_services = defaultdict(set)

    if not service_file.exists():
        logger.warning('service_list.txt not found')
        return service_to_desc, desc_to_services

    with open(service_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line or line.startswith('Found'):
                continue
            name_part, _, desc_part = line.partition(':')
            name = re.sub(r'^\d+\s+', '', name_part.strip())
            desc_part = desc_part.strip()
            if desc_part.startswith('[') and desc_part.endswith(']'):
                desc = desc_part[1:-1].strip()
                service_to_desc[name] = desc
                if desc:
                    desc_to_services[desc].add(name)
            elif name:
                service_to_desc.setdefault(name, '')

    return service_to_desc, desc_to_services


def parse_accessible_services(workspace):
    """Parse accessible_services.txt.

    Returns:
        accessible_services: set of service names with accessible=1
        all_probed: dict mapping service name -> bool
    """
    accessible_file = Path(workspace) / 'accessible_services.txt'
    if not accessible_file.exists():
        return set(), {}

    accessible_services = set()
    all_probed = {}

    with open(accessible_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'service=' not in line:
                continue
            fields = dict(re.findall(r'(\w+)=([^,]*)', line))
            name = fields.get('service', '').strip()
            accessible_val = fields.get('accessible', '').strip()
            if not name:
                continue
            is_accessible = (accessible_val == '1')
            all_probed[name] = is_accessible
            if is_accessible:
                accessible_services.add(name)

    return accessible_services, all_probed


def parse_resolved_services_from_file(file_path, desc_to_services):
    """Extract resolved service names from an AIDL output file.

    Handles both explicit [service=name1, name2] tags and descriptor fallback
    lookup via desc_to_services.
    """
    resolved = set()
    if not file_path.exists():
        return resolved

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check if this line is an interface header (contains '[' and not method signature starting with '.')
            if '[' not in line:
                continue

            # Strategy 1: Parse [service=...] tag
            m = SERVICE_TAG_PATTERN.search(line)
            if m:
                names = [s.strip() for s in m.group(1).split(',') if s.strip()]
                resolved.update(names)

            # Strategy 2: Extract descriptor and map to service names
            desc = line.split('[')[0].strip()
            if desc and desc in desc_to_services:
                resolved.update(desc_to_services[desc])

    return resolved


def _iter_elf_files(ws_path):
    seen = set()
    for rel_dir, glob_pat in ELF_SCAN_DIRS:
        base = ws_path / rel_dir
        if not base.is_dir() or base.is_symlink():
            continue
        if rel_dir == 'apex':
            sub_pat = glob_pat.removeprefix('**/')
            for entry in sorted(base.iterdir()):
                if entry.is_symlink() or not entry.is_dir():
                    continue
                for path in entry.glob('**/' + sub_pat):
                    if path.is_symlink() or not path.is_file():
                        continue
                    resolved = path.resolve()
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    yield path
        else:
            for path in base.glob(glob_pat):
                if path.is_symlink() or not path.is_file():
                    continue
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                yield path


def locate_candidate_binaries(ws_path, unresolved_services, service_to_desc):
    """Reverse-locate candidate ELF binaries or APKs referencing unresolved descriptors."""
    needles = {}
    for name in unresolved_services:
        desc = service_to_desc.get(name, '').strip()
        needle = desc if desc else (name if '.' in name else '')
        if needle:
            needles[name] = (
                needle.encode('utf-8'),
                needle.encode('utf-16le'),
                needle.replace('.', '/').encode('utf-8'),
            )
    if not needles:
        return {}

    matches = defaultdict(list)

    # 1. Scan ELF binaries across partitions & APEX
    for path in _iter_elf_files(ws_path):
        try:
            with open(path, 'rb') as fh:
                magic = fh.read(4)
                if magic != ELF_MAGIC:
                    continue
                data = magic + fh.read()
        except OSError:
            continue
        rel = str(path.relative_to(ws_path))
        for name, (utf8_b, utf16_b, _slash_b) in needles.items():
            if utf8_b in data or utf16_b in data:
                matches[name].append(rel)

    # 2. For services still without ELF hits, check package APKs/JARs (DEX & manifest)
    remaining = {name: pats for name, pats in needles.items() if not matches[name]}
    packages_dir = ws_path / 'packages'
    if remaining and packages_dir.is_dir():
        for pkg_dir in sorted(packages_dir.iterdir()):
            if not pkg_dir.is_dir() or pkg_dir.is_symlink():
                continue
            for archive in sorted(pkg_dir.iterdir()):
                if archive.is_symlink() or not archive.is_file():
                    continue
                if archive.suffix not in ('.apk', '.jar'):
                    continue
                try:
                    with zipfile.ZipFile(archive, 'r') as zf:
                        dex_names = [n for n in zf.namelist() if n.endswith('.dex')]
                        if not dex_names:
                            continue
                        rel = str(archive.relative_to(ws_path))
                        for dex_name in dex_names:
                            dex_bytes = zf.read(dex_name)
                            for name, (utf8_b, _utf16_b, slash_b) in remaining.items():
                                if utf8_b in dex_bytes or slash_b in dex_bytes:
                                    if rel not in matches[name]:
                                        matches[name].append(rel)
                except (OSError, zipfile.BadZipFile):
                    continue

    return {name: sorted(paths) for name, paths in matches.items() if paths}


def reconcile(workspace, output_file=None):
    ws_path = Path(workspace).resolve()
    if not ws_path.is_dir():
        logger.error('Workspace directory not found: %s', ws_path)
        sys.exit(1)

    accessible_services, all_probed = parse_accessible_services(ws_path)
    if not accessible_services and not all_probed:
        logger.warning('accessible_services.txt not found or empty in %s', ws_path)
        logger.warning('Cannot compute unresolved accessible services without probe results.')
        return

    service_to_desc, desc_to_services = parse_service_list(ws_path)

    java_aidl_file = ws_path / 'accessible_service_aidl.txt'
    java_resolved = parse_resolved_services_from_file(java_aidl_file, desc_to_services)

    native_aidl_file = ws_path / 'accessible_native_aidl.txt'
    native_resolved = parse_resolved_services_from_file(native_aidl_file, desc_to_services)

    all_resolved = java_resolved | native_resolved
    unresolved_services = sorted(accessible_services - all_resolved)

    total_acc = len(accessible_services)
    total_resolved = len(all_resolved & accessible_services)
    total_unresolved = len(unresolved_services)
    java_count = len(java_resolved & accessible_services)
    native_count = len(native_resolved & accessible_services)

    resolved_pct = (total_resolved / total_acc * 100.0) if total_acc else 0.0
    unresolved_pct = (total_unresolved / total_acc * 100.0) if total_acc else 0.0
    java_pct = (java_count / total_acc * 100.0) if total_acc else 0.0
    native_pct = (native_count / total_acc * 100.0) if total_acc else 0.0

    target_output = Path(output_file).resolve() if output_file else (ws_path / 'unresolved_accessible_services.txt')
    candidates_map = locate_candidate_binaries(ws_path, unresolved_services, service_to_desc)

    with open(target_output, 'w', encoding='utf-8') as f:
        f.write('# Unresolved Accessible Services\n')
        f.write('# Services confirmed accessible (accessible=1) by ASE APK probe,\n')
        f.write('# but without matching implementations in accessible_service_aidl.txt or accessible_native_aidl.txt.\n')
        f.write('#\n')
        f.write(f'# Total probed services:      {len(all_probed)}\n')
        f.write(f'# Probed accessible services: {total_acc}\n')
        f.write(f'# Total resolved services:    {total_resolved} ({resolved_pct:.1f}%)\n')
        f.write(f'#   ├─ Java AIDL resolved:    {java_count} ({java_pct:.1f}%)\n')
        f.write(f'#   └─ Native AIDL resolved:  {native_count} ({native_pct:.1f}%)\n')
        f.write(f'# Unresolved accessible:      {total_unresolved} ({unresolved_pct:.1f}%)\n')
        f.write('#\n')
        f.write('# Format: <service_name> [<descriptor>] [<reason>] [candidates=...]\n')
        f.write('#\n')

        for name in unresolved_services:
            desc = service_to_desc.get(name, '')
            if not desc:
                reason = 'empty_descriptor'
            else:
                reason = 'no_aidl_matched'
            cands = candidates_map.get(name)
            if cands:
                shown = ', '.join(cands[:5])
                if len(cands) > 5:
                    shown += f' (+{len(cands) - 5} more)'
                f.write(f'{name} [{desc}] [{reason}] [candidates={shown}]\n')
            else:
                f.write(f'{name} [{desc}] [{reason}]\n')

    logger.info('=== Accessibility Reconciliation Summary ===')
    logger.info('Total probed services:      %d', len(all_probed))
    logger.info('Accessible services (ASE):  %d', total_acc)
    logger.info('  ├─ Resolved:              %d (%.1f%%)', total_resolved, resolved_pct)
    logger.info('  │   ├─ Java AIDL:         %d (%.1f%%, %s)',
                java_count, java_pct,
                java_aidl_file.name if java_aidl_file.exists() else 'not found')
    logger.info('  │   └─ Native AIDL:       %d (%.1f%%, %s)',
                native_count, native_pct,
                native_aidl_file.name if native_aidl_file.exists() else 'not found')
    logger.info('  └─ Unresolved:            %d (%.1f%%) -> %s',
                total_unresolved, unresolved_pct, target_output.name)
    logger.info('=' * 44)


def main():
    parser = argparse.ArgumentParser(
        description='Reconcile ASE accessible services against Java and Native AIDL outputs.'
    )
    parser.add_argument('workspace', nargs='?', default='.',
                        help='Firmware dump directory (default: current directory)')
    parser.add_argument('-o', '--output',
                        help='Output file path (default: <workspace>/unresolved_accessible_services.txt)')
    args = parser.parse_args()

    reconcile(args.workspace, args.output)


if __name__ == '__main__':
    main()
