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
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('post_analyzer')

SERVICE_TAG_PATTERN = re.compile(r'\[service=([^\]]+)\]')


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
        f.write('# Format: <service_name> [<descriptor>] [<reason>]\n')
        f.write('#\n')

        for name in unresolved_services:
            desc = service_to_desc.get(name, '')
            if not desc:
                reason = 'empty_descriptor'
            else:
                reason = 'no_aidl_matched'
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
