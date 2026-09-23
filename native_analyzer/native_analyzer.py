#!/usr/bin/env python3
"""
Native AIDL Interface Analyzer

Scans ELF files (.so and executables) in Android firmware dump for native AIDL interfaces.
Combines:
  Step 1: Descriptor string scan (C++ .so, null-separated strings)
  Step 1b: Rust v0 mangled symbol parsing (Rust .so, concatenated strings)
  Step 2: Bn/Bp symbol detection (server/client identification, works for both C++ and Rust)
"""

import os
import re
import sys
import logging
import argparse
from collections import defaultdict
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('native_analyzer')

# AIDL descriptor pattern for null-separated strings (C++ .so)
AIDL_DESC_PATTERN = re.compile(rb'[a-z]+(?:\.[A-Za-z_0-9]+)+\.I[A-Z]\w*')

# Rust v0 mangled symbol prefix
RUST_SYMBOL_PATTERN = re.compile(rb'_R[A-Za-z0-9_]+')

# Library and binary directories to scan
SCAN_DIRS = [
    ('system/lib', '*.so'),
    ('system/lib64', '*.so'),
    ('vendor/lib', '*.so'),
    ('vendor/lib64', '*.so'),
    ('odm/lib', '*.so'),
    ('odm/lib64', '*.so'),
    ('product/lib', '*.so'),
    ('product/lib64', '*.so'),
    ('system_ext/lib', '*.so'),
    ('system_ext/lib64', '*.so'),
    ('system/bin', '*'),
    ('system/bin/hw', '*'),
    ('vendor/bin', '*'),
    ('vendor/bin/hw', '*'),
    ('odm/bin', '*'),
    ('odm/bin/hw', '*'),
    ('product/bin', '*'),
    ('system_ext/bin', '*'),
]

ELF_MAGIC = b'\x7fELF'


def find_elf_files(workspace):
    """Find all ELF files (.so and executables) in workspace directories."""
    elf_files = []
    for rel_dir, glob_pat in SCAN_DIRS:
        path = Path(workspace) / rel_dir
        if not path.is_dir():
            continue
        for f in path.glob(glob_pat):
            if not f.is_file():
                continue
            try:
                with open(f, 'rb') as fh:
                    if fh.read(4) == ELF_MAGIC:
                        elf_files.append(f.resolve())
            except (IOError, OSError):
                pass
    return elf_files


def extract_rust_descriptors(data):
    """Extract AIDL descriptors from Rust v0 mangled symbols.

    Rust AIDL symbols contain the full module path, e.g.:
    _RNvXs2_NtNtNtNtCsfLgIZz5Nk0P_11android_gui4aidl7android3gui16ISurfaceComposer...NtB5_17BnSurfaceComposerE

    Path components: android_gui, aidl, android, gui, ISurfaceComposer, ..., BnSurfaceComposer
    AIDL descriptor: android.gui.ISurfaceComposer
    (skip crate name + "aidl" module, join rest with dots)
    """
    descriptors = set()

    for m in RUST_SYMBOL_PATTERN.finditer(data):
        symbol = m.group()
        if b'Bn' not in symbol:
            continue

        # Extract all length-prefixed identifiers from the symbol
        components = parse_rust_length_prefixed(symbol)
        if not components:
            continue

        # Find Bn class (BnFoo where Foo starts with uppercase)
        bn_idx = None
        for idx, comp in enumerate(components):
            if comp.startswith('Bn') and len(comp) > 2 and comp[2].isupper():
                bn_idx = idx
                break

        if bn_idx is None:
            continue

        bn_class = components[bn_idx]
        iface_short = bn_class[2:]  # SurfaceComposer
        iface_name = 'I' + iface_short  # ISurfaceComposer

        # Find the interface component before Bn
        iface_idx = None
        for idx in range(bn_idx - 1, -1, -1):
            if components[idx] == iface_name:
                iface_idx = idx
                break

        if iface_idx is None:
            continue

        # Find 'aidl' module before interface
        aidl_idx = None
        for idx in range(iface_idx - 1, -1, -1):
            if components[idx] == 'aidl':
                aidl_idx = idx
                break

        if aidl_idx is None:
            continue

        # Package path: components between aidl (excl) and interface (excl)
        pkg_path = components[aidl_idx + 1:iface_idx]
        if not pkg_path:
            continue

        # Construct descriptor (may include parent interfaces for nested types)
        descriptor = '.'.join(pkg_path) + '.' + iface_name
        descriptors.add(descriptor)

    return descriptors


def parse_rust_length_prefixed(data):
    """Parse length-prefixed identifiers from Rust v0 mangled name data.

    In Rust v0 mangling, identifiers are encoded as {length}{name}
    where length is the number of bytes in the name.
    e.g., 11android_gui -> "android_gui"

    Must skip backref tokens (B{base62}_) which can contain digits that
    look like length prefixes.
    """
    components = []
    i = 0
    length_bytes = len(data)
    while i < length_bytes:
        c = data[i:i+1]

        # Skip backref: B followed by base62 chars and underscore
        if c == b'B' and i + 1 < length_bytes:
            j = i + 1
            while j < length_bytes and data[j:j+1].isalnum():
                j += 1
            if j < length_bytes and data[j:j+1] == b'_':
                i = j + 1
                continue

        if not c.isdigit():
            i += 1
            continue

        # Parse length prefix
        j = i
        while j < length_bytes and data[j:j+1].isdigit():
            j += 1
        n = int(data[i:j])
        start = j

        if n < 1 or start + n > length_bytes:
            i = j
            continue

        name = data[start:start + n]
        # Identifier must start with a letter (not underscore, not digit)
        if name[0:1].isalpha():
            # Verify it's a plausible identifier: all alphanumeric or underscore
            valid = True
            for k in range(n):
                ch = name[k:k+1]
                if not (ch.isalnum() or ch == b'_'):
                    valid = False
                    break
            if valid:
                try:
                    components.append(name.decode('ascii'))
                except UnicodeDecodeError:
                    pass
        # Always advance past the length + name to avoid re-parsing inside
        i = start + n
    return components


def scan_so(so_path):
    """Scan an ELF file for AIDL descriptors and Bn/Bp symbols.

    Returns:
        dict: descriptor -> {'server': bool, 'client': bool}
    """
    with open(so_path, 'rb') as f:
        data = f.read()

    # Step 1: Find AIDL descriptors from null-separated strings (C++)
    descriptors = set()
    for m in AIDL_DESC_PATTERN.finditer(data):
        try:
            desc = m.group().decode('ascii')
            desc = desc.split('/')[0]
            descriptors.add(desc)
        except UnicodeDecodeError:
            pass

    # Step 1b: Find AIDL descriptors from Rust v0 mangled symbols
    descriptors.update(extract_rust_descriptors(data))

    if not descriptors:
        return {}

    # Step 2: For each descriptor, check Bn/Bp presence
    # Both C++ (Itanium ABI) and Rust (v0) use {len}Bn{Name} byte encoding
    result = {}
    for desc in descriptors:
        iface_full = desc.rsplit('.', 1)[-1]
        if not iface_full.startswith('I') or len(iface_full) < 2:
            continue
        short_name = iface_full[1:]

        bn_str = 'Bn' + short_name
        bp_str = 'Bp' + short_name
        bn_pat = '{}{}'.format(len(bn_str), bn_str).encode('ascii')
        bp_pat = '{}{}'.format(len(bp_str), bp_str).encode('ascii')

        result[desc] = {
            'server': bn_pat in data,
            'client': bp_pat in data,
        }

    return result


def parse_service_list(workspace):
    """Parse registered binder services from service_list.txt.

    service_list.txt format:
      {index}\t{name}: [{descriptor}]
    e.g., 2  SurfaceFlingerAIDL: [android.gui.ISurfaceComposer]

    Returns:
        (descriptors, name_to_desc, desc_to_names): a set of registered descriptors,
        mapping from service name to descriptor, and mapping from descriptor to list of names.
    """
    service_file = Path(workspace) / 'service_list.txt'
    if not service_file.exists():
        logger.warning('service_list.txt not found')
        return set(), {}, defaultdict(list)

    descriptors = set()
    name_to_desc = {}
    desc_to_names = defaultdict(list)
    with open(service_file) as f:
        for line in f:
            line = line.strip()
            if not line or ':' not in line or line.startswith('Found'):
                continue
            name_part, _, desc_part = line.partition(':')
            name = re.sub(r'^\d+\s+', '', name_part.strip())
            desc_part = desc_part.strip()
            if desc_part.startswith('[') and desc_part.endswith(']'):
                desc = desc_part[1:-1].strip()
                if desc:
                    descriptors.add(desc)
                    name_to_desc[name] = desc
                    desc_to_names[desc].append(name)
                elif name:
                    name_to_desc.setdefault(name, '')
    return descriptors, name_to_desc, desc_to_names


def load_accessible_services(workspace, name_to_desc):
    """Parse ASE on-device accessibility results from accessible_services.txt.

    The file is the raw output of:
      adb shell content query --uri content://net.wrlu.ase.probe/binder_service

    Each row looks like:
      Row: 2 service=activity, accessible=1

    The service name is mapped to its descriptor via service_list.txt.

    Returns:
        dict mapping descriptor -> accessible (bool), or None when
        accessible_services.txt is absent.
    """
    accessible_file = Path(workspace) / 'accessible_services.txt'
    if not accessible_file.exists():
        return None

    by_desc = {}
    with open(accessible_file) as f:
        for line in f:
            if 'service=' not in line:
                continue
            fields = dict(re.findall(r'(\w+)=([^,]*)', line))
            name = fields.get('service', '').strip()
            accessible_val = fields.get('accessible', '').strip()
            desc = name_to_desc.get(name, '')
            if desc and accessible_val in ('0', '1'):
                by_desc[desc] = (accessible_val == '1')
    logger.info('Accessible services: %d', len(by_desc))
    return by_desc


def analyze(workspace, ignore_registered):
    workspace = Path(workspace).resolve()

    elf_files = find_elf_files(workspace)
    logger.info('Found %d ELF files', len(elf_files))

    if not elf_files:
        logger.error('No ELF files found. Check workspace directory.')
        return

    # Map: descriptor -> {'servers': set(so_paths), 'clients': set(so_paths)}
    aidl_map = defaultdict(lambda: {'servers': set(), 'clients': set()})

    total = len(elf_files)
    for i, so_path in enumerate(elf_files, 1):
        rel_path = str(so_path.relative_to(workspace))
        logger.info('[%d/%d] %s', i, total, rel_path)

        results = scan_so(so_path)
        for desc, info in results.items():
            if info['server']:
                aidl_map[desc]['servers'].add(rel_path)
            if info['client']:
                aidl_map[desc]['clients'].add(rel_path)

    # Registered filter: load service_list.txt unless ignored.
    # Accessibility results (accessible_services.txt) drive a separate output.
    registered, name_to_desc, desc_to_names = parse_service_list(workspace)
    accessible = None
    if not ignore_registered:
        logger.info('Registered services: %d', len(registered))
        accessible = load_accessible_services(workspace, name_to_desc)
    elif name_to_desc:
        accessible = load_accessible_services(workspace, name_to_desc)

    # Only server entries
    server_ifaces = {desc: info for desc, info in aidl_map.items() if info['servers']}

    # Apply registered filter (default: only registered)
    if not ignore_registered:
        server_ifaces = {desc: info for desc, info in server_ifaces.items() if desc in registered}

    output_file = workspace / 'native_aidl.txt'
    write_native_aidl(output_file, server_ifaces, accessible, desc_to_names=desc_to_names)
    logger.info('Output: %s', output_file)
    logger.info('Total: %d server implementations', len(server_ifaces))

    # Accessible subset -> separate output (clean format); original file keeps markers.
    if accessible is not None:
        accessible_ifaces = {d: info for d, info in server_ifaces.items()
                             if accessible.get(d) is True}
        accessible_file = workspace / 'accessible_native_aidl.txt'
        write_native_aidl(accessible_file, accessible_ifaces, desc_to_names=desc_to_names)
        not_accessible = sum(1 for d in server_ifaces if accessible.get(d) is False)
        unknown = sum(1 for d in server_ifaces if d not in accessible)
        logger.info('Accessible output: %s', accessible_file)
        logger.info('Accessibility verification: accessible=%d not_accessible=%d unknown=%d',
                    len(accessible_ifaces), not_accessible, unknown)


def write_native_aidl(output_file, server_ifaces, accessible=None, desc_to_names=None):
    with open(output_file, 'w') as f:
        for desc in sorted(server_ifaces.keys()):
            so_list = ', '.join(sorted(server_ifaces[desc]['servers']))
            line = '{} [{}]'.format(desc, so_list)
            if desc_to_names and desc in desc_to_names:
                svc_names = ', '.join(sorted(set(desc_to_names[desc])))
                line += ' [service={}]'.format(svc_names)
            if accessible is not None:
                if desc in accessible:
                    line += ' [accessible={}]'.format(1 if accessible[desc] else 0)
                else:
                    line += ' [accessible=unknown]'
            f.write(line + '\n')


def main():
    parser = argparse.ArgumentParser(
        description='Native AIDL Interface Analyzer - scan ELF files for AIDL interfaces'
    )
    parser.add_argument('workspace', help='Firmware dump directory (contains system/, vendor/, etc.)')
    parser.add_argument('--ignore-registered', action='store_true',
                        help='Ignore service_list.txt check, output all server interfaces (default: only registered)')
    args = parser.parse_args()

    if not os.path.isdir(args.workspace):
        logger.error('Invalid workspace directory: %s', args.workspace)
        sys.exit(1)

    analyze(args.workspace, args.ignore_registered)


if __name__ == '__main__':
    main()
