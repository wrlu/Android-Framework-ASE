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
import struct
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
    ('apex', '**/*.so'),
    ('system/bin', '*'),
    ('system/bin/hw', '*'),
    ('vendor/bin', '*'),
    ('vendor/bin/hw', '*'),
    ('odm/bin', '*'),
    ('odm/bin/hw', '*'),
    ('product/bin', '*'),
    ('product/bin/hw', '*'),
    ('system_ext/bin', '*'),
    ('system_ext/bin/hw', '*'),
    ('apex', '**/bin/*'),
]

ELF_MAGIC = b'\x7fELF'


def find_elf_files(workspace):
    """Find all ELF files (.so and executables) in workspace directories."""
    elf_files = []
    seen = set()
    for rel_dir, glob_pat in SCAN_DIRS:
        path = Path(workspace) / rel_dir
        if not path.is_dir() or path.is_symlink():
            continue
        if rel_dir == 'apex':
            # In apex/, there may be symlinks (Finder aliases / 替身) pointing to other apex directories.
            # Traverse only real (non-symlink) subdirectories to avoid duplicate scanning.
            for apex_entry in sorted(path.iterdir()):
                if apex_entry.is_symlink() or not apex_entry.is_dir():
                    continue
                sub_pat = glob_pat.removeprefix('**/')
                for f in apex_entry.glob('**/' + sub_pat):
                    if f.is_symlink() or not f.is_file():
                        continue
                    resolved = f.resolve()
                    if resolved in seen:
                        continue
                    try:
                        with open(f, 'rb') as fh:
                            if fh.read(4) == ELF_MAGIC:
                                elf_files.append(resolved)
                                seen.add(resolved)
                    except (IOError, OSError):
                        pass
        else:
            for f in path.glob(glob_pat):
                if f.is_symlink() or not f.is_file():
                    continue
                resolved = f.resolve()
                if resolved in seen:
                    continue
                try:
                    with open(f, 'rb') as fh:
                        if fh.read(4) == ELF_MAGIC:
                            elf_files.append(resolved)
                            seen.add(resolved)
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


def extract_elf_metadata(data):
    """Extract dynamic dependencies and symbols from ELF bytes.

    Parses ELF header, PT_DYNAMIC, and section headers (SHT_DYNAMIC / SHT_DYNSYM)
    when available, with fast byte scanning as resilient fallback.
    """
    meta = {
        'needed': set(),
        'imported': set(),
        'exported': set(),
        'is_ndk': False,
        'is_legacy': False,
        'has_ndk_server': False,
        'has_legacy_server': False,
        'has_interface_hash': False,
    }
    if len(data) < 52 or data[:4] != b'\x7fELF':
        return meta

    # Fast byte heuristics (resilient even if section headers are stripped)
    if b'libbinder_ndk.so' in data:
        meta['is_ndk'] = True
    if b'libbinder.so' in data:
        meta['is_legacy'] = True
    if any(s in data for s in [b'AIBinder_Class_define', b'AServiceManager_addService', b'AServiceManager_registerLazyService']):
        meta['has_ndk_server'] = True
    if any(s in data for s in [b'defaultServiceManager', b'_ZN7android14IPCThreadState']):
        meta['has_legacy_server'] = True
    if re.search(rb'[0-9a-f]{64}', data) or (b'notfrozen' in data):
        meta['has_interface_hash'] = True

    ei_class = data[4]
    endian = '<' if data[5] == 1 else '>'
    is_64 = (ei_class == 2)

    try:
        if is_64:
            e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
                endian + 'QQIHHHHHH', data[32:64]
            )
            sh_fmt = endian + 'IIQQQQIIQQ'
            sym_fmt = endian + 'IBBHQQ'
            dyn_fmt = endian + 'qQ'
            dyn_sz = 16
            sym_sz = 24
        else:
            e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
                endian + 'IIIHHHHHH', data[28:52]
            )
            sh_fmt = endian + 'IIIIIIIIII'
            sym_fmt = endian + 'IIIBBH'
            dyn_fmt = endian + 'iI'
            dyn_sz = 8
            sym_sz = 16

        sections = []
        if e_shoff > 0 and e_shnum > 0 and e_shoff + e_shnum * e_shentsize <= len(data):
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                fields = struct.unpack(sh_fmt, data[off:off+e_shentsize])
                sections.append(fields)

        for sec in sections:
            sh_type = sec[1]
            if sh_type == 6:  # SHT_DYNAMIC
                dyn_off, dyn_size, link = sec[4], sec[5], sec[6]
                if 0 <= link < len(sections):
                    str_sec = sections[link]
                    strtab = data[str_sec[4]:str_sec[4]+str_sec[5]]
                    for j in range(0, dyn_size, dyn_sz):
                        if dyn_off + j + dyn_sz > len(data):
                            break
                        d_tag, d_val = struct.unpack(dyn_fmt, data[dyn_off+j:dyn_off+j+dyn_sz])
                        if d_tag == 0:
                            break
                        if d_tag == 1:  # DT_NEEDED
                            if d_val < len(strtab):
                                end = strtab.find(b'\x00', d_val)
                                if end != -1:
                                    lib_name = strtab[d_val:end].decode('ascii', 'ignore')
                                    meta['needed'].add(lib_name)
                                    if lib_name == 'libbinder_ndk.so':
                                        meta['is_ndk'] = True
                                    elif lib_name == 'libbinder.so':
                                        meta['is_legacy'] = True
            elif sh_type == 11:  # SHT_DYNSYM
                sym_off, sym_size, link = sec[4], sec[5], sec[6]
                if 0 <= link < len(sections):
                    str_sec = sections[link]
                    strtab = data[str_sec[4]:str_sec[4]+str_sec[5]]
                    for j in range(0, sym_size, sym_sz):
                        if sym_off + j + sym_sz > len(data):
                            break
                        fields = struct.unpack(sym_fmt, data[sym_off+j:sym_off+j+sym_sz])
                        if is_64:
                            st_name, st_info, st_other, st_shndx, st_val, st_sz = fields
                        else:
                            st_name, st_val, st_sz, st_info, st_other, st_shndx = fields
                        if st_name < len(strtab):
                            end = strtab.find(b'\x00', st_name)
                            if end != -1:
                                sym_name = strtab[st_name:end].decode('ascii', 'ignore')
                                if st_shndx == 0:
                                    meta['imported'].add(sym_name)
                                    if sym_name in ('AIBinder_Class_define', 'AServiceManager_addService', 'AServiceManager_registerLazyService'):
                                        meta['has_ndk_server'] = True
                                else:
                                    meta['exported'].add(sym_name)
    except Exception:
        pass

    return meta


def scan_so(so_path, registered_descriptors=None):
    """Scan an ELF file for AIDL descriptors and Bn/Bp symbols.

    Returns:
        dict: descriptor -> {'server': bool, 'client': bool, 'backend': str}
    """
    with open(so_path, 'rb') as f:
        data = f.read()

    # Step 1: Extract ELF metadata (DT_NEEDED, dynamic symbols, binder backend)
    elf_meta = extract_elf_metadata(data)

    # Step 2: Find AIDL descriptors from null-separated strings (C++)
    descriptors = set()
    for m in AIDL_DESC_PATTERN.finditer(data):
        try:
            desc = m.group().decode('ascii')
            desc = desc.split('/')[0]
            descriptors.add(desc)
        except UnicodeDecodeError:
            pass

    # Step 2b: Check registered descriptors against binary data (supports UTF-8 and UTF-16LE String16)
    if registered_descriptors:
        for reg_desc in registered_descriptors:
            if (reg_desc.encode('ascii') in data) or (reg_desc.encode('utf-16le') in data):
                descriptors.add(reg_desc)

    # Step 2c: Find AIDL descriptors from Rust v0 mangled symbols
    rust_servers = extract_rust_descriptors(data)
    descriptors.update(rust_servers)

    if not descriptors:
        return {}

    # Step 3: For each descriptor, check Bn/Bp presence and backend classification
    result = {}
    for desc in descriptors:
        iface_full = desc.rsplit('.', 1)[-1]
        if iface_full.startswith('I') and len(iface_full) > 1 and iface_full[1].isupper():
            short_name = iface_full[1:]
        else:
            short_name = iface_full

        bn_str = 'Bn' + short_name
        bp_str = 'Bp' + short_name
        bn_pat = '{}{}'.format(len(bn_str), bn_str).encode('ascii')
        bp_pat = '{}{}'.format(len(bp_str), bp_str).encode('ascii')

        # Direct symbol check (Itanium ABI C++ / Rust mangling)
        has_bn = (bn_pat in data) or (b'Bn' + short_name.encode('ascii') in data)
        has_bp = (bp_pat in data) or (b'Bp' + short_name.encode('ascii') in data)

        is_server = has_bn or (desc in rust_servers)
        is_client = has_bp

        # Stable AIDL / NDK Server heuristics (handles stripped / -fno-rtti binaries):
        if not is_server and (elf_meta['is_ndk'] or elf_meta['has_ndk_server']):
            if elf_meta['has_ndk_server']:
                # The binary imports AIBinder_Class_define or AServiceManager_addService
                is_server = True
            elif registered_descriptors and desc in registered_descriptors:
                # Registered service in service_list.txt and linked with libbinder_ndk
                is_server = True

        # Legacy libbinder server heuristics (handles stripped binaries):
        if not is_server and elf_meta['is_legacy'] and elf_meta['has_legacy_server']:
            if registered_descriptors and desc in registered_descriptors:
                is_server = True

        # Fallback for registered services in binaries with binder dependencies
        if not is_server and registered_descriptors and desc in registered_descriptors:
            if elf_meta['is_ndk'] or elf_meta['is_legacy']:
                is_server = True

        # Client heuristics
        if not is_client:
            if b'AIBinder_transact' in data or b'AServiceManager_getService' in data:
                is_client = True

        # Classify backend
        if (desc in rust_servers) or (b'libbinder_rs' in data):
            backend = 'rust'
        elif elf_meta['is_ndk'] or elf_meta['has_ndk_server'] or (b'AIBinder_' in data):
            backend = 'ndk'
        elif elf_meta['is_legacy'] or elf_meta['has_legacy_server'] or (b'_ZN7android' in data):
            backend = 'libbinder'
        else:
            backend = 'unknown'

        result[desc] = {
            'server': is_server,
            'client': is_client,
            'backend': backend,
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

    # Registered filter: load service_list.txt upfront to assist in server resolution.
    # Accessibility results (accessible_services.txt) drive a separate output.
    registered, name_to_desc, desc_to_names = parse_service_list(workspace)
    accessible = None
    if not ignore_registered:
        logger.info('Registered services: %d', len(registered))
        accessible = load_accessible_services(workspace, name_to_desc)
    elif name_to_desc:
        accessible = load_accessible_services(workspace, name_to_desc)

    # Map: descriptor -> {'servers': set(so_paths), 'clients': set(so_paths), 'backends': set()}
    aidl_map = defaultdict(lambda: {'servers': set(), 'clients': set(), 'backends': set()})

    total = len(elf_files)
    for i, so_path in enumerate(elf_files, 1):
        rel_path = str(so_path.relative_to(workspace))
        logger.info('[%d/%d] %s', i, total, rel_path)

        results = scan_so(so_path, registered)
        for desc, info in results.items():
            if info['server']:
                aidl_map[desc]['servers'].add(rel_path)
            if info['client']:
                aidl_map[desc]['clients'].add(rel_path)
            if info.get('backend') and info['backend'] != 'unknown':
                aidl_map[desc]['backends'].add(info['backend'])

    # Only server entries
    server_ifaces = {desc: info for desc, info in aidl_map.items() if info['servers']}

    # Apply registered filter (default: only registered)
    if not ignore_registered:
        server_ifaces = {desc: info for desc, info in server_ifaces.items() if desc in registered}

    desc_backends = {
        desc: ', '.join(sorted(info['backends'])) if info['backends'] else 'unknown'
        for desc, info in server_ifaces.items()
    }

    output_file = workspace / 'native_aidl.txt'
    write_native_aidl(output_file, server_ifaces, accessible, desc_to_names=desc_to_names, desc_backends=desc_backends)
    logger.info('Output: %s', output_file)
    logger.info('Total: %d server implementations', len(server_ifaces))

    # Accessible subset -> separate output (clean format); original file keeps markers.
    if accessible is not None:
        accessible_ifaces = {d: info for d, info in server_ifaces.items()
                             if accessible.get(d) is True}
        accessible_file = workspace / 'accessible_native_aidl.txt'
        write_native_aidl(accessible_file, accessible_ifaces, desc_to_names=desc_to_names, desc_backends=desc_backends)
        not_accessible = sum(1 for d in server_ifaces if accessible.get(d) is False)
        unknown = sum(1 for d in server_ifaces if d not in accessible)
        logger.info('Accessible output: %s', accessible_file)
        logger.info('Accessibility verification: accessible=%d not_accessible=%d unknown=%d',
                    len(accessible_ifaces), not_accessible, unknown)


def write_native_aidl(output_file, server_ifaces, accessible=None, desc_to_names=None, desc_backends=None):
    with open(output_file, 'w') as f:
        for desc in sorted(server_ifaces.keys()):
            so_list = ', '.join(sorted(server_ifaces[desc]['servers']))
            line = '{} [{}]'.format(desc, so_list)
            if desc_to_names and desc in desc_to_names:
                svc_names = ', '.join(sorted(set(desc_to_names[desc])))
                line += ' [service={}]'.format(svc_names)
            if desc_backends and desc in desc_backends:
                line += ' [backend={}]'.format(desc_backends[desc])
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
