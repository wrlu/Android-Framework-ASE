import os
import sys
import re
import json
import copy
import argparse
import logging
import subprocess
import xml.etree.ElementTree as ET
from collections import namedtuple

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('collect')

CommandResult = namedtuple('CommandResult', ['returncode', 'stdout', 'stderr'])

settings_table = ['global', 'system', 'secure']

ASE_PACKAGE = 'net.wrlu.ase'
ASE_PROVIDER_URI = 'content://net.wrlu.ase.probe/binder_service'
ASE_PROJECT_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'AttackSurfaceExplorer'))
PREBUILT_ASE_APK = os.path.normpath(os.path.join(ASE_PROJECT_DIR, 'app-release.apk'))
BUILT_ASE_APK = os.path.normpath(os.path.join(
    ASE_PROJECT_DIR, 'app', 'build', 'outputs', 'apk', 'release', 'app-release.apk'))
DEFAULT_ASE_APK = PREBUILT_ASE_APK


def run_command(cmds, cwd='.'):
    try:
        result = subprocess.run(cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=cwd, check=False)
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except FileNotFoundError:
        logger.error('Command not found: %s', cmds[0])
        return CommandResult(127, b'', b'command not found')


class AdbDevice:
    def __init__(self, serial, status='device'):
        self.serial = serial
        self.status = status
        self._root_status = None
        self._fingerprint = None

    def _run(self, *args, cwd='.'):
        return run_command(['adb', '-s', self.serial, *args], cwd=cwd)

    def shell(self, *cmd):
        return self._run('shell', *cmd).stdout

    def shell_su(self, *cmd):
        return self._run('shell', 'su', '-c', ' '.join(cmd)).stdout

    def shell_with_root(self, *cmd):
        if self.root_status == 'su_root':
            return self.shell_su(*cmd)
        return self.shell(*cmd)

    def pull(self, remote, dest_name=None, cwd='.'):
        args = ['pull', remote]
        if dest_name:
            args.append(dest_name)
        r = self._run(*args, cwd=cwd)
        if r.returncode != 0:
            if sys.stderr.isatty():
                sys.stderr.write('\n')
                sys.stderr.flush()
            logger.warning('adb pull failed: %s (rc=%d)', remote, r.returncode)
        return r.returncode == 0

    def root(self):
        return self._run('root')

    def install(self, apk, replace=True, grant=True):
        args = ['install']
        if replace:
            args.append('-r')
        if grant:
            args.append('-g')
        args.append(apk)
        return self._run(*args)

    def whoami(self):
        return self.shell('whoami').decode('ascii').strip()

    def get_prop(self, name):
        return self.shell('getprop', name).decode('ascii').strip()

    @property
    def root_status(self):
        if self._root_status is None:
            self.root()
            if self.whoami() == 'root':
                self._root_status = 'adb_root'
            elif self.shell_su('whoami').decode('ascii').strip() == 'root':
                self._root_status = 'su_root'
            else:
                self._root_status = 'shell'
        return self._root_status

    @property
    def build_fingerprint(self):
        if self._fingerprint is None:
            self._fingerprint = self.get_prop('ro.build.fingerprint')
        return self._fingerprint


def list_adb_devices():
    output = run_command(['adb', 'devices']).stdout.decode('ascii')
    devices = []
    for line in output.split('\n'):
        line = line.strip()
        if '\t' in line:
            parts = line.split('\t')
            serial, status = parts[0], parts[1]
            dev = AdbDevice(serial, status)
            if status == 'device':
                dev._fingerprint = dev.get_prop('ro.build.fingerprint')
                _ = dev.root_status
            else:
                dev._fingerprint = 'unknown'
                dev._root_status = 'unknown'
            devices.append(dev)
    return devices


def select_device(pre_select_serial=None):
    devices = list_adb_devices()
    if not devices:
        logger.error('No adb devices found.')
        return None

    if pre_select_serial:
        for dev in devices:
            if dev.serial == pre_select_serial:
                if dev.status != 'device':
                    logger.warning('Device not available, status is: %s', dev.status)
                    return None
                if dev.root_status == 'shell':
                    logger.warning('Non-root device, can only dump less binaries & libraries due to permission issue.')
                return dev
        logger.error('Device %s not found.', pre_select_serial)
        return None

    logger.info('Please select an adb device:')
    for i, dev in enumerate(devices, 1):
        if dev.status == 'device':
            logger.info('%d => %s\t%s\t%s', i, dev.serial, dev.build_fingerprint, dev.root_status)
        else:
            logger.info('%d => %s\t%s', i, dev.serial, dev.status)

    select = int(input())
    logger.info('You select device on line %d', select)
    if select > len(devices):
        logger.error('Out of range.')
        return None
    dev = devices[select - 1]
    if dev.status != 'device':
        logger.warning('Device not available, status is: %s', dev.status)
        return None
    if dev.root_status == 'shell':
        logger.warning('Non-root device, can only dump less binaries & libraries due to permission issue.')
    return dev


def list_packages(device, scope='all'):
    args = ['pm', 'list', 'packages', '--user', '0', '-f', '-U']
    if scope == 'system':
        args.append('-s')
    elif scope == 'third':
        args.append('-3')
    return device.shell(*args).decode('ascii')


def parse_pm_list(output, with_uid=False):
    items = []
    for line in output.split('\n'):
        line = line.strip().strip('package:')
        if with_uid:
            if '=' in line and ' ' in line:
                path = line[:line.rindex('=')]
                rest = line[line.rindex('=') + 1:]
                name = rest[:rest.rindex(' ')]
                uid = rest[rest.rindex(' ') + 1:].strip('uid:')
                if ',' in uid:
                    uid = uid.split(',')[0]
                items.append({'package_name': name, 'path': path, 'uid': uid})
        else:
            if '=' in line:
                path = line[:line.rindex('=')]
                name = line[line.rindex('=') + 1:]
                items.append({'apex_name': name, 'path': path})
    return items


def dump_apk_folder(device, package, workspace):
    apk_folder = package['path'][:package['path'].rindex('/')]
    if package['package_name'] == 'com.miui.rom':
        apk_folder = '/system_ext/framework'
    dest_dir = os.path.join(workspace, 'packages', package['package_name'])
    os.makedirs(dest_dir, exist_ok=True)
    file_list = device.shell('ls', '-1', apk_folder).decode('ascii', 'ignore').strip()
    for filename in file_list.split('\n'):
        filename = filename.strip()
        if not filename:
            continue
        if 'auto_generated_rro' in filename:
            continue
        if filename == 'oat':
            continue
        if filename == 'app.metadata':
            continue
        if filename.endswith('.digests'):
            continue
        device.pull(apk_folder + '/' + filename, filename, cwd=dest_dir)


def get_apex_mount_info(device):
    """Parse active APEX mounts and apex-info-list.xml from device."""
    mounted_paths = set()
    try:
        proc_mounts = device.shell('cat', '/proc/mounts').decode('utf-8', 'ignore')
        for line in proc_mounts.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2 and parts[1].startswith('/apex/'):
                p = parts[1]
                if p != '/apex/apex-info-list.xml':
                    mounted_paths.add(p)
    except Exception:
        pass

    path_map = {}
    module_map = {}
    try:
        xml_out = device.shell('cat', '/apex/apex-info-list.xml').decode('utf-8', 'ignore')
        if xml_out.strip().startswith('<?xml') or '<apex-info-list>' in xml_out:
            root = ET.fromstring(xml_out)
            for info in root.findall('apex-info'):
                if info.get('isActive') == 'true':
                    mname = info.get('moduleName')
                    vcode = info.get('versionCode')
                    mpath = info.get('modulePath')
                    prepath = info.get('preinstalledModulePath')

                    actual_mount = None
                    cands = [f'/apex/{mname}', f'/apex/{mname}@{vcode}']
                    for c in cands:
                        if c in mounted_paths:
                            actual_mount = c
                            break
                    if not actual_mount:
                        for mp in mounted_paths:
                            if mp == f'/apex/{mname}' or mp.startswith(f'/apex/{mname}@'):
                                actual_mount = mp
                                break
                    if not actual_mount:
                        actual_mount = f'/apex/{mname}'

                    module_map[mname] = actual_mount
                    if mpath:
                        path_map[mpath] = actual_mount
                    if prepath:
                        path_map[prepath] = actual_mount
    except Exception:
        pass

    mount_by_name = {}
    for mp in mounted_paths:
        name = mp[len('/apex/'):]
        mount_by_name[name] = mp
        if '@' in name:
            base_name = name.split('@')[0]
            if base_name not in mount_by_name:
                mount_by_name[base_name] = mp

    return {
        'path_map': path_map,
        'module_map': module_map,
        'mount_by_name': mount_by_name,
        'mounted_paths': mounted_paths,
    }


def resolve_mounted_apex_path(apex, mount_info):
    """Resolve the actual mounted directory under /apex for a given APEX entry."""
    name = apex.get('apex_name', '')
    path = apex.get('path', '')

    path_map = mount_info.get('path_map', {})
    module_map = mount_info.get('module_map', {})
    mount_by_name = mount_info.get('mount_by_name', {})

    # 1. Exact match from xml modulePath or preinstalledModulePath
    if path and path in path_map:
        return path_map[path]

    # 2. Match from xml moduleName
    if name and name in module_map:
        return module_map[name]

    # 3. Direct match in mount_by_name
    if name and name in mount_by_name:
        return mount_by_name[name]

    # 4. Extract base name from apex file path
    base = ''
    if path:
        base = os.path.basename(path).split('@')[0]
        for ext in ('.decompressed.apex', '.decompressed.capex', '.apex', '.capex'):
            if base.endswith(ext):
                base = base[:-len(ext)]
                break
        if base in module_map:
            return module_map[base]
        if base in mount_by_name:
            return mount_by_name[base]

    # 5. Transform name variants (e.g. com.google.android.* -> com.android.*)
    candidates = [name]
    if base:
        candidates.append(base)
    if name.startswith('com.google.android.'):
        candidates.append('com.android.' + name[len('com.google.android.'):])
    if name.startswith('com.google.'):
        candidates.append(name[len('com.google.'):])
        candidates.append('com.' + name[len('com.google.'):])

    for c in list(candidates):
        c_stripped = re.sub(r'[\d\-_]+$', '', c)
        if c_stripped and c_stripped != c:
            candidates.append(c_stripped)

    for c in candidates:
        if c in module_map:
            return module_map[c]
        if c in mount_by_name:
            return mount_by_name[c]

    # 6. Prefix match against mounted directories
    for c in candidates:
        for mname, mp in mount_by_name.items():
            if mname.startswith(c) or c.startswith(mname):
                return mp

    return '/apex/' + name


def dump_apex_folder(device, apex, workspace, mount_info=None):
    if mount_info is None:
        mount_info = get_apex_mount_info(device)
    mounted_apex_path = resolve_mounted_apex_path(apex, mount_info)
    apex_dir = os.path.join(workspace, 'apex')
    ok = device.pull(mounted_apex_path, apex['apex_name'], cwd=apex_dir)
    mounted_name = os.path.basename(mounted_apex_path).split('@')[0]
    if ok and mounted_name and mounted_name != apex['apex_name']:
        link_path = os.path.join(apex_dir, mounted_name)
        if not os.path.exists(link_path):
            try:
                os.symlink(apex['apex_name'], link_path)
            except OSError:
                pass
    return ok


def dump_binary_folder(device, binary_path, partition, workspace, sub_dir):
    if device.root_status == 'adb_root':
        device.pull(binary_path, cwd=os.path.join(workspace, sub_dir))
    else:
        device.shell_with_root('cp', '-r', binary_path,
                               os.path.join('/sdcard/.dump_android_script/', partition))
        device.pull(os.path.join('/sdcard/.dump_android_script/', binary_path[1:]),
                    cwd=os.path.join(workspace, sub_dir))


def dump_binary_folder_directly(device, binary_path, workspace, sub_dir):
    device.pull(binary_path, cwd=os.path.join(workspace, sub_dir))


def dump_selinux_policy(device, workspace):
    selinux_dir = os.path.join(workspace, 'selinux')
    os.makedirs(selinux_dir, exist_ok=True)
    device.pull('/sys/fs/selinux/policy', cwd=selinux_dir)
    link_if_exists(os.path.join(workspace, 'system', 'etc', 'selinux'),
                   os.path.join(selinux_dir, 'selinux'))


def dump_permissions_policy_xml(device, workspace):
    perms_dir = os.path.join(workspace, 'permissions')
    os.makedirs(perms_dir, exist_ok=True)
    for part, name in [('system', 'system_permissions'),
                       ('system_ext', 'system_ext_permissions'),
                       ('product', 'product_permissions'),
                       ('vendor', 'vendor_permissions')]:
        link_if_exists(os.path.join(workspace, part, 'etc', 'permissions'),
                       os.path.join(perms_dir, name))


BAR_WIDTH = 30

def show_progress(now, total, msg):
    if total == 0:
        return
    p = min((now * 100) // total, 100)
    filled = (p * BAR_WIDTH) // 100
    if filled == 0:
        bar = '>' + ' ' * (BAR_WIDTH - 1)
    elif filled >= BAR_WIDTH:
        bar = '=' * BAR_WIDTH
    else:
        bar = '=' * (filled - 1) + '>' + ' ' * (BAR_WIDTH - filled)
    if sys.stderr.isatty():
        sys.stderr.write('\r\033[K[%s] %3d%% %s' % (bar, p, msg))
        sys.stderr.flush()
        if now >= total:
            sys.stderr.write('\n')
    else:
        logger.info('[%s] %3d%% %s', bar, p, msg)


def gen_jadx_project_file(packages_dir):
    template = {"projectVersion": 1, "files": []}
    for package in os.listdir(packages_dir):
        if 'auto_generated_rro_product' in package:
            continue
        package_dir = os.path.join(packages_dir, package)
        if os.path.isdir(package_dir):
            jadx_file = os.path.join(package_dir, package + '.jadx')
            content = copy.deepcopy(template)
            for file in os.listdir(package_dir):
                full = os.path.join(package_dir, file)
                if 'auto_generated_rro_product' in file:
                    continue
                if os.path.isfile(full) and (file.endswith('.apk') or file.endswith('.jar') or file.endswith('.dex')):
                    content['files'].append(file)
            with open(jadx_file, 'w') as f:
                json.dump(content, f)


def dump_packages(device, workspace, pkg_filter_mode):
    scope = 'all' if pkg_filter_mode == 0 else ('system' if pkg_filter_mode == 1 else 'third')
    packages = parse_pm_list(list_packages(device, scope), with_uid=True)
    # Skip AttackSurfaceExplorer itself (installed by the collector for probing)
    packages = [p for p in packages if p['package_name'] != ASE_PACKAGE]
    packages_dir = os.path.join(workspace, 'packages')
    os.makedirs(packages_dir, exist_ok=True)
    with open(os.path.join(workspace, 'package_index.csv'), 'w') as f:
        f.write('package_name,path,uid\n')
        total = len(packages)
        for i, package in enumerate(packages):
            f.write(package['package_name'] + ',' + package['path'] + ',' + package['uid'] + '\n')
            f.flush()
            if '/overlay/' in package['path']:
                continue
            dump_apk_folder(device, package, workspace)
            show_progress(i + 1, total, 'Dump package binaries for ' + package['package_name'])


def dump_apexes(device, workspace):
    mount_info = get_apex_mount_info(device)
    output = device.shell('pm', 'list', 'packages', '--user', '0', '-f', '--apex-only').decode('ascii', 'ignore')
    apexes = parse_pm_list(output, with_uid=False)
    if not apexes and mount_info.get('mounted_paths'):
        for mp in sorted(mount_info['mounted_paths']):
            mname = os.path.basename(mp).split('@')[0]
            apexes.append({'apex_name': mname, 'path': mp})
    apex_dir = os.path.join(workspace, 'apex')
    os.makedirs(apex_dir, exist_ok=True)
    with open(os.path.join(workspace, 'apex_index.csv'), 'w') as f:
        f.write('apex_name,path\n')
        total = len(apexes)
        for i, apex in enumerate(apexes):
            f.write(apex['apex_name'] + ',' + apex['path'] + '\n')
            f.flush()
            dump_apex_folder(device, apex, workspace, mount_info=mount_info)
            show_progress(i + 1, total, 'Dump apex binaries for ' + apex['apex_name'])


def dump_overlays(device, workspace):
    overlay_dir = os.path.join(workspace, 'overlay')
    os.makedirs(overlay_dir, exist_ok=True)
    with open(os.path.join(workspace, 'overlay_index.csv'), 'w') as f:
        f.write('overlay_path\n')
        for part in ['vendor', 'product']:
            src_dir = '/' + part + '/overlay'
            listing = device.shell('find', src_dir, '-name', '*.apk', '-type', 'f').decode('ascii', 'ignore').strip()
            if not listing:
                continue
            apk_paths = [p.strip() for p in listing.split('\n') if p.strip()]
            total = len(apk_paths)
            for i, apk_path in enumerate(apk_paths):
                if 'auto_generated_rro' in apk_path:
                    continue
                name = apk_path[apk_path.rindex('/') + 1:]
                device.pull(apk_path, name, cwd=overlay_dir)
                f.write(apk_path + '\n')
                f.flush()
                show_progress(i + 1, total, 'Dump overlay ' + name)


def build_ase_apk():
    """Build the AttackSurfaceExplorer release APK via its Gradle wrapper."""
    gradlew = os.path.join(ASE_PROJECT_DIR, 'gradlew')
    if not os.path.isfile(gradlew):
        logger.warning('AttackSurfaceExplorer project not found: %s', ASE_PROJECT_DIR)
        return False
    logger.info('Build AttackSurfaceExplorer release APK')
    r = run_command([gradlew, ':app:assembleRelease'], cwd=ASE_PROJECT_DIR)
    if r.returncode != 0:
        logger.warning('Failed to build ASE APK: %s',
                       r.stderr.decode('ascii', 'ignore').strip())
        return False
    return True


def resolve_ase_apk(user_specified_apk=None):
    """Resolve which AttackSurfaceExplorer APK to use.

    Priority:
    1. User explicitly specified path (via --ase-apk).
    2. Precompiled release APK in AttackSurfaceExplorer/app-release.apk.
    3. Previously built APK in AttackSurfaceExplorer/app/build/.../app-release.apk.
    4. Automatically trigger build via gradlew :app:assembleRelease.
    """
    if user_specified_apk:
        if os.path.isfile(user_specified_apk):
            return user_specified_apk
        logger.warning('User-specified ASE APK not found: %s', user_specified_apk)
        return None

    if os.path.isfile(PREBUILT_ASE_APK):
        logger.info('Using precompiled AttackSurfaceExplorer APK: %s', PREBUILT_ASE_APK)
        return PREBUILT_ASE_APK

    if os.path.isfile(BUILT_ASE_APK):
        logger.info('Using existing built AttackSurfaceExplorer APK: %s', BUILT_ASE_APK)
        return BUILT_ASE_APK

    logger.info('No precompiled or built APK found, building AttackSurfaceExplorer release APK...')
    if build_ase_apk() and os.path.isfile(BUILT_ASE_APK):
        return BUILT_ASE_APK

    return None


def dump_accessible_services(device, workspace, ase_apk=None):
    """Install AttackSurfaceExplorer and probe binder service accessibility.

    Resolves the release APK (prioritizing precompiled APK, then built APK or building),
    installs it via overwrite (-r -g), then queries its ContentProvider and writes
    accessible_services.txt. When the APK is missing or the provider is unavailable
    the file is skipped (analyzers then run without accessibility verification).
    """
    resolved_apk = resolve_ase_apk(ase_apk)
    if not resolved_apk or not os.path.isfile(resolved_apk):
        logger.warning('ASE APK not found (skip accessible_services.txt)')
        return
    logger.info('Install AttackSurfaceExplorer APK (overwrite): %s', resolved_apk)
    r = device.install(resolved_apk)
    if r.returncode != 0:
        logger.warning('Failed to install ASE APK (skip accessible_services.txt): %s',
                       r.stderr.decode('ascii', 'ignore').strip())
        return

    output = device.shell('content', 'query', '--uri', ASE_PROVIDER_URI)
    if not output or b'Row:' not in output:
        logger.warning('No accessible result from AttackSurfaceExplorer '
                       '(skip accessible_services.txt)')
        return
    with open(os.path.join(workspace, 'accessible_services.txt'), 'wb') as f:
        f.write(output)


def run_metadata_commands(device, workspace, ase_apk):
    with open(os.path.join(workspace, 'service_list.txt'), 'wb') as f:
        f.write(device.shell_with_root('service', 'list'))
    dump_accessible_services(device, workspace, ase_apk)
    with open(os.path.join(workspace, 'lshal.txt'), 'wb') as f:
        f.write(device.shell_with_root('lshal'))
    with open(os.path.join(workspace, 'netstat.txt'), 'wb') as f:
        f.write(device.shell_with_root('netstat', '-nlptu'))
    with open(os.path.join(workspace, 'getprop.txt'), 'wb') as f:
        f.write(device.shell('getprop'))
    perms_dir = os.path.join(workspace, 'permissions')
    os.makedirs(perms_dir, exist_ok=True)
    with open(os.path.join(perms_dir, 'permissions.txt'), 'wb') as f:
        f.write(device.shell('pm', 'list', 'permissions', '-f'))
    dump_permissions_policy_xml(device, workspace)
    for table in settings_table:
        with open(os.path.join(workspace, 'settings_' + table + '.txt'), 'wb') as f:
            f.write(device.shell('settings', 'list', table))


def link_if_exists(src, dst):
    if os.path.exists(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.lexists(dst):
            os.remove(dst)
        os.symlink(os.path.abspath(src), dst)


def dump_binaries(device, workspace):
    root_status = device.root_status
    for part in ['system', 'vendor', 'system_ext', 'product', 'odm']:
        os.makedirs(os.path.join(workspace, part), exist_ok=True)
    if root_status != 'adb_root':
        device.shell('mkdir', '/sdcard/.dump_android_script/')
        for p in ['system', 'vendor', 'system_ext', 'product', 'odm']:
            device.shell('mkdir', '/sdcard/.dump_android_script/' + p)

    for part in ['system', 'vendor', 'system_ext', 'product', 'odm']:
        for sub in ['bin', 'lib64', 'lib', 'etc']:
            dump_binary_folder(device, '/' + part + '/' + sub + '/', part, workspace, part)

    if root_status != 'adb_root':
        device.shell('rm', '-rf', '/sdcard/.dump_android_script')


def dump_init_scripts(device, workspace):
    init_dir = os.path.join(workspace, 'init')
    os.makedirs(init_dir, exist_ok=True)
    for part, name in [('system', 'system_init'), ('vendor', 'vendor_init'), ('odm', 'odm_init')]:
        link_if_exists(os.path.join(workspace, part, 'etc', 'init'),
                       os.path.join(init_dir, name))


def cleanup_tmp(device):
    device.shell('rm', '-rf', '/sdcard/.dump_android_script')


def main():
    parser = argparse.ArgumentParser(description='Dump useful files from Android devices.')
    parser.add_argument('-o', '--output', help='Output directory for dumped firmware (default: current directory).')
    parser.add_argument('-d', '--device', help='adb serial id (non-interactive selection).')
    parser.add_argument('--ase-apk', help='AttackSurfaceExplorer APK installed before probing '
                                         '(default: precompiled AttackSurfaceExplorer/app-release.apk).')
    parser.add_argument('--probe-only', action='store_true',
                        help='Only run the binder service accessibility probe and generate accessible_services.txt.')
    exclusive_group = parser.add_mutually_exclusive_group()
    exclusive_group.add_argument('-s', '--system', action='store_true', help='Only dump system packages.')
    exclusive_group.add_argument('-3', '--third-party', action='store_true', help='Only dump third party packages.')
    args = parser.parse_args()

    ase_apk = args.ase_apk

    pkg_filter_mode = 0
    if args.system:
        pkg_filter_mode = 1
        logger.info('-s or --system: will only dump system packages.')
    elif args.third_party:
        pkg_filter_mode = 2
        logger.info('-3 or --third-party detected: will only dump third party packages.')

    workspace = args.output or '.'
    os.makedirs(workspace, exist_ok=True)

    device = select_device(args.device)
    if device is None:
        return

    if args.probe_only:
        logger.info('[Probe] Run binder service probe only')
        dump_accessible_services(device, workspace, ase_apk)
        logger.info('Done')
        return

    try:
        logger.info('[Task 1] Dump Android framework & Apps')
        dump_packages(device, workspace, pkg_filter_mode)
        gen_jadx_project_file(os.path.join(workspace, 'packages'))

        if pkg_filter_mode == 2:
            logger.info('Third-party mode, skip apex/selinux/binaries dump.')
            return

        dump_apexes(device, workspace)
        dump_overlays(device, workspace)
        logger.info('[Task 2] Dump binaries')
        dump_binaries(device, workspace)
        logger.info('[Task 3] Dump SELinux policy & init scripts & permissions')
        dump_selinux_policy(device, workspace)
        dump_init_scripts(device, workspace)
        logger.info('[Task 4] Run useful commands')
        run_metadata_commands(device, workspace, ase_apk)
    finally:
        cleanup_tmp(device)

    logger.info('Done')


if __name__ == '__main__':
    main()
