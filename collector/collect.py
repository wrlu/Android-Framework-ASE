import os
import sys
import json
import copy
import argparse
import logging
import subprocess
from collections import namedtuple

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('collect')

CommandResult = namedtuple('CommandResult', ['returncode', 'stdout', 'stderr'])

settings_table = ['global', 'system', 'secure']


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
            logger.warning('adb pull failed: %s (rc=%d)', remote, r.returncode)
        return r.returncode == 0

    def root(self):
        return self._run('root')

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


def dump_apex_folder(device, apex, workspace):
    mounted_apex_path = '/apex/' + apex['apex_name']
    device.pull(mounted_apex_path, apex['apex_name'], cwd=os.path.join(workspace, 'apex'))


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
    output = device.shell('pm', 'list', 'packages', '--user', '0', '-f', '--apex-only').decode('ascii')
    apexes = parse_pm_list(output, with_uid=False)
    apex_dir = os.path.join(workspace, 'apex')
    os.makedirs(apex_dir, exist_ok=True)
    with open(os.path.join(workspace, 'apex_index.csv'), 'w') as f:
        f.write('apex_name,path\n')
        total = len(apexes)
        for i, apex in enumerate(apexes):
            f.write(apex['apex_name'] + ',' + apex['path'] + '\n')
            f.flush()
            dump_apex_folder(device, apex, workspace)
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


def run_metadata_commands(device, workspace):
    with open(os.path.join(workspace, 'service_list.txt'), 'wb') as f:
        f.write(device.shell_with_root('service', 'list'))
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

    logger.info('[Task 4] Dump binaries')
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
    exclusive_group = parser.add_mutually_exclusive_group()
    exclusive_group.add_argument('-s', '--system', action='store_true', help='Only dump system packages.')
    exclusive_group.add_argument('-3', '--third-party', action='store_true', help='Only dump third party packages.')
    args = parser.parse_args()

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
        run_metadata_commands(device, workspace)
    finally:
        cleanup_tmp(device)

    logger.info('Done')


if __name__ == '__main__':
    main()
