#!/usr/bin/env python3
"""Vodafone HU для всех обнаруженных SIM по полному IMSI."""
from __future__ import annotations
import argparse
import asyncio
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent

PARENT = '/var/mobile/Library/Carrier Bundles'
TARGET = PARENT + '/iPhone'
PAYLOAD_PATH = 'q0/q1/q2/q3/q4/payload'
BUNDLE = 'Vodafone_hu.bundle'
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 4000
BOOK_FILES = ('Books/Books.plist', 'Books/Sync/Books.plist', 'Books/Sync/Upload.plist',
              'Books/Sync/Database/OutstandingAssets_4.sqlite',
              'Books/Sync/Database/OutstandingAssets_4.sqlite-shm',
              'Books/Sync/Database/OutstandingAssets_4.sqlite-wal')
BOOK_DIRS = ('Books', 'Books/Managed', 'Books/Sync', 'Books/Sync/Database')



def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def recover_hint():
    # The launcher menu runs this script with CARRIERSIM_MENU=1; its users never type flags.
    if os.environ.get('CARRIERSIM_MENU'):
        return 'выберите в меню пункт 5 «Восстановить после сбоя»'
    return 'запустите скрипт с флагом --recover'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def save_json(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)

def safe_name(name):
    require(bool(name) and not name.startswith('/') and '\\' not in name and
            all(p not in ('', '.', '..') for p in name.split('/')), 'Unsafe tree path: ' + name)
    return name


def validate_tree(tree):
    require(len(tree) <= MAX_NODES, 'Too many tree nodes')
    require(sum(len(v[1]) for v in tree.values()) <= MAX_BYTES, 'Tree too large')
    for name, (kind, data) in tree.items():
        safe_name(name)
        require(kind in ('d', 'f', 'l'), 'Unknown node type')
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                require(tree.get(str(parent), (None,))[0] == 'd', 'Missing or non-directory parent')
        if kind == 'l':
            require(b'\x00' not in data and len(data) <= 4096, 'Invalid symlink')

def tree_hash(tree):
    return digest(json.dumps({n: [k, digest(b)] for n, (k, b) in sorted(tree.items())},
                             sort_keys=True).encode())

def zi(name, kind, streaming=False):
    mode = {'f': stat.S_IFREG | 0o644, 'd': stat.S_IFDIR | 0o755,
            'l': stat.S_IFLNK | 0o777}[kind]
    z = zipfile.ZipInfo(name + ('/' if kind == 'd' and not name.endswith('/') else ''),
                        (2026, 9, 24, 0, 0, 0))
    z.create_system = 3
    z.external_attr = mode << 16
    if streaming:
        z.extra = struct.pack('<HHH', 0x5A53, 2, mode)
    return z

def write_tree_zip(path, tree):
    validate_tree(tree)
    with zipfile.ZipFile(path, 'x') as z:
        for name, (kind, data) in sorted(tree.items()):
            z.writestr(zi(name, kind), data)

def read_tree_zip(path):
    tree = {}
    with zipfile.ZipFile(path) as z:
        require(len(z.infolist()) <= MAX_NODES and sum(i.file_size for i in z.infolist()) <= MAX_BYTES,
                'Archive too large')
        for i in z.infolist():
            name = safe_name(i.filename.rstrip('/'))
            require(name not in tree, 'Duplicate archive entry')
            mode = stat.S_IFMT(i.external_attr >> 16)
            require(mode in (0, stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK), 'Unsupported archive type')
            tree[name] = ('d' if i.is_dir() else 'l' if mode == stat.S_IFLNK else 'f', z.read(i))
    validate_tree(tree)
    return tree

def bundle_info(tree, name=BUNDLE):
    prefix = name + '/'
    def pl(file):
        value = tree.get(prefix + file)
        require(value is not None and value[0] == 'f', 'Missing ' + prefix + file)
        return plistlib.loads(value[1])
    info, carrier = pl('Info.plist'), pl('carrier.plist')
    require(any(n.startswith(prefix + 'signatures/') and k == 'f' for n, (k, _) in tree.items()),
            'No signature files (presence is not cryptographic verification)')
    return info, carrier

def staging_archive(payload=None):
    # Six staging levels keep system links inside the ZIP while unpacking.
    # After placement the same six '..' components resolve from /private/var/mobile/... to /.
    tree = {'META-INF': ('d', b''), 'META-INF/com.apple.ZipMetadata.plist':
            ('f', plistlib.dumps({'Version': 2}, fmt=plistlib.FMT_BINARY)),
            'p0': ('d', b''), 'p0/p1': ('d', b''), 'p0/p1/p2': ('d', b''),
            'p0/p1/p2/link': ('l', ('../../../' + PARENT[1:]).encode())}
    def directories(path):
        cursor = ''
        for part in path.split('/'):
            cursor += ('/' if cursor else '') + part
            tree[cursor] = ('d', b'')
    directories(PARENT[1:])
    if payload is not None:
        directories(PAYLOAD_PATH)
        system_names = set(TARGET_BUNDLES)
        for kind, data in payload.values():
            if kind == 'l' and data.startswith(SYSTEM_PREFIX.encode()):
                name = data.decode().removeprefix(SYSTEM_PREFIX)
                require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle', name), 'Неожиданная системная ссылка')
                system_names.add(name)
        for name in system_names:
            directories('System/Library/Carrier Bundles/iPhone/'+name)
        tree.update({PAYLOAD_PATH+'/'+n:v for n,v in payload.items()})
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', allowZip64=False) as z:
        for name, (kind, data) in sorted(tree.items()):
            z.writestr(zi(name, kind, streaming=True), data)
    return b.getvalue()

async def exists(afc, path):
    from pymobiledevice3.exceptions import AfcFileNotFoundError
    try:
        return await afc.stat(path)
    except AfcFileNotFoundError:
        return None

async def remote_tree(afc, root):
    tree = {}
    total = 0
    async def visit(path, name='', depth=0):
        nonlocal total
        require(depth < 32 and len(tree) < MAX_NODES, 'Remote tree limit')
        before = await afc.stat(path)
        kind = before['st_ifmt']
        if kind == 'S_IFDIR':
            if name:
                tree[name] = ('d', b'')
            children = sorted(await afc.listdir(path))
            for child in children:
                require(child not in ('', '.', '..') and '/' not in child, 'Invalid remote name')
                await visit(path + '/' + child, name + '/' + child if name else child, depth + 1)
            require(children == sorted(await afc.listdir(path)), 'Remote directory changed')
        elif kind == 'S_IFLNK':
            require(name, 'Root is a symlink')
            tree[name] = ('l', before['LinkTarget'].encode())
        elif kind == 'S_IFREG':
            require(name and before['st_size'] <= MAX_BYTES, 'Remote file limit')
            data = await afc.get_file_contents(path)
            total += len(data)
            require(total <= MAX_BYTES and len(data) == before['st_size'], 'Remote size mismatch')
            tree[name] = ('f', data)
        else:
            raise RuntimeError('Unsupported remote node: ' + path)
        after = await afc.stat(path)
        require(before == after, 'Remote file changed during read: ' + path)
    require((await afc.stat(root))['st_ifmt'] == 'S_IFDIR', 'Carrier root is not a directory')
    await visit(root)
    validate_tree(tree)
    return tree

async def books_snapshot(afc, run):
    # Preserve the entire Books tree, but only restore known sync artifacts automatically.
    node = await exists(afc, 'Books')
    tree = await remote_tree(afc, 'Books') if node else {}
    write_tree_zip(run / 'books.zip', tree)
    state = {'existed': bool(node), 'hash': tree_hash(tree)}
    save_json(run / 'books.json', state)
    require(tree == (await remote_tree(afc, 'Books') if node else {}), 'Books changed before staging')
    for path in BOOK_FILES:
        rel = path.removeprefix('Books/')
        require(rel not in tree or tree[rel][0] == 'f', 'Unexpected Books sync artifact')
    for path in BOOK_DIRS[1:]:
        rel = path.removeprefix('Books/')
        require(rel not in tree or tree[rel][0] == 'd', 'Unexpected Books directory')
    return tree, bool(node)

async def restore_books(afc, tree, existed):
    for path in BOOK_FILES:
        rel = path.removeprefix('Books/')
        current = await exists(afc, path)
        require(current is None or current['st_ifmt'] == 'S_IFREG', 'Unexpected Books artifact; keep backup')
        if rel in tree:
            await afc.makedirs(str(PurePosixPath(path).parent))
            await afc.set_file_contents(path, tree[rel][1])
            require(await afc.get_file_contents(path) == tree[rel][1], 'Books restore mismatch')
        elif current:
            await afc.rm_single(path)
    # AirTraffic created these empty lock files during the first physical test.
    # Never delete a pre-existing lock or one with unexpected contents/type.
    for rel in ('Managed/.Managed.plist.lock', 'Sync/.bookSync.lock'):
        if rel not in tree:
            path = 'Books/' + rel
            node = await exists(afc, path)
            if node is not None:
                require(node['st_ifmt'] == 'S_IFREG' and node['st_size'] == 0,
                        'Unexpected generated Books lock; retain backup')
                await afc.rm_single(path)
    for path in reversed(BOOK_DIRS):
        was_present = existed if path == 'Books' else path.removeprefix('Books/') in tree
        if not was_present and await exists(afc, path) and not await afc.listdir(path):
            await afc.rm_single(path)
    after = await remote_tree(afc, 'Books') if await exists(afc, 'Books') else {}
    diff = sorted(n for n in tree.keys() | after.keys() if tree.get(n) != after.get(n))
    require(not diff, 'Не удалось вернуть служебную папку Books на iPhone в исходное состояние. '
            'Копии сохранены в папке runs — не удаляйте её. Сообщите автору текст этой ошибки. '
            'Отличаются: ' + ', '.join(diff[:10]))


# Device-side view of an AirTraffic session: atc decides which assets enter the manifest.
DEVICE_LOG_KEYS = ('atc', 'airtraffic', 'book', 'sandbox', 'deny', 'airlift', 'carrier bundles',
                   'itunes', 'medialibrary', 'mobile.lockdown')


@contextlib.asynccontextmanager
async def device_log(device, path):
    from pymobiledevice3.services.syslog import SyslogService
    ready = asyncio.Event()
    async def watch():
        try:
            async with SyslogService(device) as log:
                ready.set()
                size = 0
                with path.open('w', encoding='utf-8') as f:
                    async for row in log.watch():
                        line = row.decode(errors='replace') if isinstance(row, bytes) else row
                        low = line.lower()
                        if any(k in low for k in DEVICE_LOG_KEYS):
                            size += len(line)
                            if size > 16 * 1024 * 1024: break
                            f.write(line + '\n'); f.flush()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            with contextlib.suppress(Exception):
                with path.open('a', encoding='utf-8') as f: f.write('LOG ERROR: ' + repr(error) + '\n')
        finally:
            ready.set()
    task = asyncio.create_task(watch())
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(ready.wait(), 10)
    try:
        yield
    finally:
        await asyncio.sleep(1)  # let the phone flush the last lines
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


async def transfer(device, run, payload=None, expected=None, recovery=False):
    from pymobiledevice3.services.afc import AfcService
    run.mkdir(parents=True, exist_ok=False)
    token = os.urandom(10).hex()
    source, link, exported = ('airlift-' + t + '-' + token for t in ('src', 'link', 'saved'))
    final_source = source + '/' + PAYLOAD_PATH if payload is not None else exported
    assets = [(f'../../{source}/p0/p1/p2/link', link),
              ('../../../' + TARGET.removeprefix('/var/mobile/'), exported),
              ('../../' + final_source, link + '/iPhone')]
    journal = {'schema': 1, 'udid_hash': digest(device.udid.encode()), 'target': TARGET,
               'source': source, 'link': link, 'exported': exported,
               'complete': False, 'phase': 'created', 'payload_hash': tree_hash(payload) if payload is not None else None}
    def phase(name, **values):
        journal.update(phase=name, **values)
        save_json(run / 'journal.json', journal)
    phase('created')
    snapshot = None
    async with AfcService(device) as afc:
        for path in (source, link, exported):
            require(await exists(afc, path) is None, 'Staging path collision')
        books, books_existed = await books_snapshot(afc, run)
        mutated = False
        try:
            raw = staging_archive(payload)
            (run / 'staging.zip').write_bytes(raw)
            if payload is not None:
                write_tree_zip(run / 'desired.zip', payload)
            phase('staging', requires_recovery=True)
            mutated = True
            service = await device.start_lockdown_service('com.apple.streaming_zip_conduit')
            try:
                await service.send_plist({'MediaSubdir': source}, fmt=plistlib.FMT_BINARY)
                await service.sendall(raw)
                reply = await asyncio.wait_for(service.recv_plist(), 30)
                require(reply.get('Status') == 'DataComplete', 'Streaming ZIP was rejected')
            finally:
                await service.close()
            node = await afc.stat(source + '/p0/p1/p2/link')
            require(node['st_ifmt'] == 'S_IFLNK' and node.get('LinkTarget') == '../../../' + PARENT[1:],
                    'Staged link mismatch')
            if payload is not None:
                require(await remote_tree(afc, source + '/' + PAYLOAD_PATH) == payload, 'Staged carrier tree mismatch')
            await afc.makedirs('Books/Sync')
            metadata = plistlib.dumps({'Books': [{'Persistent ID': a, 'Item ID': str(i), 'DSID': '1'}
                                      for i, (a, _) in enumerate(assets, 1)]}, fmt=plistlib.FMT_BINARY)
            await afc.set_file_contents('Books/Sync/Books.plist', metadata)
            require(await afc.get_file_contents('Books/Sync/Books.plist') == metadata, 'Books staging mismatch')
            async def pause():
                nonlocal snapshot
                phase('export-check')
                # FileComplete is asynchronous: wait for the directory to appear.
                for _ in range(40):
                    if await exists(afc, exported):
                        break
                    await asyncio.sleep(0.1)
                node = await exists(afc, exported)
                if node is None and recovery and payload is not None:
                    phase('recovery-final-authorized')
                    return
                require(node and node['st_ifmt'] == 'S_IFDIR',
                        'iPhone не отдал текущие настройки оператора. Не повторяйте установку: '+recover_hint()+'.')
                phase('original-exported')
                snapshot = await remote_tree(afc, exported)
                write_tree_zip(run / 'original.zip', snapshot)
                phase('backup-saved', original_hash=tree_hash(snapshot))
                if expected is not None:
                    require(snapshot == expected, 'Настройки оператора на iPhone изменились во время операции. Запись отменена: '+recover_hint()+'.')
                require(await remote_tree(afc, exported) == snapshot, 'Export changed after backup')
                phase('final-authorized')
            phase('host-started')
            async with device_log(device, run / 'device.log'):
                await host_session(device.udid, assets, pause, run)
            for _ in range(30):
                if await exists(afc, final_source) is None:
                    break
                await asyncio.sleep(0.1)
            require(await exists(afc, final_source) is None, 'Final source not consumed; operation unconfirmed')
            phase('placement-observed', complete=True, requires_recovery=False)
        except BaseException as error:
            journal['operation_error'] = str(error)
            save_json(run / 'journal.json', journal)
            raise
        finally:
            if mutated:
                try:
                    await restore_books(afc, books, books_existed)
                    journal['books_restored'] = True
                except Exception as e:
                    journal['books_restored'] = False
                    journal['books_restore_error'] = str(e)
                    save_json(run / 'journal.json', journal)
                    raise
                save_json(run / 'journal.json', journal)
    # Remote originals and staging identifiers are intentionally retained for recovery.
    return snapshot

async def connect(udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    return await asyncio.wait_for(create_using_usbmux(serial=udid, autopair=False, connection_type='USB'), 15)

async def device_info(device):
    result = {k: await device.get_value(key=k) for k in
              ('ProductType', 'HardwareModel', 'ProductVersion', 'BuildVersion', 'ActivationState')}
    rows = await device.get_value(key='CarrierBundleInfoArray') or []
    result['carriers'] = [{k: r[k] for k in ('MCC', 'MNC', 'Slot', 'CFBundleIdentifier', 'CFBundleVersion') if k in r}
                          for r in rows]
    return result

def check_trigger(path, sims, target=BUNDLE):
    require(path.suffix == '.ipcc', 'Trigger must be an IPCC')
    tree = read_tree_zip(path)
    bundles = {n.split('/')[1] for n in tree if n.startswith('Payload/') and len(n.split('/')) > 1
               and n.split('/')[1].endswith('.bundle')}
    require(len(bundles) == 1, 'Trigger must contain exactly one bundle')
    name = bundles.pop()
    inner = {n.removeprefix('Payload/'): v for n, v in tree.items() if n.startswith('Payload/')}
    info, carrier = bundle_info(inner, name)
    require(name != target, 'Триггер совпадает с устанавливаемым профилем '+target+'; нужен другой IPCC')
    require(info.get('CFBundleIdentifier') != 'com.apple.Viva_kw', 'Viva is not an independent trigger')
    identifiers = carrier.get('SupportedSIMs', [])
    require(identifiers and all(isinstance(s, str) and re.fullmatch(r'\d{5,6}(?:_.*)?', s) for s in identifiers),
            'Unknown SupportedSIMs format in trigger')
    affected = set(identifiers)
    for n, (k, data) in tree.items():
        if k == 'l':
            leaf = n.split('/')[-1]
            require(re.fullmatch(r'\d{5,6}(?:_.*)?', leaf), 'Unexpected trigger symlink')
            affected.add(leaf)
    require(not any(a == s or a.startswith(s + '_') for a in affected for s in sims),
            'Trigger overlaps an installed SIM; select a different carrier')
    return {'bundle': name, 'version': info.get('CFBundleVersion'), 'sha256': digest(path.read_bytes())}

async def install_trigger(device, path, run):
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    from pymobiledevice3.services.syslog import SyslogService
    from pymobiledevice3.exceptions import ConnectionTerminatedError
    # Override upstream extraction to preserve raw bytes without creating local symlinks.
    class Installer(InstallationProxyService):
        async def _upload_ipcc(self, file_stream, afc_client, dst):
            with zipfile.ZipFile(file_stream) as z:
                for entry in z.infolist():
                    target = dst + '/' + entry.filename
                    await afc_client.makedirs(target if entry.is_dir() else target.rsplit('/', 1)[0])
                    if not entry.is_dir():
                        await afc_client.set_file_contents(target, z.read(entry))
    ready = asyncio.Event()
    status = {'ipcc_installation_completed': False, 'log_error': None, 'nr_data_verified': False}
    async def watch():
        try:
            async with SyslogService(device) as log:
                ready.set()
                size = 0
                with (run / 'commcenter.log').open('w', encoding='utf-8') as f:
                    async for row in log.watch():
                        line = row.decode(errors='replace') if isinstance(row, bytes) else row
                        if 'CommCenter' in line:
                            size += len(line)
                            require(size < 16 * 1024 * 1024, 'Log limit reached')
                            f.write(line + '\n')
                            f.flush()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            status['log_error'] = type(error).__name__ + ': ' + str(error)
            ready.set()
    watcher = asyncio.create_task(watch())
    try:
        await asyncio.wait_for(ready.wait(), 10)
        async with Installer(device) as installer:
            await asyncio.wait_for(installer.install_from_local(path), 90)
        status['ipcc_installation_completed'] = True
        save_json(run / 'installation.json', status)
        await asyncio.sleep(8)
    except BaseException as error:
        status['installation_error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher
        save_json(run / 'installation.json', status)
    return status

# AirTraffic protocol follows the MIT-licensed AirLift host sequence.
# Native Apple calls run in a disposable subprocess: a blocked DLL cannot hang recovery.
import ctypes as C
import subprocess
import uuid
from datetime import datetime

APPLE_DIRS = []
ASSET_SHA256 = '6de1ea0be81a29c145ef414f24bc21d1dcb8a4eb737b22b1f956e9a6f0c2098b'

class AppleHost:
    def __init__(self, directories=()):
        self.handles = []
        self.pool = None
        if sys.platform == 'darwin':
            self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
            self.at = C.CDLL('/System/Library/PrivateFrameworks/AirTrafficHost.framework/AirTrafficHost')
            self.objc = C.CDLL('/usr/lib/libobjc.A.dylib')
            self.objc.objc_autoreleasePoolPush.restype = C.c_void_p
            self.objc.objc_autoreleasePoolPush.argtypes = []
            self.objc.objc_autoreleasePoolPop.argtypes = [C.c_void_p]
            self.objc.objc_autoreleasePoolPop.restype = None
            self.pool = self.objc.objc_autoreleasePoolPush()
        elif sys.platform == 'win32':
            require(C.sizeof(C.c_void_p) == 8, 'Нужен 64-битный Python и 64-битные компоненты Apple.')
            paths = [Path(p).resolve() for p in directories]
            for key in ('CommonProgramW6432', 'CommonProgramFiles'):
                base = os.environ.get(key)
                if base:
                    paths += [Path(base)/'Apple'/'Mobile Device Support',
                              Path(base)/'Apple'/'Apple Application Support']
            paths = list(dict.fromkeys(p for p in paths if p.is_dir()))
            for p in paths:
                self.handles.append(os.add_dll_directory(str(p)))
            def load(name):
                candidates = [p/name for p in paths if (p/name).is_file()]
                require(candidates, 'Не найдена ' + name + '. Установите iTunes x64 с сайта Apple '
                        'или укажите папки библиотек через --apple-dir. Версия Microsoft Store может не подойти.')
                return C.CDLL(str(candidates[0]), winmode=0x1100)
            self.cf = load('CoreFoundation.dll')
            self.at = load('AirTrafficHost.dll')
        else:
            raise RuntimeError('Поддерживаются macOS и Windows.')
        P, I, U = C.c_void_p, C.c_ssize_t, C.c_size_t
        def bind(lib, name, result, args):
            f = getattr(lib, name); f.restype = result; f.argtypes = args
        for name, result, args in [
            ('CFDataCreate', P, [P,P,I]), ('CFDataGetLength', I, [P]),
            ('CFDataGetBytePtr', P, [P]), ('CFRelease', None, [P]),
            ('CFPropertyListCreateWithData', P, [P,P,U,P,P]),
            ('CFPropertyListCreateData', P, [P,P,I,U,P])]:
            bind(self.cf, name, result, args)
        for name, result, args in [
            ('ATHostConnectionCreate', P, [P]), ('ATHostConnectionRelease', None, [P]),
            ('ATHostConnectionReadMessage', P, [P]),
            ('ATHostConnectionSendHostInfo', None, [P,P]),
            ('ATHostConnectionSendSyncRequest', None, [P,P,P,P]),
            ('ATHostConnectionSendMetadataSyncFinished', None, [P,P,P]),
            ('ATHostConnectionSendAssetCompleted', None, [P,P,P,P]),
            ('ATCFMessageGetName', P, [P]), ('ATCFMessageGetParam', P, [P,P])]:
            bind(self.at, name, result, args)

    def encode(self, value):
        raw = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
        buf = C.create_string_buffer(raw)
        data = self.cf.CFDataCreate(None, buf, len(raw))
        require(data, 'CFDataCreate failed')
        try:
            result = self.cf.CFPropertyListCreateWithData(None, data, 0, None, None)
            require(result, 'CFPropertyListCreateWithData failed')
            return result
        finally:
            self.cf.CFRelease(data)

    def decode(self, value):
        require(value, 'Пустое сообщение Apple')
        data = self.cf.CFPropertyListCreateData(None, value, 200, 0, None)
        require(data, 'CFPropertyListCreateData failed')
        try:
            size = self.cf.CFDataGetLength(data)
            require(0 <= size <= MAX_BYTES, 'Слишком большое сообщение Apple')
            return plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data), size))
        finally:
            self.cf.CFRelease(data)

    def call(self, name, connection, *values):
        refs = []
        try:
            for v in values: refs.append(self.encode(v))
            return getattr(self.at, name)(connection, *refs)
        finally:
            for ref in refs: self.cf.CFRelease(ref)

    def close(self):
        if self.pool:
            self.objc.objc_autoreleasePoolPop(self.pool); self.pool = None


def framed(value):
    print('CARRIER_SWAP_JSON:' + json.dumps(value), flush=True)


def native_host(udid, assets, directories):
    host = AppleHost(directories)
    connection = None
    try:
        sample = {'test': ['Book', 1, False]}
        ref = host.encode(sample)
        try: require(host.decode(ref) == sample, 'Ошибка обмена с CoreFoundation')
        finally: host.cf.CFRelease(ref)
        if udid is None:
            framed({'ok': True, 'deviceConnections': 0}); return
        ref = host.encode(udid)
        try: connection = host.at.ATHostConnectionCreate(ref)
        finally: host.cf.CFRelease(ref)
        require(connection, 'Не удалось открыть AirTraffic. Закройте синхронизацию iTunes/Finder.')
        def until(wanted, limit):
            for _ in range(limit):
                msg = host.at.ATHostConnectionReadMessage(connection)
                if not msg: continue
                try:
                    name = host.decode(host.at.ATCFMessageGetName(msg))
                    try: body = json.dumps(host.decode(msg), ensure_ascii=False, default=str)[:4000]
                    except Exception as e: body = 'не прочитано: ' + str(e)
                    framed({'event': 'message', 'name': name, 'body': body})
                    if name == wanted:
                        if name != 'AssetManifest': return True
                        key = host.encode('AssetManifest')
                        try: return host.decode(host.at.ATCFMessageGetParam(msg, key))
                        finally: host.cf.CFRelease(key)
                    require(name not in ('SyncFailed','SyncFinished'), 'Синхронизация закончилась преждевременно')
                finally: host.cf.CFRelease(msg)
            raise RuntimeError('Не получено сообщение ' + wanted)
        until('SyncAllowed', 8)
        info = {'Type':'iTunes', 'Version':'13.7.0.161', 'SyncHostName':'CarrierSIM',
                'LibraryID':str(uuid.uuid4()), 'SyncedDataclasses':['Book'],
                'SyncedAssetTypes':['Book'], 'Wakeable':False}
        if sys.platform == 'darwin':
            import platform
            info['MacOSVersion'] = platform.mac_ver()[0]
        host.call('ATHostConnectionSendHostInfo', connection, info)
        time.sleep(.2)
        host.call('ATHostConnectionSendSyncRequest', connection, ['Book'], {}, info)
        until('ReadyForSync', 12)
        host.call('ATHostConnectionSendMetadataSyncFinished', connection, {'Book':1}, {})
        manifest = until('AssetManifest', 20)
        require(isinstance(manifest,dict), 'Неверный манифест AirTraffic')
        books = [r for r in manifest.get('Book',[]) if isinstance(r,dict)]
        found = {r.get('AssetID') for r in books if r.get('IsDownload')}
        missing = [a for a,_ in assets if a not in found]
        if missing:
            # Keep what the phone actually answered: host.jsonl in the run folder.
            framed({'event':'manifest','dataclasses':sorted(map(str,manifest)),'expected':[a for a,_ in assets],
                    'book':[{k:str(v) for k,v in r.items()} for r in books[:50]]})
            raise RuntimeError(f'AirTraffic не подтвердил нужные объекты: iPhone вернул {len(books)} '
                               f'объект(ов) Book, не хватает {len(missing)} из {len(assets)}')
        for i,(identifier,destination) in enumerate(assets):
            if i == 2:
                framed({'event':'before-final-asset'})
                require(sys.stdin.readline().strip() == 'CONTINUE', 'Резервная копия не подтверждена')
            host.call('ATHostConnectionSendAssetCompleted', connection, identifier, 'Book', destination)
            if i+1 < len(assets): time.sleep(.9)
        time.sleep(2)
        framed({'ok':True})
    finally:
        if connection: host.at.ATHostConnectionRelease(connection)
        host.close()


def host_command():
    return [sys.executable, str(Path(__file__).resolve()), '--_host']


async def host_session(udid, assets, callback, run):
    config = run/'host-input.json'
    save_json(config, {'udid':udid, 'assets':assets, 'directories':APPLE_DIRS})
    proc = await asyncio.create_subprocess_exec(*host_command(), str(config),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    async def stderr():
        with (run/'host.stderr').open('wb') as f:
            while data := await proc.stderr.read(4096): f.write(data)
    task = asyncio.create_task(stderr())
    paused = False; result = None
    try:
        with (run/'host.jsonl').open('wb') as log:
            async with asyncio.timeout(170):
                while line := await proc.stdout.readline():
                    log.write(line); log.flush()
                    if not line.startswith(b'CARRIER_SWAP_JSON:'): continue
                    row = json.loads(line[len(b'CARRIER_SWAP_JSON:'):])
                    if row.get('event') == 'before-final-asset':
                        require(not paused, 'Повторная пауза AirTraffic')
                        await callback(); paused = True
                        proc.stdin.write(b'CONTINUE\n'); await proc.stdin.drain()
                    elif 'ok' in row: result = row
                code = await proc.wait()
        detail = (result or {}).get('error') or ('код ' + str(code))
        require(code == 0 and paused and result and result.get('ok'), 'Сбой AirTraffic: ' + str(detail))
    finally:
        if proc.returncode is None:
            proc.kill(); await proc.wait()
        await task
        config.unlink(missing_ok=True)

TARGET_BUNDLES = ('Vodafone_hu.bundle',)
SYSTEM_PREFIX = '../../../../../../System/Library/Carrier Bundles/iPhone/'
MODELS = {'iPhone14,7': {'name': 'iPhone 14', 'boards': ['D27AP']}, 'iPhone14,8': {'name': 'iPhone 14 Plus', 'boards': ['D28AP']}, 'iPhone15,2': {'name': 'iPhone 14 Pro', 'boards': ['D73AP']}, 'iPhone15,3': {'name': 'iPhone 14 Pro Max', 'boards': ['D74AP']}, 'iPhone15,4': {'name': 'iPhone 15', 'boards': ['D37AP']}, 'iPhone15,5': {'name': 'iPhone 15 Plus', 'boards': ['D38AP']}, 'iPhone16,1': {'name': 'iPhone 15 Pro', 'boards': ['D83AP']}, 'iPhone16,2': {'name': 'iPhone 15 Pro Max', 'boards': ['D84AP']}, 'iPhone17,4': {'name': 'iPhone 16 Plus', 'boards': ['D48AP']}, 'iPhone17,2': {'name': 'iPhone 16 Pro Max', 'boards': ['D94AP']}, 'iPhone17,3': {'name': 'iPhone 16', 'boards': ['D47AP']}, 'iPhone17,1': {'name': 'iPhone 16 Pro', 'boards': ['D93AP']}, 'iPhone17,5': {'name': 'iPhone 16e', 'boards': ['V59AP']}, 'iPhone18,1': {'name': 'iPhone 17 Pro', 'boards': ['V53AP']}, 'iPhone18,2': {'name': 'iPhone 17 Pro Max', 'boards': ['V54AP']}, 'iPhone18,4': {'name': 'iPhone Air', 'boards': ['D23AP']}, 'iPhone18,3': {'name': 'iPhone 17', 'boards': ['V57AP']}, 'iPhone18,5': {'name': 'iPhone 17e', 'boards': ['V159AP']}, 'iPhone19,7': {'name': 'iPhone 18 Pro Max', 'boards': ['V64SAP']}, 'iPhone19,3': {'name': 'iPhone 18 Pro Max (U.S.)', 'boards': ['V64AP']}, 'iPhone19,2': {'name': 'iPhone 18 Pro', 'boards': ['V63AP']}}


def load_assets():
    path = ROOT/'assets.zip'
    require(digest(path.read_bytes()) == ASSET_SHA256, 'Архив assets.zip повреждён или заменён.')
    tree = read_tree_zip(path)
    return tree


def bundle_link(name):
    require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle', name), 'Неверное имя пакета: '+name)
    return ('l', (SYSTEM_PREFIX+name).encode())


SLOT_NAMES = {'kOne': 'SIM 1', 'kTwo': 'SIM 2'}
SLOT_CHOICES = {'1': ('kOne',), '2': ('kTwo',), 'all': ('kOne', 'kTwo')}


def select_sims(rows, bundle=BUNDLE, slots=SLOT_CHOICES['all']):
    selected = []; seen_slots = set(); seen_imsi = set()
    for row in rows:
        mcc, mnc = str(row.get('MCC','')), str(row.get('MNC',''))
        slot, imsi = row.get('Slot'), row.get('InternationalMobileSubscriberIdentity')
        require(slot in ('kOne','kTwo') and slot not in seen_slots, 'Неоднозначные слоты SIM; запись отменена.')
        seen_slots.add(slot)
        if slot not in slots: continue
        require(re.fullmatch(r'\d{3}',mcc) and re.fullmatch(r'\d{2,3}',mnc) and isinstance(imsi,str) and
                re.fullmatch(r'\d{15}',imsi) and imsi.startswith(mcc+mnc),
                'iPhone не сообщил полный IMSI для SIM '+mcc+mnc+'. Включите линию и разблокируйте телефон.')
        require(imsi not in seen_imsi, 'Один IMSI указан в двух слотах; запись отменена.')
        seen_imsi.add(imsi)
        selected.append({'slot':slot,'plmn':mcc+mnc,'imsi':imsi,'bundle':bundle})
    missing = [SLOT_NAMES[s] for s in slots if s not in seen_slots]
    require(len(slots) > 1 or not missing, missing and missing[0]+' не найдена в iPhone. Выберите другую SIM.')
    require(selected, 'Телефон не сообщил ни одной SIM с доступным IMSI.')
    return selected


def make_plan(original, sims):
    desired = dict(original)
    # Signed system bundles match the phone's own firmware; only exact IMSI aliases change.
    for sim in sims:
        n = sim['imsi']
        require(n not in original or original[n][0]=='l', 'Вместо ссылки IMSI обнаружен файл или каталог.')
        desired[n] = bundle_link(sim['bundle'])
    validate_tree(desired)
    return desired


def remove_imsi_links(original):
    # This installer creates root-level, 15-digit IMSI aliases, never directories.
    result = {n:v for n,v in original.items()
              if not (v[0]=='l' and re.fullmatch(r'\d{15}',n))}
    validate_tree(result)
    return result


def check_phone(info):
    model = MODELS.get(info['ProductType'])
    if (not model or str(info['HardwareModel']).upper() not in model['boards']
            or info['ProductVersion'] != '27.0'
            or info['BuildVersion'] not in ('24A435', '24A437')):
        print('Предупреждение: модель, плата или версия iOS не проверена. '
              'Скрипт МОЖЕТ не работать. Продолжаю без ограничения совместимости.', flush=True)
    require(info['ActivationState']=='Activated','iPhone не активирован.')


async def choose_device(udid, wait_seconds=180):
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, NoDeviceConnectedError
    deadline=time.monotonic()+wait_seconds
    announced=False
    while True:
        try:
            devices=[d.serial for d in await list_devices() if d.connection_type=='USB']
        except (OSError, ConnectionError, ConnectionFailedToUsbmuxdError, NoDeviceConnectedError):devices=[]
        if udid and udid in devices:return udid
        if not udid and len(devices)==1:return devices[0]
        require(udid or len(devices)<2,'Подключено несколько iPhone. Укажите --udid.')
        if not announced:
            print('Ожидаю подключения iPhone по USB. Подключите и разблокируйте телефон…',flush=True)
            announced=True
        require(time.monotonic()<deadline,'Время ожидания подключения истекло. Проверьте кабель и повторите.')
        await asyncio.sleep(min(2,max(0,deadline-time.monotonic())))


async def ready_device(udid, wait_seconds):
    from pymobiledevice3 import exceptions as errors
    deadline=time.monotonic()+wait_seconds
    last=None;asked=False
    while True:
        await choose_device(udid,max(0,deadline-time.monotonic()))
        try:
            device=await connect(udid)
            if not device.paired:
                # No pair record on this computer: without pairing lockdown answers GetProhibited.
                # pymobiledevice3 saves the new record to usbmuxd too, so Apple's AirTrafficHost can use it.
                try:
                    if not asked:
                        print('На iPhone появится запрос «Доверять этому компьютеру?». '
                              'Нажмите «Доверять» и введите код-пароль.',flush=True)
                        asked=True
                    await device.pair(timeout=max(1,deadline-time.monotonic()))
                    require(await device.validate_pairing(),'Не удалось установить доверие с iPhone. Отключите кабель и повторите.')
                except errors.UserDeniedPairingError:
                    await device.close()
                    raise RuntimeError('На iPhone выбрано «Не доверять». Отключите и снова подключите кабель, '
                                       'затем нажмите «Доверять».') from None
                except BaseException:
                    await device.close();raise
            return device
        except (OSError, errors.ConnectionTerminatedError, errors.PasswordRequiredError,
                errors.NotPairedError, errors.PairingDialogResponsePendingError,
                errors.ConnectionFailedError, errors.InvalidConnectionError) as error:
            if last is None:print('Ожидаю разблокировки, доверия и готовности USB-соединения…',flush=True)
            last=error
            if time.monotonic()>=deadline:raise RuntimeError('iPhone не готов: разблокируйте и подтвердите доверие.') from error
            await asyncio.sleep(2)


def transient_error(error):
    from pymobiledevice3 import exceptions as errors
    if isinstance(error,(ConnectionError,TimeoutError,errors.ConnectionTerminatedError,
                         errors.ConnectionFailedError,errors.InvalidConnectionError)):
        return True
    if isinstance(error,OSError) and error.errno in (32,54,60,104,110):return True
    # The phone answering without our assets is deterministic: retrying only repeats it.
    return isinstance(error,RuntimeError) and any(t in str(error) for t in
        ('Сбой AirTraffic','Final source not consumed')) and 'не подтвердил нужные объекты' not in str(error)


async def execute_with_retry(args,assets):
    # Once selected, reconnect only to this exact phone, even if a different phone appears.
    args.udid=await choose_device(args.udid,args.wait_seconds)
    for attempt in range(1,args.attempts+1):
        print(f'Попытка {attempt} из {args.attempts}',flush=True)
        try:return await execute(args,assets)
        except Exception as error:
            # Roll back after any failure; retry only when a new attempt can change the outcome.
            failed=pending(args.runs,args.udid)
            if failed:
                print('Сбой во время записи. Сначала возвращаю iPhone в исходное состояние…',flush=True)
                device=await ready_device(args.udid,args.wait_seconds)
                recovery=args.runs/(datetime.now().strftime('%Y%m%d-%H%M%S-')+'auto-recovery-'+uuid.uuid4().hex[:6])
                recovery.mkdir(mode=0o700)
                try:
                    await recover_all(device,failed,recovery)
                    print('iPhone возвращён в исходное состояние.',flush=True)
                except BaseException:
                    print('Автовосстановление не завершено. Журнал:',recovery,flush=True)
                    print('Не удаляйте папку runs и '+recover_hint()+'.',flush=True)
                    raise
                finally:await device.close()
            if attempt==args.attempts or not transient_error(error):raise
            print('Повторяю попытку…',flush=True)
            await asyncio.sleep(2)


def report_log(path, sims):
    results = {s['slot']:{'slot':s['slot'],'plmn':s['plmn'],'expected':s['bundle'],
                         'selected':None,'verified':False} for s in sims}
    if path.exists():
        for block in path.read_text(encoding='utf-8',errors='replace').split('----------Bundle File----------'):
            resolved = re.findall(r'Resolved path\s*:\s*([^\r\n]+)',block)
            linked = re.findall(r'Linking Path\s*:\s*([^\r\n]+)',block)
            verified = re.findall(r'Verification Result\s*:\s*([^\r\n]+)',block)
            if len(resolved)!=1 or len(linked)!=1: continue
            for slot,index in (('kOne',1),('kTwo',2)):
                if slot in results and linked[0].strip().endswith(f'/Carrier{index}Bundle.bundle'):
                    results[slot].update(selected=resolved[0].strip().rsplit('/',1)[-1],
                                         verified=verified==['Success'])
    return list(results.values())


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def pending(runs, udid):
    # Oldest first: run folders start with a timestamp; stages inside one run by journal age.
    journals = sorted(runs.glob('*/*/journal.json'), key=lambda p: (p.parent.parent.name, p.stat().st_mtime))
    return [p.parent for p in journals
            if (j:=read_json(p)).get('udid_hash')==digest(udid.encode())
            and (j.get('requires_recovery') or j.get('books_restored') is False) and not j.get('recovered_by')]


@contextlib.contextmanager
def operation_lock(runs):
    runs.mkdir(parents=True,exist_ok=True)
    with (runs/'.lock').open('a+b') as f:
        f.seek(0); f.write(b'0'); f.flush(); f.seek(0)
        if sys.platform=='win32':
            import msvcrt
            msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
        else:
            import fcntl
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try: yield
        finally:
            if sys.platform=='win32':
                f.seek(0); msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)


def bound(record,device):
    require(record.get('target')==TARGET and record.get('udid_hash')==digest(device.udid.encode()),
            'Копия относится к другому телефону или каталогу.')


async def recover_stage(device, failed, run, tag=''):
    from pymobiledevice3.services.afc import AfcService
    record = read_json(failed/'journal.json'); bound(record,device)
    remote = record.get('exported','')
    require(re.fullmatch(r'airlift-saved-[a-f0-9]{20}',remote),'Неверный путь восстановления.')
    books = read_tree_zip(failed/'books.zip'); state=read_json(failed/'books.json')
    require(tree_hash(books)==state['hash'],'Копия Books повреждена.')
    desired = None
    async with AfcService(device) as afc:
        if record.get('complete'):
            # The carrier stage finished; only the Books cleanup failed. Never roll back the catalog.
            await restore_books(afc,books,state['existed'])
            record['recovered_by']=str(run);record['books_restored']=True
            save_json(failed/'journal.json',record)
            return
        if await exists(afc,remote):
            desired = await remote_tree(afc,remote)
            if record.get('original_hash'):
                require(tree_hash(desired)==record['original_hash'],'Удалённая копия изменилась.')
        elif (failed/'original.zip').exists():
            desired = read_tree_zip(failed/'original.zip')
            require(tree_hash(desired)==record.get('original_hash'),'Локальная копия повреждена.')
        else:
            # No exported copy on the phone and none saved locally: the catalog was never moved
            # out, and the final asset is only sent after the backup is saved. Only the staging
            # files in /var/mobile/Media changed, so undo those without another AirTraffic session.
            require(record.get('phase') in ('created','staging','host-started','export-check'),
                    'Нет проверенной копии. Сохраните runs; восстановление остановлено.')
        await restore_books(afc,books,state['existed'])
    if desired is not None:
        write_tree_zip(run/f'recovery-original{tag}.zip',desired)
        await transfer(device,run/f'recover{tag}',payload=desired,recovery=True)
        observed=await transfer(device,run/f'readback{tag}')
        require(observed==desired,'Восстановленный каталог не совпадает с копией.')
    record['recovered_by']=str(run);record['requires_recovery']=False;record['books_restored']=True
    save_json(failed/'journal.json',record)


async def recover_all(device, stages, run):
    # Undo newest first: a failed recovery attempt is itself a stage on top of the one it repaired.
    for i,failed in enumerate(reversed(stages),1):
        print('Восстанавливаю этап:',failed,flush=True)
        await recover_stage(device,failed,run,f'-{i}' if len(stages)>1 else '')


def check_trigger_hardware(path, hardware):
    tree = read_tree_zip(path)
    board = hardware.upper().removesuffix('AP')
    for name,(kind,data) in tree.items():
        leaf = name.rsplit('/',1)[-1]
        if kind!='f' or '/signatures/' in name or not leaf.startswith('overrides_') or not leaf.endswith('.plist'):
            continue
        boards = leaf.removeprefix('overrides_').removesuffix('.plist').upper().split('_')
        if board in boards:
            signature = name.rsplit('/',1)[0]+'/signatures/'+leaf
            if signature in tree:
                return True
            break
    print('Предупреждение: в IPCC нет настроек с подписью для платы '+hardware+
          '. Пересканирование МОЖЕТ не работать; продолжаю.', flush=True)
    return False



async def execute(args,assets):
    udid=args.udid
    device=await ready_device(udid,args.wait_seconds)
    run=None
    try:
        info=await device_info(device); DIAG['info']=info; check_phone(info)
        rows=await device.get_value(key='CarrierBundleInfoArray') or []
        slots=SLOT_CHOICES[args.sims]
        sims=select_sims(rows,args.bundle,slots) if not (args.restore or args.restore_backup or args.recover) else []
        if args.restore:
            sims=[{'slot':r['Slot'],'plmn':str(r.get('MCC',''))+str(r.get('MNC','')),'bundle':None}
                  for r in rows if r.get('Slot') in ('kOne','kTwo')]
        print(f"\n  {MODELS.get(info['ProductType'], {}).get('name', info['ProductType'])} · iOS {info['ProductVersion']} ({info['BuildVersion']})",flush=True)
        for s in sims:
            label = {'kOne':'SIM 1', 'kTwo':'SIM 2'}[s['slot']]
            target='штатный профиль' if args.restore else args.bundle.removesuffix('.bundle')+' (по IMSI)'
            print(f"  {label}  ·  {s['plmn']}  →  {target}",flush=True)
        print(flush=True)
        if args.status: return
        if args.trigger:
            check_trigger(args.trigger,{str(r.get('MCC',''))+str(r.get('MNC','')) for r in rows},args.bundle)
            check_trigger_hardware(args.trigger,info['HardwareModel'])
        unresolved=pending(args.runs,udid)
        if args.recover == Path('AUTO'):
            if not unresolved:
                print('Незавершённых операций для этого iPhone нет, восстанавливать нечего.');return 0
            args.recover=unresolved
        require(not unresolved or args.recover,
                'Прошлая операция на этом iPhone не завершилась. Сначала '+recover_hint()+
                ', затем повторите действие. Этап: '+str(unresolved[0] if unresolved else ''))
        run=args.runs/(datetime.now().strftime('%Y%m%d-%H%M%S-')+uuid.uuid4().hex[:6])
        run.mkdir(mode=0o700); DIAG['run']=run
        print('Копии и журнал:',run,flush=True)
        print('Идёт установка или восстановление, ожидайте… Не отключайте iPhone.',flush=True)
        save_json(run/'device.json',{**info,'udid_hash':digest(udid.encode())})
        trigger=None
        plmns={str(r.get('MCC',''))+str(r.get('MNC','')) for r in rows}
        for name in (() if args.trigger else ('AVEA_tr.ipcc','Swisscom_ch.ipcc','O2_Germany.ipcc')):
            candidate=run/name;candidate.write_bytes(assets['triggers/'+name][1])
            try:
                check_trigger(candidate,plmns,args.bundle)
                check_trigger_hardware(candidate,info['HardwareModel'])
                trigger=candidate;break
            except RuntimeError:candidate.unlink()
        if args.trigger:
            trigger=run/'custom-trigger.ipcc';trigger.write_bytes(args.trigger.read_bytes())
            check_trigger(trigger,plmns,args.bundle);check_trigger_hardware(trigger,info['HardwareModel'])
        require(trigger is not None,'Не найден независимый триггер для этих SIM.')
        DIAG['trigger']=trigger.name
        if args.recover:
            if isinstance(args.recover,list):await recover_all(device,args.recover,run)
            else:await recover_stage(device,args.recover.resolve(),run)
        elif args.restore:
            print('[1/4] Подготавливаю пересканирование…',flush=True)
            init=run/'initialize';init.mkdir();await install_trigger(device,trigger,init)
            print('[2/4] Сохраняю текущие настройки…',flush=True)
            original=await transfer(device,run/'snapshot')
            desired=remove_imsi_links(original)
            removed=len(original)-len(desired)
            save_json(run/'plan.json',{'action':'remove-imsi','removed':removed,'before':tree_hash(original),'after':tree_hash(desired)})
            print(f'[3/4] Удаляю ссылки по IMSI: {removed}. Проверяю результат…',flush=True)
            await transfer(device,run/'restore',payload=desired,expected=original)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        elif args.restore_backup:
            failed=args.restore_backup.resolve()/'snapshot'
            record=read_json(failed/'journal.json');bound(record,device)
            desired=read_tree_zip(failed/'original.zip')
            require(tree_hash(desired)==record.get('original_hash'),'Копия повреждена.')
            await transfer(device,run/'restore',payload=desired,recovery=True)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        else:
            # A non-overlapping trigger also creates the user catalog on a clean phone.
            init=run/'initialize';init.mkdir()
            print('[1/4] Подготавливаю пересканирование…',flush=True)
            await install_trigger(device,trigger,init)
            print('[2/4] Сохраняю исходные настройки…',flush=True)
            original=await transfer(device,run/'snapshot')
            require(original is not None,'Не удалось сохранить исходный каталог.')
            current=select_sims(await device.get_value(key='CarrierBundleInfoArray') or [],args.bundle,slots)
            require(current==sims,'SIM изменились во время операции; запись отменена.')
            desired=make_plan(original,sims)
            save_json(run/'plan.json',{'slots':[{k:v for k,v in s.items() if k!='imsi'} for s in sims],
                                      'before':tree_hash(original),'after':tree_hash(desired)})
            print('[3/4] Записываю ссылки по IMSI и проверяю результат…',flush=True)
            await transfer(device,run/'apply',payload=desired,expected=original)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        print('[4/4] Ожидаю применения профиля и проверки подписей…',flush=True)
        rescan=run/'rescan';rescan.mkdir()
        installation=await install_trigger(device,trigger,rescan)
        result=report_log(rescan/'commcenter.log',sims)
        save_json(run/'result.json',{'catalog_verified':True,'installation':installation,'slots':result})
        unconfirmed=False
        for s in result:
            ok=s['verified'] and (args.restore or (s['selected'] or '').lower()==s['expected'].lower());unconfirmed |= not ok
            print(f"{SLOT_NAMES[s['slot']]} ({s['plmn']}): "+(s['selected']+' — подпись принята' if ok else
                  'выбор нужного пакета не подтверждён; см. журнал'),flush=True)
        if args.restore:print('Все ссылки по IMSI удалены. Обычные ссылки операторов сохранены.',flush=True)
        installing=not (args.restore or args.restore_backup or args.recover)
        if installing and args.bundle!=BUNDLE and not any(
                (s['selected'] or '').lower()==s['expected'].lower() for s in result):
            # AFC cannot read /System, so a missing bundle only shows up in the rescan log.
            # Never leave links to it: put back the catalog saved before this write.
            print('iOS не выбрала '+args.bundle+' ни для одной SIM: такого пакета, видимо, нет в этой '
                  'версии iOS или имя введено с ошибкой. Возвращаю прежние настройки…',flush=True)
            await transfer(device,run/'rollback',payload=original,expected=desired)
            require(await transfer(device,run/'rollback-readback')==original,
                    'Прежние настройки не вернулись: '+recover_hint()+'.')
            rescan=run/'rescan-rollback';rescan.mkdir()
            await install_trigger(device,trigger,rescan)
            save_json(run/'result.json',{'catalog_verified':True,'installation':installation,'slots':result,
                                         'rolled_back':True})
            print('Прежние настройки возвращены. Проверьте имя пакета и повторите.',flush=True)
            return 2
        if unconfirmed:return 2
        print('Готово. Включите авиарежим на 15 секунд и проверьте связь. Работа 5G не проверялась.')
        return 0
    except BaseException as error:
        if run:
            save_json(run/'error.json',{'error':type(error).__name__+': '+str(error)})
            # execute_with_retry rolls back any unfinished stage and reports the outcome.
            print('Операция остановлена. Журнал:',run,file=sys.stderr)
        raise
    finally:await device.close()

# ---- Diagnostics printed on failure: enough to debug without sending the runs folder.
# Never includes IMSI, UDID or serial numbers.
DIAG = {}


def win_file_version(path):
    try:
        v = C.windll.version
        size = v.GetFileVersionInfoSizeW(str(path), None)
        if not size: return None
        buf = C.create_string_buffer(size)
        if not v.GetFileVersionInfoW(str(path), 0, size, buf): return None
        ptr, length = C.c_void_p(), C.c_uint()
        if not v.VerQueryValueW(buf, '\\', C.byref(ptr), C.byref(length)): return None
        info = C.cast(ptr, C.POINTER(C.c_uint32 * 13)).contents
        ms, ls = info[2], info[3]
        return f'{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}'
    except Exception:
        return None


def sysctl(name):
    try:
        return subprocess.run(['/usr/sbin/sysctl', '-n', name], capture_output=True, text=True, timeout=5).stdout.strip() or None
    except Exception:
        return None


def environment_info():
    import platform
    from importlib.metadata import version, metadata, PackageNotFoundError
    rows = [('Сборка скрипта', digest((ROOT/'carrier.py').read_bytes())[:12]),
            ('Python', f"{sys.version.split()[0]} {platform.machine()} {'64' if sys.maxsize > 2**32 else '32'}-bit")]
    libs = []
    for name in ('pymobiledevice3', 'cryptography', 'pyimg4', 'pylzss', 'lzfse'):
        try:
            placeholder = 'placeholder' in (metadata(name).get('Summary') or '')
            libs.append(f"{name} {version(name)}{' (заглушка)' if placeholder else ''}")
        except PackageNotFoundError:
            libs.append(f'{name} нет')
    rows.append(('Библиотеки', ', '.join(libs)))
    if sys.platform == 'darwin':
        cpu = 'Apple Silicon' if sysctl('hw.optional.arm64') == '1' else 'Intel'
        if sysctl('sysctl.proc_translated') == '1': cpu += ', Python под Rosetta'
        rows.append(('macOS', f"{platform.mac_ver()[0]} · {sysctl('hw.model') or '?'} · {cpu} · {sysctl('machdep.cpu.brand_string') or ''}".rstrip(' ·')))
        try:
            at = plistlib.loads(Path('/System/Library/PrivateFrameworks/AirTrafficHost.framework/Resources/Info.plist').read_bytes())
            rows.append(('AirTrafficHost', f"{at.get('CFBundleShortVersionString')} ({at.get('CFBundleVersion')})"))
        except Exception:
            rows.append(('AirTrafficHost', 'версия не прочитана'))
    elif sys.platform == 'win32':
        w = sys.getwindowsversion()
        rows.append(('Windows', f"{platform.release()} {platform.version()} (build {w.build}) · {platform.machine()}"))
        dirs = [Path(d) for d in APPLE_DIRS]
        for key in ('CommonProgramW6432', 'CommonProgramFiles'):
            if os.environ.get(key):
                dirs += [Path(os.environ[key])/'Apple'/'Mobile Device Support', Path(os.environ[key])/'Apple'/'Apple Application Support']
        found = {}
        for d in dict.fromkeys(dirs):
            for name in ('AirTrafficHost.dll', 'MobileDevice.dll', 'CoreFoundation.dll'):
                if name not in found and (d/name).is_file():
                    found[name] = f'{win_file_version(d/name) or "?"} ({d})'
        for name in ('AirTrafficHost.dll', 'MobileDevice.dll', 'CoreFoundation.dll'):
            rows.append((name, found.get(name, 'не найдена')))
        itunes = [Path(os.environ[k])/'iTunes'/'iTunes.exe' for k in ('ProgramW6432', 'ProgramFiles') if os.environ.get(k)]
        itunes = next((x for x in itunes if x.is_file()), None)
        rows.append(('iTunes', win_file_version(itunes) if itunes else 'iTunes.exe не найден (возможно, версия из Microsoft Store)'))
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service') as k:
                rows.append(('Apple Mobile Device Service', 'установлена'))
        except Exception:
            rows.append(('Apple Mobile Device Service', 'не найдена'))
    else:
        rows.append(('ОС', platform.platform()))
    return rows


def run_details(run):
    rows = []
    for journal in sorted(run.glob('*/journal.json'), key=lambda p: p.stat().st_mtime):
        stage = journal.parent
        try: j = read_json(journal)
        except Exception: continue
        line = f"фаза {j.get('phase')}, завершён {bool(j.get('complete'))}, Books восстановлен {j.get('books_restored')}"
        if j.get('operation_error'): line += f", ошибка: {j['operation_error']}"
        rows.append((f'Этап {stage.name}', line))
        try:
            b = read_json(stage/'books.json'); tree = read_tree_zip(stage/'books.zip')
            known = [n for n in (x.removeprefix('Books/') for x in BOOK_FILES + BOOK_DIRS[1:]) if n in tree]
            rows.append(('  Books до операции', f"{'был' if b.get('existed') else 'не было'}, объектов {len(tree)}, служебные: {', '.join(known) or 'нет'}"))
        except Exception:
            pass
        host = stage/'host.jsonl'
        if host.exists():
            for raw in host.read_text(encoding='utf-8', errors='replace').splitlines():
                if not raw.startswith('CARRIER_SWAP_JSON:'): continue
                try: row = json.loads(raw.split(':', 1)[1])
                except ValueError: continue
                if row.get('event') == 'manifest':
                    book = row.get('book', [])
                    expected = set(row.get('expected', []))
                    rows.append(('  Ответ AirTraffic', f"типы {row.get('dataclasses')}, объектов Book {len(book)}, "
                                 f"IsDownload {sum(1 for x in book if x.get('IsDownload') in ('True', '1'))}, "
                                 f"наших {sum(1 for x in book if x.get('AssetID') in expected)} из {len(expected)}"))
                    for x in book[:5]:
                        rows.append(('    Book', ', '.join(f'{k}={v[:60]}' for k, v in x.items())))
                elif row.get('ok') is False:
                    rows.append(('  Ошибка AirTraffic', str(row.get('error'))))
        if host.exists():
            names = []
            for raw in host.read_text(encoding='utf-8', errors='replace').splitlines():
                if raw.startswith('CARRIER_SWAP_JSON:'):
                    with contextlib.suppress(ValueError):
                        row = json.loads(raw.split(':', 1)[1])
                        if row.get('event') == 'message': names.append(row.get('name'))
            if names: rows.append(('  Сообщения AirTraffic', ' → '.join(map(str, names))))
        dlog = stage/'device.log'
        if dlog.exists():
            lines = dlog.read_text(encoding='utf-8', errors='replace').splitlines()
            key = [l for l in lines if any(k in l.lower() for k in
                   ('deny', 'error', 'fail', 'airlift', 'carrier bundles', 'not found', 'no such', 'reject', 'skip', 'invalid'))]
            rows.append(('  Журнал iPhone', f'{len(lines)} строк, важных {len(key)}'))
            for l in key[-25:]:
                rows.append(('    iPhone', re.sub(r'^\w{3} +\d+ [\d:]+ \S+ ', '', l.strip())[:300]))
        err = stage/'host.stderr'
        if err.exists():
            tail = [l.strip()[:200] for l in err.read_text(encoding='utf-8', errors='replace').splitlines() if l.strip()][-5:]
            for l in tail: rows.append(('  host.stderr', l))
    for name in ('initialize', 'rescan'):
        f = run/name/'installation.json'
        if f.exists():
            try:
                j = read_json(f)
                rows.append((f'Триггер ({name})', f"установлен {j.get('ipcc_installation_completed')}"
                             + (f", ошибка: {j['installation_error']}" if j.get('installation_error') else '')
                             + (f", журнал: {j['log_error']}" if j.get('log_error') else '')))
            except Exception:
                pass
    return rows


def print_diagnostics(error):
    rows = []
    try: rows += environment_info()
    except Exception as e: rows.append(('Окружение', f'не собрано: {e}'))
    info = DIAG.get('info')
    if info:
        rows.append(('iPhone', f"{MODELS.get(info['ProductType'], {}).get('name', '?')} · {info['ProductType']} · "
                     f"{info['HardwareModel']} · iOS {info['ProductVersion']} ({info['BuildVersion']}) · {info['ActivationState']}"))
        for c in info.get('carriers', []):
            rows.append(('  SIM', f"{c.get('Slot')} {c.get('MCC','')}{c.get('MNC','')} {c.get('CFBundleIdentifier','')} {c.get('CFBundleVersion','')}"))
    args = DIAG.get('args')
    if args is not None:
        rows.append(('Действие', ' '.join(a for a in sys.argv[1:]) or 'установка'))
        rows.append(('Профиль', f"{getattr(args, 'bundle', BUNDLE)}, SIM: {getattr(args, 'sims', 'all')}"))
    if DIAG.get('trigger'): rows.append(('Триггер', DIAG['trigger']))
    run = DIAG.get('run')
    if run:
        rows.append(('Папка операции', str(run)))
        try: rows += run_details(run)
        except Exception as e: rows.append(('Журналы', f'не прочитаны: {e}'))
    rows.append(('Ошибка', f'{type(error).__name__}: {error}'))
    print('\n===== Данные для отладки: скопируйте этот блок автору =====', file=sys.stderr)
    for k, v in rows: print(f'{k}: {v}', file=sys.stderr)
    print('===== конец блока =====\n', file=sys.stderr, flush=True)



def main():
    if len(sys.argv)>1 and sys.argv[1]=='--_host':
        try:
            value=json.loads(sys.stdin.readline()) if sys.argv[2]=='check' else read_json(Path(sys.argv[2]))
            native_host(value.get('udid'),value.get('assets',[]),value.get('directories',[]))
            return 0
        except Exception as e:framed({'ok':False,'error':str(e)});return 1
    print('Исследование, разработка и тесты — Vladimir B / vlw (vlwwwwww@gmail.com).',flush=True)
    parser=argparse.ArgumentParser(description='Vodafone_hu для всех SIM независимо от страны. '
        'Без флагов: установить по IMSI на SIM, сообщённые iPhone. Без ограничений по модели iPhone и версии iOS; совместимость не гарантируется.',
        add_help=False)
    parser.add_argument('-h','--help',action='help',help='показать эту справку')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--check',action='store_true',help='проверить файлы и библиотеки Apple, без подключения к телефону')
    group.add_argument('--status',action='store_true',help='показать найденные SIM и план, ничего не записывать')
    group.add_argument('--restore',action='store_true',help='удалить все ссылки по IMSI и включить штатный выбор профилей; путь не нужен')
    group.add_argument('--restore-backup',type=Path,metavar='КАТАЛОГ',help='дополнительно: вернуть каталог из конкретной резервной копии')
    group.add_argument('--recover',type=Path,nargs='?',const=Path('AUTO'),metavar='ЭТАП',help='восстановиться после сбоя автоматически; путь к этапу необязателен')
    parser.add_argument('--bundle',default=BUNDLE,metavar='ПАКЕТ',
                        help='системный пакет оператора на iPhone вместо Vodafone_hu, например O2_Germany')
    parser.add_argument('--sims',choices=SLOT_CHOICES,default='all',
                        help='на какие SIM установить: 1, 2 или all — все найденные (по умолчанию)')
    parser.add_argument('--trigger',type=Path,metavar='IPCC',help='свой подписанный IPCC вместо комплектного; плата и SIM проверяются')
    parser.add_argument('--attempts',type=int,default=3,metavar='N',help='попытки при временном сбое связи (по умолчанию 3)')
    parser.add_argument('--wait-seconds',type=int,default=180,metavar='СЕК',help='ожидать подключение и разблокировку (по умолчанию 180 секунд)')
    parser.add_argument('--udid',metavar='ID',help='выбрать iPhone, если по USB подключено несколько')
    parser.add_argument('--apple-dir',action='append',default=[],metavar='ПАПКА',help='Windows: папка DLL Apple; можно указать несколько раз')
    parser.add_argument('--runs',type=Path,default=ROOT/'runs',metavar='ПАПКА',help='куда сохранять копии и журналы (по умолчанию runs рядом со скриптом)')
    parser._optionals.title='Параметры'
    args=parser.parse_args()
    DIAG['args']=args
    args.bundle=args.bundle.strip().removesuffix('.bundle')+'.bundle'
    require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle',args.bundle),
            'Имя пакета может содержать только латинские буквы, цифры и _, например O2_Germany.')
    require(1 <= args.attempts <= 10, 'Число попыток должно быть от 1 до 10.')
    require(0 <= args.wait_seconds <= 3600, 'Ожидание должно быть от 0 до 3600 секунд.')
    os.umask(0o077)
    require(sys.version_info >= (3,11), 'Нужен Python 3.11 или новее.')
    from importlib.metadata import version, PackageNotFoundError
    try: installed=version('pymobiledevice3')
    except PackageNotFoundError: raise RuntimeError('Установите зависимости: python -m pip install -r requirements.txt')
    require(installed=='11.12.5', 'Нужен pymobiledevice3 11.12.5: python -m pip install -r requirements.txt')
    assets=load_assets()
    global APPLE_DIRS
    APPLE_DIRS=[str(Path(p).resolve()) for p in args.apple_dir]
    # No shell, no compiler, no native executable bundled with the archive.
    check=subprocess.run(host_command()+['check'],input=json.dumps({'directories':APPLE_DIRS}),
                         capture_output=True,text=True,encoding='utf-8',timeout=20)
    frames=[json.loads(l.split(':',1)[1]) for l in check.stdout.splitlines() if l.startswith('CARRIER_SWAP_JSON:')]
    require(check.returncode==0 and frames and frames[-1].get('ok'),
            'Библиотеки Apple недоступны: '+str(frames[-1].get('error') if frames else check.stderr.strip()))
    if args.check:
        for k,v in environment_info():print(f'{k}: {v}')
        print('Триггеры целы, библиотеки Apple доступны; пакеты будут взяты из системы iPhone. Подключений к телефону не было.');return 0
    args.runs=args.runs.resolve()
    try:
        args.runs.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=args.runs,prefix='.write-test-'):pass
    except OSError as error:
        raise RuntimeError(f'Скрипт не может сохранить копии в папку: {args.runs}\n'
                           'Что сделать: закройте это окно, скопируйте всю папку CarrierSIM '
                           'в «Загрузки» и запустите оттуда.') from None
    print('Разблокируйте iPhone и подтвердите доверие компьютеру. Закройте синхронизацию Finder/iTunes.',flush=True)
    with operation_lock(args.runs):return asyncio.run(execute_with_retry(args,assets)) or 0


if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:
        print('Прервано. Не удаляйте папку runs. Если запись уже началась, '+recover_hint()+'.',file=sys.stderr);sys.exit(130)
    except Exception as e:
        if not (len(sys.argv)>1 and sys.argv[1]=='--_host'):
            with contextlib.suppress(Exception):print_diagnostics(e)
        print('Ошибка:',str(e),file=sys.stderr);sys.exit(1)
