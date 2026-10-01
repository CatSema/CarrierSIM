"""ATC protocol regressions with an in-memory device; no phone is contacted."""
import asyncio
import plistlib
import unittest

import airtraffic_native as atc


def message(command, session=1, params=None):
    row = {'Command': command, 'Session': session, 'Type': 0}
    if params is not None:
        row['Params'] = params
    return row


class FakeService:
    def __init__(self):
        self.data = bytearray()
        self.wake = asyncio.Event()
        self.sent = []
        self.closed = False

    def feed(self, row):
        self.data.extend(atc.frame(row))
        self.wake.set()

    async def recvall(self, size):
        while len(self.data) < size:
            self.wake.clear()
            await self.wake.wait()
        result = bytes(self.data[:size])
        del self.data[:size]
        return result

    async def sendall(self, raw):
        assert int.from_bytes(raw[:4], 'little') == len(raw) - 4
        self.sent.append(plistlib.loads(raw[4:]))

    async def close(self):
        self.closed = True


class FakeDevice:
    def __init__(self, service):
        self.service = service
        self.closed = False

    async def start_lockdown_service(self, name):
        assert name == 'com.apple.atc'
        return self.service

    async def close(self):
        self.closed = True


class FramingTest(unittest.IsolatedAsyncioTestCase):
    async def test_binary_plist_little_endian_frame(self):
        raw = atc.frame(message('Ping'))
        self.assertEqual(int.from_bytes(raw[:4], 'little'), len(raw) - 4)
        self.assertTrue(raw[4:].startswith(b'bplist00'))

    async def test_bad_frames_are_rejected(self):
        for raw in (b'\0\0\0\0', (atc.MAX_ATC_FRAME + 1).to_bytes(4, 'little'),
                    atc.frame(['not', 'a', 'dict']), (3).to_bytes(4, 'little') + b'bad'):
            with self.subTest(raw=raw[:8]):
                service = FakeService()
                service.data.extend(raw)
                service.wake.set()
                client = atc.NativeAtcClient(service, lambda _: None)
                with self.assertRaises(atc.AtcError):
                    await asyncio.wait_for(client.read_message(), .1)

    async def test_wrong_envelope(self):
        service = FakeService()
        service.feed({'Command': 'Ping', 'Session': 1})
        with self.assertRaises(atc.AtcError):
            await atc.NativeAtcClient(service, lambda _: None).read_message()


class ProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.service = FakeService()
        self.device = FakeDevice(self.service)
        self.events = []
        self.assets = [('a', 'dest-a'), ('b', 'dest-b'), ('c', 'dest-c')]

    async def run_client(self, authorize, probe=False):
        async def connector(**kwargs):
            self.assertEqual(kwargs['connection_type'], 'Network')
            return self.device
        await atc.run_session('udid', 'Network', self.assets, self.events.append,
                              authorize, probe=probe, connector=connector)

    def startup(self, support=None, protected=False):
        if support is not None:
            self.service.feed(message('Capabilities', 0, {'GrappaSupportInfo': support}))
        self.service.feed(message('SyncAllowed', 0, {'DataProtected': protected}))

    def manifest(self, rows=None):
        if rows is None:
            rows = [{'AssetID': item, 'IsDownload': True} for item, _ in self.assets]
        self.service.feed(message('AssetManifest', 1, {'AssetManifest': {'Book': rows}}))

    async def wait_sent(self, command, count=1):
        async with asyncio.timeout(3):
            while sum(row['Command'] == command for row in self.service.sent) < count:
                await asyncio.sleep(.005)

    async def test_probe_stops_before_metadata(self):
        self.startup()
        task = asyncio.create_task(self.run_client(lambda: None, probe=True))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await task
        self.assertNotIn('FinishedSyncingMetadata', [r['Command'] for r in self.service.sent])
        self.assertTrue(self.device.closed and self.service.closed)

    async def test_grappa_in_both_messages(self):
        self.startup({'version': 1, 'deviceType': 0, 'protocolVersion': 1})
        task = asyncio.create_task(self.run_client(lambda: None, probe=True))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await task
        host, request = self.service.sent[:2]
        self.assertEqual(host['Params']['HostInfo']['Grappa'], atc.GRAPPA_TOKEN)
        self.assertEqual(request['Params']['Grappa'], atc.GRAPPA_TOKEN)
        self.assertEqual(len(atc.GRAPPA_TOKEN), 84)
        self.assertNotIn(atc.GRAPPA_TOKEN.hex(), repr(self.events))

    async def test_unknown_grappa_and_protected_abort_before_metadata(self):
        for support, protected in (({'version': 2, 'deviceType': 0, 'protocolVersion': 1}, False),
                                   (None, True)):
            self.service = FakeService()
            self.device = FakeDevice(self.service)
            self.startup(support, protected)
            with self.assertRaises(atc.AtcError):
                await self.run_client(lambda: None, probe=True)
            self.assertFalse(self.service.sent)

    async def test_capability_after_sync_allowed_is_included(self):
        self.startup()
        self.service.feed(message('Capabilities', 0, {'GrappaSupportInfo': {
            'version': 1, 'deviceType': 0, 'protocolVersion': 1}}))
        task = asyncio.create_task(self.run_client(lambda: None, probe=True))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await task
        self.assertEqual(self.service.sent[0]['Params']['HostInfo']['Grappa'], atc.GRAPPA_TOKEN)

    async def test_late_grappa_aborts_before_metadata(self):
        self.startup()
        task = asyncio.create_task(self.run_client(lambda: None, probe=True))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('Capabilities', 1, {'GrappaSupportInfo': {
            'version': 1, 'deviceType': 0, 'protocolVersion': 1}}))
        with self.assertRaises(atc.AtcError):
            await task
        self.assertNotIn('FinishedSyncingMetadata', [r['Command'] for r in self.service.sent])

    async def test_wrong_ready_session_and_sync_failed(self):
        for answer in (message('ReadyForSync', 0), message('SyncFailed', 1, {'ErrorCode': 4})):
            self.service = FakeService()
            self.device = FakeDevice(self.service)
            self.startup()
            task = asyncio.create_task(self.run_client(lambda: None, probe=True))
            await self.wait_sent('RequestingSync')
            self.service.feed(answer)
            with self.assertRaises(atc.AtcError):
                await task

    async def test_manifest_missing_or_duplicate_sends_no_filecomplete(self):
        for rows in ([{'AssetID': 'a', 'IsDownload': True}],
                     [{'AssetID': 'a', 'IsDownload': True}] * 2 +
                     [{'AssetID': x, 'IsDownload': True} for x in ('b', 'c')]):
            self.service = FakeService()
            self.device = FakeDevice(self.service)
            self.startup()
            task = asyncio.create_task(self.run_client(lambda: asyncio.sleep(0)))
            await self.wait_sent('RequestingSync')
            self.service.feed(message('ReadyForSync'))
            await self.wait_sent('FinishedSyncingMetadata')
            self.manifest(rows)
            with self.assertRaises(atc.AtcError):
                await task
            self.assertNotIn('FileComplete', [r['Command'] for r in self.service.sent])

    async def test_two_phase_commit_responds_to_ping(self):
        allow = asyncio.Event()
        async def authorize():
            await allow.wait()
            return True
        self.startup()
        task = asyncio.create_task(self.run_client(authorize))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await self.wait_sent('FinishedSyncingMetadata')
        self.manifest()
        await self.wait_sent('FileComplete', 2)
        async with asyncio.timeout(3):
            while not any(e.get('event') == 'before-final-asset' for e in self.events):
                await asyncio.sleep(.005)
        self.assertEqual([r['Params']['AssetID'] for r in self.service.sent if r['Command'] == 'FileComplete'], ['a', 'b'])
        self.service.feed(message('Ping'))
        await self.wait_sent('Pong')
        for command in ('AssetMetrics', 'InstalledAssets', 'Capabilities'):
            self.service.feed(message(command))
        async with asyncio.timeout(3):
            while not any(e.get('name') == 'Capabilities' and e.get('session') == 1 for e in self.events):
                await asyncio.sleep(.005)
        self.assertFalse(task.done())
        self.assertEqual(sum(r['Command'] == 'FileComplete' for r in self.service.sent), 2)
        allow.set()
        await self.wait_sent('FileComplete', 3)
        self.service.feed(message('SyncFinished'))
        await task
        self.assertEqual([r['Params']['AssetID'] for r in self.service.sent if r['Command'] == 'FileComplete'], ['a', 'b', 'c'])

    async def test_commit_eof_prevents_third_asset(self):
        self.startup()
        task = asyncio.create_task(self.run_client(lambda: asyncio.sleep(0, result=False)))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await self.wait_sent('FinishedSyncingMetadata')
        self.manifest()
        with self.assertRaises(atc.AtcError):
            await task
        self.assertEqual(sum(r['Command'] == 'FileComplete' for r in self.service.sent), 2)

    async def test_sync_failed_during_commit_prevents_third_asset(self):
        allow = asyncio.Event()
        async def authorize():
            await allow.wait()
            return True
        self.startup()
        task = asyncio.create_task(self.run_client(authorize))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await self.wait_sent('FinishedSyncingMetadata')
        self.manifest()
        await self.wait_sent('FileComplete', 2)
        self.service.feed(message('AssetMetrics'))
        self.service.feed(message('SyncFailed', 1, {'ErrorCode': 4}))
        with self.assertRaises(atc.AtcError):
            await task
        self.assertEqual(sum(r['Command'] == 'FileComplete' for r in self.service.sent), 2)

    async def test_sync_finished_is_required(self):
        self.startup()
        task = asyncio.create_task(self.run_client(lambda: asyncio.sleep(0, result=True)))
        await self.wait_sent('RequestingSync')
        self.service.feed(message('ReadyForSync'))
        await self.wait_sent('FinishedSyncingMetadata')
        self.manifest()
        await self.wait_sent('FileComplete', 3)
        self.assertFalse(task.done())
        self.service.feed(message('SyncFailed', 1, {'ErrorCode': 4}))
        with self.assertRaises(atc.AtcError):
            await task
