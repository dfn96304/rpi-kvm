import http.client
import importlib.util
import json
from pathlib import Path
import struct
import socket
import subprocess
import sys
import shutil
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('kvm', Path(__file__).parents[1] / 'rpi_kvm.py')
kvm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kvm)

class Reports(unittest.TestCase):
    def test_boot_keyboard(self):
        self.assertEqual(kvm.keyboard_report(5, [76]), b'\x05\0\x4c\0\0\0\0\0')
        for mods, keys in [(256, []), (True, []), (0, [4] * 7), (0, [232]), (0, [True])]:
            with self.assertRaises(ValueError): kvm.keyboard_report(mods, keys)

    def test_pointer(self):
        self.assertEqual(kvm.mouse_report(7, 32767, 1, -127), struct.pack('<BHHb', 7, 32767, 1, -127))
        for values in [(8, 0, 0, 0), (0, -1, 0, 0), (0, 0, 32768, 0), (0, 0, 0, 128)]:
            with self.assertRaises(ValueError): kvm.mouse_report(*values)

    def test_lease_watchdog(self):
        hid = kvm.HID(True)
        try:
            hid.update(dict(client='a', kind='keyboard', mods=0, keys=[4]))
            with self.assertRaises(ValueError): hid.update(dict(client='b', kind='heartbeat'))
            hid.update(dict(client='a', kind='release'))
            hid.update(dict(client='b', kind='heartbeat'))
            self.assertEqual(hid.owner, 'b')
            hid.last = time.monotonic() - 3
            hid.pressed = True
            time.sleep(.35)
            self.assertIsNone(hid.owner)
            self.assertFalse(hid.pressed)
        finally: hid.close()

    def test_partial_release_retries(self):
        hid = kvm.HID(True)
        try:
            with patch.object(hid, 'emit', side_effect=[OSError('unplugged'), None]) as emit:
                hid.release()
                self.assertEqual(emit.call_count, 2)
                self.assertTrue(hid.pressed)
        finally: hid.close()

class Media(unittest.TestCase):
    def test_attribute_clear_is_nonempty_kernel_write(self):
        with tempfile.TemporaryDirectory() as directory:
            attribute = Path(directory) / 'attribute'
            kvm.write(attribute, '')
            self.assertEqual(attribute.read_bytes(), b'\n')
            kvm.write(attribute, kvm.KEYBOARD)
            self.assertEqual(attribute.read_bytes(), kvm.KEYBOARD)

    def test_path_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ['boot.iso', 'disk.img', 'secret.txt']: (root / name).touch()
            (root / 'link.iso').symlink_to(root / 'secret.txt')
            (root / 'dir.iso').mkdir()
            self.assertEqual(kvm.images(root), ['boot.iso', 'disk.img'])
            for name in ('../boot.iso', 'link.iso', 'dir.iso', 'secret.txt', None):
                with self.assertRaises(ValueError): kvm.image_path(root, name)

    def test_jpeg_chunk_boundaries(self):
        parser = kvm.JPEGParser()
        self.assertEqual(parser.feed(b'junk\xff'), [])
        self.assertEqual(parser.feed(b'\xd8abc\xff'), [])
        self.assertEqual(parser.feed(b'\xd9\xff\xd8two\xff\xd9'), [b'\xff\xd8abc\xff\xd9', b'\xff\xd8two\xff\xd9'])
        with self.assertRaises(ValueError): parser.feed(b'\xff\xd8' + b'a' * (8 * 1024 * 1024))

    @unittest.skipUnless(shutil.which('ffmpeg'), 'FFmpeg not installed')
    def test_real_ffmpeg_capture_and_shutdown(self):
        args = SimpleNamespace(demo=True, format='mjpeg', size='320x240', fps=5, video='/dev/video0')
        video = kvm.Video(args)
        try:
            with video.condition:
                ready = video.condition.wait_for(lambda: video.frame is not None, 8)
            self.assertTrue(ready, video.error)
            self.assertTrue(video.frame.startswith(b'\xff\xd8'))
            self.assertTrue(video.frame.endswith(b'\xff\xd9'))
            self.assertIsNone(video.error)
        finally:
            video.close()
        self.assertFalse(video.thread.is_alive())
        self.assertIsNotNone(video.process.poll())

    def test_capture_retry_joins_slow_stderr_reader(self):
        # Delay iteration longer than the old 200 ms join timeout. The child
        # exits immediately, so stdout EOF races with the delayed stderr read.
        processes, failures = [], []
        third_attempt = threading.Event()
        real_popen = subprocess.Popen
        class DelayedPipe:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): self.stream.close()
            def __iter__(self):
                time.sleep(.35)
                return iter(self.stream)
            def close(self): self.stream.close()
        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            # Make the diagnostic exist before close() can terminate this attempt.
            process.wait(timeout=3)
            process.stderr = DelayedPipe(process.stderr)
            processes.append(process)
            if len(processes) >= 3: third_attempt.set()
            return process
        args = SimpleNamespace()
        command = [sys.executable, '-c', 'import sys; print("camera missing", file=sys.stderr)']
        with patch.object(kvm.Video, 'command', return_value=command), \
             patch.object(kvm.subprocess, 'Popen', side_effect=spawn), \
             patch.object(threading, 'excepthook', side_effect=failures.append), \
             self.assertLogs(kvm.LOG, level='WARNING') as logs:
            video = kvm.Video(args)
            try:
                self.assertTrue(third_attempt.wait(10), 'Capture did not retry')
            finally:
                video.close()
        self.assertEqual(failures, [])
        self.assertFalse(video.thread.is_alive())
        self.assertEqual(video.error, 'camera missing')
        self.assertGreaterEqual(len(logs.output), 2)
        for process in processes:
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stderr.stream.closed)
            self.assertTrue(process.stdout.closed)

    def test_capture_shutdown_kills_child_ignoring_sigterm(self):
        ready, failures = threading.Event(), []
        real_drain = kvm.drain_stderr
        def drain(stream, consume):
            def line(value):
                consume(value)
                ready.set()
            real_drain(stream, line)
        command = [sys.executable, '-c',
                   'import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                   'print("ready", file=sys.stderr, flush=True); time.sleep(60)']
        with patch.object(kvm.Video, 'command', return_value=command), \
             patch.object(kvm, 'drain_stderr', side_effect=drain), \
             patch.object(threading, 'excepthook', side_effect=failures.append):
            video = kvm.Video(SimpleNamespace())
            try:
                self.assertTrue(ready.wait(3))
            finally: video.close()
        self.assertFalse(video.thread.is_alive())
        self.assertEqual(video.process.returncode, -9)
        self.assertEqual(failures, [])

    def test_audio_shutdown_finishes_readers_before_closing_pipes(self):
        real_popen = subprocess.Popen
        real_drain = kvm.drain_stderr
        failures = []
        def spawn(_command, **kwargs):
            process = real_popen([sys.executable, '-c',
                                  'import sys; print("audio unavailable", file=sys.stderr)'], **kwargs)
            process.wait(timeout=3)
            return process
        def slow_drain(stream, consume):
            time.sleep(.35)
            real_drain(stream, consume)
        with patch.object(kvm.subprocess, 'Popen', side_effect=spawn), \
             patch.object(kvm, 'drain_stderr', side_effect=slow_drain), \
             patch.object(threading, 'excepthook', side_effect=failures.append), \
             self.assertLogs(kvm.LOG, level='WARNING'):
            audio = kvm.Audio('test-card')
            audio.close()
        self.assertEqual(failures, [])
        self.assertTrue(all(not reader.is_alive() for reader in audio.readers))
        self.assertTrue(all(process.poll() is not None for process in audio.processes))

    def test_video_command(self):
        video = object.__new__(kvm.Video)
        video.args = SimpleNamespace(demo=False, format='mjpeg', size='1280x720', fps=30, video='/dev/video9')
        self.assertIn('copy', video.command())
        video.args.format = 'yuyv422'
        self.assertNotIn('copy', video.command())
        self.assertIn('mjpeg', video.command())

class HTTP(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        video = SimpleNamespace(error=None, updated=time.monotonic(), stop=threading.Event(), condition=threading.Condition(), sequence=1, frame=b'\xff\xd8test\xff\xd9')
        self.hid = kvm.HID(True)
        args = SimpleNamespace(images=self.temp.name, demo=True, cert=None)
        self.state = dict(args=args, video=video, audio=None, hid=self.hid, token='a' * 32, csrf='b' * 32, session='c' * 32, media_lock=threading.Lock())
        self.server = kvm.Server(('127.0.0.1', 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self):
        self.state['video'].stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.hid.close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def headers(self):
        return {'Origin': f'http://127.0.0.1:{self.port}', 'Cookie': 'kvm=' + self.state['session'], 'X-KVM-CSRF': self.state['csrf'], 'Content-Type': 'application/json'}

    def test_login_cookie_csp(self):
        self.assertEqual(self.request('GET', '/api/status')[0], 401)
        self.assertIn(b'Access token', self.request('GET', '/')[2])
        code, headers, _ = self.request('POST', '/login', 'token=' + 'a' * 32, {'Origin': f'http://127.0.0.1:{self.port}'})
        self.assertEqual(code, 303)
        self.assertIn('HttpOnly; SameSite=Strict', headers['Set-Cookie'])
        code, headers, body = self.request('GET', '/', headers=self.headers())
        self.assertEqual(code, 200)
        self.assertIn(b'<script nonce="' + b'b' * 32, body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])

    def test_login_page_preserves_browser_form_origin(self):
        # Browsers apply the document policy to its form POST. no-referrer
        # makes that request's Origin null, so the policy is part of login's
        # response contract, not just a cosmetic security header.
        code, headers, body = self.request('GET', '/')
        self.assertEqual(code, 200)
        self.assertEqual(headers['Referrer-Policy'], 'strict-origin-when-cross-origin')
        self.assertIn(b'action="/login"', body)
        code, _, _ = self.request('POST', '/login', 'token=' + self.state['token'],
                                   {'Origin': f'http://127.0.0.1:{self.port}'})
        self.assertEqual(code, 303)

    def test_login_rejects_cross_site_and_opaque_origins(self):
        for origin in ['http://evil.example', 'null', f'http://127.0.0.1:{self.port + 1}', None]:
            with self.subTest(origin=origin):
                headers = {} if origin is None else {'Origin': origin}
                code, _, _ = self.request('POST', '/login', 'token=' + self.state['token'], headers)
                self.assertEqual(code, 403)

    def test_csrf_and_validation(self):
        obj = json.dumps(dict(client='a', kind='keyboard', mods=0, keys=[4]))
        headers = self.headers(); headers['Origin'] = 'http://evil.example'
        self.assertEqual(self.request('POST', '/api/hid', obj, headers)[0], 403)
        headers = self.headers(); del headers['X-KVM-CSRF']
        self.assertEqual(self.request('POST', '/api/hid', obj, headers)[0], 403)
        self.assertEqual(self.request('POST', '/api/hid', '[]', self.headers())[0], 400)
        self.assertEqual(self.request('POST', '/api/hid', obj, self.headers())[0], 200)
        self.assertEqual(self.hid.owner, 'a')

    def test_media_insert_eject(self):
        with patch.object(kvm, 'ROOT', Path(self.temp.name) / 'gadget'):
            lun = kvm.ROOT / 'functions/mass_storage.disk/lun.0/file'
            lun.parent.mkdir(parents=True); lun.touch(); (lun.parent / 'cdrom').write_text('0')
            (Path(self.temp.name) / 'boot.iso').touch()
            self.assertEqual(self.request('POST', '/api/media', '{"image":"boot.iso"}', self.headers())[0], 200)
            self.assertTrue(lun.read_text().strip().endswith('/boot.iso'))
            self.assertEqual(self.request('POST', '/api/media', '{"image":"boot.iso"}', self.headers())[0], 400)
            self.assertEqual(self.request('POST', '/api/media', '{"image":null}', self.headers())[0], 200)
            self.assertEqual(lun.read_text(), '\n')
            (lun.parent / 'cdrom').write_text('1')
            (Path(self.temp.name) / 'disk.img').touch()
            self.assertEqual(self.request('POST', '/api/media', '{"image":"disk.img"}', self.headers())[0], 400)

    @unittest.skipUnless(socket.has_dualstack_ipv6(), 'IPv6 dual stack unavailable')
    def test_dual_stack_listener_serves_ipv6_and_ipv4(self):
        server = kvm.Server(('::', 0), self.state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertEqual(server.socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY), 0)
            for host in ['::1', '127.0.0.1']:
                with self.subTest(host=host):
                    connection = http.client.HTTPConnection(host, server.server_port, timeout=2)
                    authority = f'[{host}]' if ':' in host else host
                    origin = f'http://{authority}:{server.server_port}'
                    try:
                        connection.request('GET', '/')
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        response.read()
                        connection.request('POST', '/login', 'token=' + self.state['token'],
                                           {'Origin': origin})
                        response = connection.getresponse()
                        self.assertEqual(response.status, 303)
                        cookie = response.getheader('Set-Cookie').split(';')[0]
                        response.read()
                        connection.request('POST', '/api/hid',
                                           json.dumps(dict(client='dual', kind='heartbeat')),
                                           {'Origin': origin, 'Cookie': cookie,
                                            'X-KVM-CSRF': self.state['csrf']})
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        response.read()
                    finally: connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    @unittest.skipUnless(shutil.which('ffmpeg'), 'FFmpeg not installed')
    def test_missing_capture_card_keeps_http_and_hid_available(self):
        failures = []
        args = SimpleNamespace(demo=False, format='mjpeg', size='320x240', fps=5,
                               video=str(Path(self.temp.name) / 'absent-camera'))
        with patch.object(threading, 'excepthook', side_effect=failures.append), \
             patch.object(kvm.LOG, 'warning', wraps=kvm.LOG.warning) as warnings:
            video = kvm.Video(args)
            self.state['video'] = video
            try:
                deadline = time.monotonic() + 8
                while warnings.call_count < 2 and time.monotonic() < deadline:
                    time.sleep(.025)
                self.assertGreaterEqual(warnings.call_count, 2)
                code, _, body = self.request('GET', '/api/status', headers=self.headers())
                self.assertEqual(code, 200)
                self.assertIn('absent-camera', json.loads(body)['video_error'])
                obj = json.dumps(dict(client='a', kind='keyboard', mods=0, keys=[4]))
                self.assertEqual(self.request('POST', '/api/hid', obj, self.headers())[0], 200)
            finally: video.close()
        self.assertEqual(failures, [])
        self.assertFalse(video.thread.is_alive())

    def test_stream_waits_without_spinning_before_first_frame(self):
        class CountingCondition(threading.Condition):
            calls = 0
            def wait_for(self, *args, **kwargs):
                self.calls += 1
                return super().wait_for(*args, **kwargs)
        video = self.state['video']
        video.sequence, video.frame = 0, None
        video.condition = CountingCondition()
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            connection.request('GET', '/stream', headers=self.headers())
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            time.sleep(.15)
            self.assertLessEqual(video.condition.calls, 2)
        finally:
            video.stop.set()
            with video.condition: video.condition.notify_all()
            connection.close()

    def test_multipart_stream(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        connection.request('GET', '/stream', headers=self.headers())
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn('multipart', response.getheader('Content-Type'))
        self.assertEqual(response.readline(), b'--frame\r\n')
        self.assertEqual(response.readline(), b'Content-Type: image/jpeg\r\n')
        self.assertEqual(response.readline(), b'Content-Length: 8\r\n')
        self.assertEqual(response.readline(), b'\r\n')
        self.assertEqual(response.read(8), self.state['video'].frame)
        connection.close()

if __name__ == '__main__': unittest.main()
