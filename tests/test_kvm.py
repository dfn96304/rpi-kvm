import http.client
import importlib.util
import json
from pathlib import Path
import struct
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
