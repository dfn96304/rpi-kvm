#!/usr/bin/env python3
"""Tiny Linux USB KVM. Python standard library + system FFmpeg; no pip packages."""
import argparse
import collections
import contextlib
import errno
import fcntl
import hmac
import http.cookies
import json
import logging
import os
from pathlib import Path
import re
import secrets
import select
import signal
import ssl
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LOG = logging.getLogger('rpi-kvm')
ROOT = Path('/sys/kernel/config/usb_gadget/rpi-kvm')
KEYBOARD = bytes.fromhex('05010906a101050719e029e71500250175019508810295017508810395057501050819012905910295017503910395067508150025650507190029658100c0')
# Absolute pointer: 3 buttons, 16-bit X/Y (0..32767), signed wheel.
MOUSE = bytes.fromhex('05010902a1010901a1000509190129031500250195037501810295017505810305010930093116000026ff7f75109502810209381581257f750895018106c0c0')


def write(path, value):
    # configfs needs a nonempty write to clear attributes (e.g. UDC/LUN file).
    Path(path).write_bytes(value if isinstance(value, bytes) else (str(value) + '\n').encode())


def run(*args):
    subprocess.run(args, check=True)


def images(directory):
    root = Path(directory).resolve()
    return sorted(p.name for p in root.iterdir()
                  if p.suffix.lower() in ('.iso', '.img') and p.is_file()
                  and not p.is_symlink())


def image_path(directory, name):
    if not isinstance(name, str) or name not in images(directory):
        raise ValueError('Choose an existing .iso or .img in the image directory')
    return Path(directory).resolve() / name


def configure(args):
    if os.geteuid() != 0:
        raise RuntimeError('USB gadget setup needs sudo')
    run('modprobe', 'libcomposite')
    if not Path('/sys/kernel/config/usb_gadget').is_dir():
        run('mount', '-t', 'configfs', 'none', '/sys/kernel/config')
    udcs = list(Path('/sys/class/udc').iterdir())
    if not udcs:
        raise RuntimeError('No UDC. Enable dtoverlay=dwc2,dr_mode=peripheral and reboot')
    udc = args.udc or (udcs[0].name if len(udcs) == 1 else None)
    if udc not in [p.name for p in udcs]:
        raise RuntimeError('Select a controller with --udc: ' + ', '.join(p.name for p in udcs))
    if ROOT.exists() and args.reuse:
        expected = 'mass_storage.disk' if args.profile == 'storage' else 'uac2.audio'
        if (ROOT / 'UDC').read_text().strip() != udc or not (ROOT / 'functions' / expected).exists():
            raise RuntimeError('Existing gadget/controller does not match requested profile')
        for key, value in [('idVendor', args.vid), ('idProduct', args.pid)]:
            if int((ROOT / key).read_text().strip(), 16) != int(value, 16):
                raise RuntimeError('Existing gadget USB identity differs; teardown first')
        if (ROOT / 'strings/0x409/serialnumber').read_text().strip() != args.serial:
            raise RuntimeError('Existing gadget serial differs; teardown first')
        if args.profile == 'storage':
            lun = ROOT / 'functions/mass_storage.disk/lun.0'
            if int((lun / 'cdrom').read_text().strip()) != int(args.cdrom):
                raise RuntimeError('Existing storage mode differs; teardown first')
            if args.image and (lun / 'file').read_text().strip() != str(image_path(args.images, args.image)):
                raise RuntimeError('Existing media differs; eject/insert explicitly')
        print('Reusing existing bound gadget')
        return
    for gadget in ROOT.parent.iterdir():
        if (gadget / 'UDC').read_text().strip() == udc:
            raise RuntimeError(f'{udc} is already owned by {gadget.name}; stop its service first')
    if ROOT.exists():
        raise RuntimeError('Our gadget already exists; run teardown before reconfiguring')
    ROOT.mkdir()
    try:
        for key, val in {'idVendor': args.vid, 'idProduct': args.pid,
                         'bcdDevice': '0x0100', 'bcdUSB': '0x0200'}.items():
            write(ROOT / key, val)
        strings = ROOT / 'strings/0x409'
        strings.mkdir()
        for key, val in {'serialnumber': args.serial, 'manufacturer': 'rpi-kvm',
                         'product': 'Minimal USB KVM'}.items():
            write(strings / key, val)
        config = ROOT / 'configs/c.1'
        config.mkdir()
        (config / 'strings/0x409').mkdir()
        write(config / 'strings/0x409/configuration', args.profile)
        write(config / 'MaxPower', '250')
        for name, desc, size, subclass, protocol in [
                ('hid.keyboard', KEYBOARD, 8, 1, 1), ('hid.mouse', MOUSE, 6, 0, 0)]:
            function = ROOT / 'functions' / name
            function.mkdir()
            for key, val in {'protocol': protocol, 'subclass': subclass,
                             'report_length': size, 'report_desc': desc}.items():
                write(function / key, val)
            if (function / 'no_out_endpoint').exists():
                write(function / 'no_out_endpoint', 1)
            (config / name).symlink_to(function)
        if args.profile == 'storage':
            function = ROOT / 'functions/mass_storage.disk'
            function.mkdir()
            for key, val in {'stall': 1, 'lun.0/removable': 1, 'lun.0/ro': 1,
                             'lun.0/cdrom': int(args.cdrom)}.items():
                write(function / key, val)
            if args.image:
                write(function / 'lun.0/file', image_path(args.images, args.image))
            (config / function.name).symlink_to(function)
        else:
            # Separate profile: adding storage too can exhaust DWC2 IN endpoints.
            function = ROOT / 'functions/uac2.audio'
            function.mkdir()
            for prefix in ('c', 'p'):
                for key, val in {'chmask': 3, 'srate': 48000, 'ssize': 2}.items():
                    write(function / f'{prefix}_{key}', val)
            (config / function.name).symlink_to(function)
        write(ROOT / 'UDC', udc)
    except Exception:
        teardown()
        raise
    print(f'Gadget bound to {udc}; profile={args.profile}')


def teardown():
    if not ROOT.exists():
        return
    write(ROOT / 'UDC', '')
    for config in (ROOT / 'configs').iterdir():
        for child in config.iterdir():
            if child.is_symlink():
                child.unlink()
        for lang in (config / 'strings').iterdir():
            lang.rmdir()
        config.rmdir()
    for function in (ROOT / 'functions').iterdir():
        function.rmdir()
    for lang in (ROOT / 'strings').iterdir():
        lang.rmdir()
    ROOT.rmdir()


def hid_path(name):
    dev = (ROOT / f'functions/hid.{name}/dev').read_text().strip()
    fields = dict(line.split('=', 1) for line in
                  Path(f'/sys/dev/char/{dev}/uevent').read_text().splitlines() if '=' in line)
    return Path('/dev') / fields['DEVNAME']


def keyboard_report(mods, keys):
    if type(mods) is not int or not 0 <= mods <= 255:
        raise ValueError('Invalid modifier mask')
    if not isinstance(keys, list) or len(keys) > 6 or any(
            type(k) is not int or not 4 <= k <= 101 for k in keys):
        raise ValueError('Keyboard supports six non-modifier keys (HID usages 4..101)')
    return bytes([mods, 0] + keys + [0] * (6 - len(keys)))


def mouse_report(buttons, x, y, wheel):
    for val, low, high in ((buttons, 0, 7), (x, 0, 32767), (y, 0, 32767), (wheel, -127, 127)):
        if type(val) is not int or not low <= val <= high:
            raise ValueError('Invalid pointer report')
    return struct.pack('<BHHb', buttons, x, y, wheel)


class HID:
    def __init__(self, demo=False):
        self.demo = demo
        self.lock = threading.Lock()
        self.owner = None
        self.last = 0
        self.pressed = False
        self.pointer = (0, 0)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.watchdog, daemon=True)
        self.thread.start()

    def emit(self, name, report):
        if self.demo:
            return
        fd = os.open(hid_path(name), os.O_WRONLY | os.O_NONBLOCK)
        try:
            # No indefinitely blocked HTTP workers when the target is unplugged.
            if not select.select([], [fd], [], .15)[1]:
                raise OSError(errno.ETIMEDOUT, 'Target USB is not accepting HID reports')
            if os.write(fd, report) != len(report):
                raise OSError('Short HID write')
        finally:
            os.close(fd)

    def release(self):
        errors = []
        for name, report in [('keyboard', bytes(8)), ('mouse', mouse_report(0, *self.pointer, 0))]:
            try:
                self.emit(name, report)
            except OSError as exc:
                errors.append(str(exc))
        self.pressed = bool(errors)  # Retry releases after target reconnects.
        if errors:
            LOG.debug('Release pending: %s', errors)

    def update(self, obj):
        client = obj.get('client')
        if not isinstance(client, str) or not 1 <= len(client) <= 80:
            raise ValueError('Missing client ID')
        kind = obj.get('kind')
        if kind == 'keyboard':
            report = keyboard_report(obj.get('mods'), obj.get('keys'))
        elif kind == 'mouse':
            report = mouse_report(obj.get('buttons'), obj.get('x'), obj.get('y'), obj.get('wheel', 0))
        elif kind not in ('release', 'heartbeat'):
            raise ValueError('Unknown HID action')
        with self.lock:
            now = time.monotonic()
            if self.owner != client and self.owner and now - self.last < 2:
                raise ValueError('Another browser tab holds the control lease')
            if self.owner != client:
                self.release()
            self.owner, self.last = client, now
            if kind == 'release':
                self.release()
                self.owner = None
            elif kind != 'heartbeat':
                self.pressed = True  # Also release after a partial or failed write.
                self.emit(kind, report)
                if kind == 'mouse':
                    self.pointer = (obj['x'], obj['y'])

    def watchdog(self):
        while not self.stop.wait(.25):
            with self.lock:
                if time.monotonic() - self.last > 2:
                    if self.pressed:
                        self.release()
                    self.owner = None

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        with self.lock:
            self.release()


class JPEGParser:
    """Bounded JPEG marker framing for FFmpeg's image2pipe output."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, chunk):
        self.buffer.extend(chunk)
        frames = []
        while True:
            start = self.buffer.find(b'\xff\xd8')
            if start < 0:
                self.buffer[:] = self.buffer[-1:]
                break
            if start:
                del self.buffer[:start]
            end = self.buffer.find(b'\xff\xd9', 2)
            if end < 0:
                break
            frames.append(bytes(self.buffer[:end + 2]))
            del self.buffer[:end + 2]
        if len(self.buffer) > 8 * 1024 * 1024:
            self.buffer.clear()
            raise ValueError('Capture frame exceeds 8 MiB')
        return frames


class Video:
    def __init__(self, args):
        self.args = args
        self.condition = threading.Condition()
        self.frame = None
        self.sequence = 0
        self.updated = 0
        self.error = 'Starting capture'
        self.stop = threading.Event()
        self.process = None
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()

    def command(self):
        a = self.args
        cmd = ['ffmpeg', '-hide_banner', '-loglevel', 'error', '-nostdin']
        if a.demo:
            cmd += ['-re', '-f', 'lavfi', '-i', f'testsrc2=size={a.size}:rate={a.fps}']
        else:
            cmd += ['-f', 'v4l2', '-input_format', a.format, '-video_size', a.size,
                    '-framerate', str(a.fps), '-i', a.video]
        cmd += ['-an']
        cmd += ['-c:v', 'copy'] if a.format == 'mjpeg' and not a.demo else ['-c:v', 'mjpeg', '-q:v', '5', '-threads', '1']
        return cmd + ['-f', 'image2pipe', 'pipe:1']

    def worker(self):
        while not self.stop.is_set():
            try:
                self.process = subprocess.Popen(self.command(), stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, bufsize=0)
                process = self.process
                errors = collections.deque(maxlen=8)
                def drain():
                    for line in process.stderr:
                        errors.append(line.decode(errors='replace').strip()[:400])
                drainer = threading.Thread(target=drain, daemon=True)
                drainer.start()
                parser = JPEGParser()
                while not self.stop.is_set():
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        break
                    for frame in parser.feed(chunk):
                        with self.condition:
                            self.frame = frame
                            self.sequence += 1
                            self.updated = time.monotonic()
                            self.error = None
                            self.condition.notify_all()
                drainer.join(timeout=.2)
                self.error = '; '.join(errors) or 'Capture stopped; retrying'
            except (OSError, ValueError) as exc:
                self.error = str(exc)
            finally:
                if self.process:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
                    self.process.stdout.close()
                    self.process.stderr.close()
            if not self.stop.is_set():
                LOG.warning('Video: %s', self.error)
            self.stop.wait(2)

    def close(self):
        self.stop.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
        with self.condition:
            self.condition.notify_all()
        self.thread.join(timeout=4)


LOGIN = '''<!doctype html><meta name="viewport" content="width=device-width"><title>rpi-kvm login</title>
<style>body{background:#101724;color:#eaf2ff;font:18px system-ui;max-width:500px;margin:15vh auto;padding:20px}input,button{padding:12px;margin:8px 0;width:100%;box-sizing:border-box}</style>
<h1>rpi-kvm</h1><p>Your tiny portal to another computer.</p><form method="post" action="/login">
<input type="password" name="token" placeholder="Access token" required autocomplete="current-password"><button>Connect</button></form>'''

UI = r'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>rpi-kvm</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0d1320;color:#e9f1ff;font:15px system-ui}header{padding:16px 24px;display:flex;gap:18px;align-items:center;background:#151f31;flex-wrap:wrap}h1{font-size:21px;margin:0}small{color:#9aaac3}button,select{background:#24354e;border:1px solid #435774;color:inherit;padding:9px;border-radius:7px;cursor:pointer}button:hover{background:#36516e}main{padding:20px;max-width:1600px;margin:auto}#screen{display:block;width:100%;aspect-ratio:16/9;object-fit:contain;background:#03060b;outline:none;touch-action:none}#screen:focus{box-shadow:0 0 0 2px #51d9c4}section{margin-top:16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}#status{color:#71e6d4;min-height:1.5em}details{margin:20px 0;color:#adbcd3}audio{height:35px}input{max-width:100%}</style>
<header><h1>rpi-kvm <small>· one script, one portal</small></h1><button id="focus">Control</button><button id="release">Release keys</button><button id="cad">Ctrl + Alt + Del</button><button id="full">Fullscreen</button></header>
<main><img id="screen" tabindex="0" alt="Capture stream"><section><select id="images"><option value="">Choose image</option></select><button id="mount">Insert read-only</button><button id="eject">Eject</button><span id="media"></span></section>
<section id="audio" hidden><button id="listen">Listen to target</button><button id="mic">Send microphone</button><button id="stopaudio">Stop audio</button></section>
<p id="status">Connecting…</p><details><summary>Controls & connection</summary><p>Click Control or the picture to send keyboard and absolute pointer input. Focus is outlined in mint. Click outside or switch tabs to release keys. Host keyboard layout determines typed characters. Ctrl+Alt+Del has its own button because your browser/OS reserves some shortcuts. Six simultaneous non-modifier keys are supported. One browser tab controls the target at a time.</p><p>Audio is experimental PCM stereo at 48 kHz and needs HTTPS or an SSH localhost tunnel. The target must select the USB audio gadget as output/input. Start audio only while controlling the target. Media images are provisioned on the Pi; this UI does not upload large ISOs.</p></details></main>
<script>
const csrf='__CSRF__', client=Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join(''), screen=document.querySelector('#screen'), status=document.querySelector('#status');
const $=s=>document.querySelector(s); let queue=Promise.resolve(), active=false, keys=new Set(), mods=0, buttons=0,x=0,y=0,mouseDirty=false;
async function api(path,body){let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-KVM-CSRF':csrf},body:JSON.stringify(body),signal:AbortSignal.timeout(3000)});let j=await r.json();if(!r.ok)throw Error(j.error||r.statusText);return j}
let pending=0,epoch=0,mousePending=false;
function send(body){if(pending>=32&&body.kind!=='release'){status.textContent='Input connection too slow; releasing control';release();return queue}if(body.kind==='release')epoch++;const ticket=epoch;pending++;queue=queue.then(()=>ticket===epoch?api('/api/hid',{client,...body}):null).catch(e=>{epoch++;status.textContent=e.message;active=false;keys.clear();mods=buttons=0;screen.blur()}).finally(()=>pending--);return queue}
const codes={Enter:40,Escape:41,Backspace:42,Tab:43,Space:44,Minus:45,Equal:46,BracketLeft:47,BracketRight:48,Backslash:49,Semicolon:51,Quote:52,Backquote:53,Comma:54,Period:55,Slash:56,CapsLock:57,PrintScreen:70,ScrollLock:71,Pause:72,Insert:73,Home:74,PageUp:75,Delete:76,End:77,PageDown:78,ArrowRight:79,ArrowLeft:80,ArrowDown:81,ArrowUp:82,NumLock:83,NumpadDivide:84,NumpadMultiply:85,NumpadSubtract:86,NumpadAdd:87,NumpadEnter:88,Numpad0:98,NumpadDecimal:99,IntlBackslash:100,ContextMenu:101};
for(let i=0;i<26;i++)codes['Key'+String.fromCharCode(65+i)]=4+i;
for(let i=1;i<=9;i++){codes['Digit'+i]=29+i;codes['Numpad'+i]=88+i}codes.Digit0=39;
for(let i=1;i<=12;i++)codes['F'+i]=57+i;
const modifiers={ControlLeft:1,ShiftLeft:2,AltLeft:4,MetaLeft:8,ControlRight:16,ShiftRight:32,AltRight:64,MetaRight:128};
function keyboard(){send({kind:'keyboard',mods,keys:[...keys]})}
function release(){active=false;keys.clear();mods=buttons=0;mouseDirty=false;send({kind:'release'})}
screen.onfocus=()=>{active=true;status.textContent='Control active'};screen.onblur=release;
for(const type of ['keydown','keyup'])screen.addEventListener(type,e=>{e.preventDefault();if(!active||e.repeat)return;let down=type==='keydown';if(modifiers[e.code]){if(down)mods|=modifiers[e.code];else mods&=~modifiers[e.code]}else if(codes[e.code]){if(down){if(keys.size>=6)return;keys.add(codes[e.code])}else keys.delete(codes[e.code])}else return;keyboard()});
function coords(e){const r=screen.getBoundingClientRect(),vw=screen.naturalWidth||16,vh=screen.naturalHeight||9,scale=Math.min(r.width/vw,r.height/vh),w=vw*scale,h=vh*scale;x=Math.round(Math.max(0,Math.min(1,(e.clientX-r.left-(r.width-w)/2)/w))*32767);y=Math.round(Math.max(0,Math.min(1,(e.clientY-r.top-(r.height-h)/2)/h))*32767)}
function pointer(wheel=0){send({kind:'mouse',buttons,x,y,wheel})}
screen.onpointerdown=e=>{if(e.button>2)return;e.preventDefault();screen.focus();screen.setPointerCapture(e.pointerId);coords(e);buttons=e.buttons&1|(e.buttons&2)|(e.buttons&4);pointer()};
screen.onpointerup=e=>{coords(e);buttons=e.buttons&7;pointer()};screen.onpointercancel=release;
screen.onpointermove=e=>{if(active){coords(e);mouseDirty=true}};
screen.oncontextmenu=e=>e.preventDefault();screen.addEventListener('wheel',e=>{e.preventDefault();if(active)pointer(e.deltaY>0?-1:1)},{passive:false});
// Browser button bitmask matches HID: left=1, right=2, middle=4.
setInterval(()=>{if(active&&mouseDirty&&!mousePending){mouseDirty=false;mousePending=true;send({kind:'mouse',buttons,x,y,wheel:0}).finally(()=>mousePending=false)}},33);
setInterval(()=>{if(active){keyboard();send({kind:'heartbeat'})}},600);
window.addEventListener('blur',release);document.addEventListener('visibilitychange',()=>{if(document.hidden){release();stopAudio()}});
$('#focus').onclick=()=>screen.focus();$('#release').onclick=release;
$('#cad').onclick=async()=>{release();await send({kind:'keyboard',mods:5,keys:[76]});await send({kind:'release'});screen.focus()};
$('#full').onclick=()=>screen.requestFullscreen();
let audioContext,listenSource,micStream,micNode,micSource,nextTime=0,audioRunning=false,micRunning=false;
async function context(){if(!audioContext)audioContext=new AudioContext({sampleRate:48000});await audioContext.resume();if(audioContext.sampleRate!==48000)throw Error('Audio context must run at 48 kHz');return audioContext}
async function listen(){if(audioRunning)return;const ctx=await context();audioRunning=true;nextTime=0;try{while(audioRunning){let r=await fetch('/api/audio',{headers:{'X-KVM-CSRF':csrf}});if(!r.ok)throw Error(await r.text());let data=new Int16Array(await r.arrayBuffer());if(!audioRunning)break;if(!data.length)continue;const n=data.length/2,b=ctx.createBuffer(2,n,48000);for(let c=0;c<2;c++){let d=b.getChannelData(c);for(let i=0;i<n;i++)d[i]=data[i*2+c]/32768}if(nextTime<ctx.currentTime||nextTime>ctx.currentTime+.3)nextTime=ctx.currentTime+.04;let s=ctx.createBufferSource();s.buffer=b;s.connect(ctx.destination);s.start(nextTime);nextTime+=n/48000}}finally{audioRunning=false}}
async function mic(){if(micRunning)return;const ctx=await context();micStream=await navigator.mediaDevices.getUserMedia({audio:{channelCount:1,echoCancellation:true},video:false});micRunning=true;micSource=ctx.createMediaStreamSource(micStream);micNode=ctx.createScriptProcessor(4096,1,1);let busy=false;micNode.onaudioprocess=e=>{if(busy||!micRunning)return;const f=e.inputBuffer.getChannelData(0),pcm=new Int16Array(f.length*2);for(let i=0;i<f.length;i++)pcm[2*i]=pcm[2*i+1]=Math.max(-32768,Math.min(32767,Math.round(f[i]*32767)));busy=true;fetch('/api/audio',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-KVM-CSRF':csrf},body:pcm}).then(async r=>{if(!r.ok)throw Error(await r.text())}).catch(e=>{status.textContent=e.message;stopAudio()}).finally(()=>busy=false)};micSource.connect(micNode);micNode.connect(ctx.destination)}
function stopAudio(){audioRunning=micRunning=false;if(micNode){micNode.disconnect();micNode.onaudioprocess=null;micNode=null}if(micSource){micSource.disconnect();micSource=null}if(micStream){micStream.getTracks().forEach(t=>t.stop());micStream=null}if(audioContext){audioContext.close();audioContext=null}}
for(const [id,fn]of [['listen',listen],['mic',mic]])$('#'+id).onclick=()=>fn().catch(e=>{status.textContent=e.message;stopAudio()});$('#stopaudio').onclick=stopAudio;
async function refresh(){try{let r=await fetch('/api/status'),s=await r.json();if(!r.ok)throw Error('Session expired; reload to sign in');let chosen=$('#images').value;$('#images').replaceChildren(new Option('Choose image',''),...s.images.map(i=>new Option(i,i)));$('#images').value=chosen;$('#mount').disabled=$('#eject').disabled=!s.storage;$('#media').textContent=s.media||'No media inserted';$('#audio').hidden=!s.audio;if(s.video_error)status.textContent=s.video_error;else if(!active)status.textContent=s.demo?'Demo — no USB hardware writes':'Connected · click Control'}catch(e){status.textContent=e.message}}
$('#mount').onclick=()=>api('/api/media',{image:$('#images').value}).then(refresh).catch(e=>status.textContent=e.message);
$('#eject').onclick=()=>api('/api/media',{image:null}).then(refresh).catch(e=>status.textContent=e.message);
screen.src='/stream';screen.onerror=()=>setTimeout(()=>screen.src='/stream?t='+Date.now(),2000);refresh();setInterval(refresh,4000);
</script></html>'''


class Audio:
    """Experimental fixed-format ALSA bridge. Bounded queues; never block HTTP on ALSA."""
    def __init__(self, device):
        self.device = device
        self.condition = threading.Condition()
        self.chunks = collections.deque(maxlen=4)
        self.processes = []
        self.stop = threading.Event()
        self.write_lock = threading.Lock()
        self.error = None
        try:
            capture = subprocess.Popen(['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error',
                                       '-f', 'alsa', '-ac', '2', '-ar', '48000', '-i', device,
                                       '-f', 's16le', '-ac', '2', '-ar', '48000', 'pipe:1'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(capture)
            playback = subprocess.Popen(['ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'error',
                                        '-probesize', '32', '-analyzeduration', '0',
                                        '-f', 's16le', '-ar', '48000', '-ac', '2', '-i', 'pipe:0',
                                        '-f', 'alsa', device], stdin=subprocess.PIPE,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.processes.append(playback)
            os.set_blocking(playback.stdin.fileno(), False)
            self.playback = playback
            for process in self.processes:
                threading.Thread(target=self.errors, args=(process,), daemon=True).start()
            self.thread = threading.Thread(target=self.reader, args=(capture,), daemon=True)
            self.thread.start()
        except Exception:
            self.close()
            raise

    def errors(self, process):
        for line in process.stderr:
            self.error = line.decode(errors='replace').strip()[:400]
            LOG.warning('Audio: %s', self.error)

    def reader(self, process):
        while not self.stop.is_set():
            chunk = process.stdout.read(9600)  # 50 ms stereo PCM.
            if not chunk:
                break
            if len(chunk) % 4:
                self.error = 'Unaligned PCM from FFmpeg'
                break
            with self.condition:
                self.chunks.append(chunk)
                self.condition.notify_all()
        self.error = self.error or 'Audio capture stopped; restart the service'
        with self.condition:
            self.condition.notify_all()

    def read(self):
        with self.condition:
            self.condition.wait_for(lambda: self.chunks or self.error or self.stop.is_set(), 2)
            if self.chunks:
                return self.chunks.popleft()
            if self.error:
                raise ValueError(self.error)
            return b''

    def feed(self, data):
        if not data or len(data) % 4:
            raise ValueError('Expected stereo S16LE PCM')
        with self.write_lock:
            if self.playback.poll() is not None:
                raise ValueError(self.error or 'Audio playback stopped')
            # PIPE_BUF chunks and a short deadline avoid unbounded microphone latency.
            fd = self.playback.stdin.fileno()
            deadline = time.monotonic() + .2
            view = memoryview(data)
            while view:
                timeout = deadline - time.monotonic()
                if timeout <= 0 or not select.select([], [fd], [], timeout)[1]:
                    raise ValueError('Audio playback stalled')
                try:
                    view = view[os.write(fd, view[:4096]):]
                except BlockingIOError:
                    continue

    def close(self):
        self.stop.set()
        with self.condition:
            self.condition.notify_all()
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe:
                    pipe.close()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, state):
        self.state = state
        self.slots = threading.BoundedSemaphore(16)
        self.streams = threading.BoundedSemaphore(4)
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'rpi-kvm/0.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    @property
    def state(self):
        return self.server.state

    def log_message(self, fmt, *args):
        LOG.debug('%s %s', self.client_address[0], fmt % args)

    def reply(self, code, body, content_type='application/json', cookie=None):
        if content_type == 'application/json':
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.headers_safe()
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def headers_safe(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        # no-referrer can suppress Origin on browser form POSTs, breaking login.
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('X-Frame-Options', 'DENY')
        # UI is embedded: only this page's nonce authorizes inline script.
        nonce = self.state['csrf']
        self.send_header('Content-Security-Policy', f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")

    def authenticated(self):
        try:
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            return 'kvm' in cookie and hmac.compare_digest(cookie['kvm'].value, self.state['session'])
        except (http.cookies.CookieError, TypeError):
            return False

    def same_origin(self):
        origin = self.headers.get('Origin')
        expected = ('https' if self.state['args'].cert else 'http') + '://' + self.headers.get('Host', '')
        return origin == expected

    def body(self, limit=32768):
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Transfer encoding is not supported')
        length = int(self.headers.get('Content-Length', '-1'))
        if not 0 <= length <= limit:
            raise ValueError('Request body too large or missing Content-Length')
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError('Incomplete request')
        return data

    def do_GET(self):
        try:
            self.get()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except (OSError, ValueError) as exc:
            self.reply(400, {'error': str(exc)})

    def get(self):
        path = urlsplit(self.path).path
        if not self.authenticated():
            if path == '/':
                return self.reply(200, LOGIN, 'text/html; charset=utf-8')
            return self.reply(401, {'error': 'Sign in first'})
        if path == '/':
            ui = UI.replace('__CSRF__', self.state['csrf']).replace('<script>', f'<script nonce="{self.state["csrf"]}">')
            return self.reply(200, ui, 'text/html; charset=utf-8')
        if path == '/api/status':
            lun = ROOT / 'functions/mass_storage.disk/lun.0/file'
            video = self.state['video']
            return self.reply(200, {'images': images(self.state['args'].images),
                                   'storage': lun.exists(), 'audio': bool(self.state['audio']),
                                   'media': Path(lun.read_text().strip()).name if lun.exists() and lun.read_text().strip() else None,
                                   'video_error': video.error or ('No recent video frames' if time.monotonic() - video.updated > 3 else None),
                                   'demo': self.state['args'].demo})
        if path == '/api/audio':
            if not hmac.compare_digest(self.headers.get('X-KVM-CSRF', ''), self.state['csrf']):
                return self.reply(403, {'error': 'Invalid CSRF header'})
            if not self.state['audio']:
                raise ValueError('Audio bridge is disabled')
            return self.reply(200, self.state['audio'].read(), 'application/octet-stream')
        if path != '/stream':
            return self.reply(404, {'error': 'Not found'})
        if not self.server.streams.acquire(blocking=False):
            return self.reply(503, {'error': 'Four video viewers maximum'})
        try:
            video = self.state['video']
            self.send_response(200)
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
            self.headers_safe()
            self.end_headers()
            seq = -1
            while not video.stop.is_set():
                with video.condition:
                    video.condition.wait_for(lambda: video.sequence != seq or video.stop.is_set(), 2)
                    frame, current = video.frame, video.sequence
                if frame is None or current == seq:
                    continue
                seq = current
                self.wfile.write(b'--frame\r\nContent-Type: image/jpeg\r\nContent-Length: ' +
                                 str(len(frame)).encode() + b'\r\n\r\n' + frame + b'\r\n')
                self.wfile.flush()
        finally:
            self.server.streams.release()

    def do_POST(self):
        try:
            self.post()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except (ValueError, KeyError, TypeError, OSError) as exc:
            self.reply(400, {'error': str(exc)})

    def post(self):
        if not self.same_origin():
            return self.reply(403, {'error': 'Same-origin browser request required'})
        path = urlsplit(self.path).path
        if path == '/login':
            from urllib.parse import parse_qs
            data = parse_qs(self.body(4096).decode())
            token = data.get('token', [''])[0]
            if not hmac.compare_digest(token.encode(), self.state['token'].encode()):
                return self.reply(403, {'error': 'Invalid access token'})
            cookie = f'kvm={self.state["session"]}; HttpOnly; SameSite=Strict; Path=/'
            if self.state['args'].cert:
                cookie += '; Secure'
            self.send_response(303)
            self.send_header('Set-Cookie', cookie)
            self.send_header('Location', '/')
            self.send_header('Content-Length', '0')
            self.headers_safe()
            self.end_headers()
            return
        if not self.authenticated():
            return self.reply(401, {'error': 'Sign in first'})
        if not hmac.compare_digest(self.headers.get('X-KVM-CSRF', ''), self.state['csrf']):
            return self.reply(403, {'error': 'Invalid CSRF header'})
        if path == '/api/audio':
            if not self.state['audio']:
                raise ValueError('Audio bridge is disabled')
            self.state['audio'].feed(self.body())
        else:
            obj = json.loads(self.body())
            if not isinstance(obj, dict):
                raise ValueError('Expected JSON object')
            if path == '/api/hid':
                self.state['hid'].update(obj)
            elif path == '/api/media':
                lun = ROOT / 'functions/mass_storage.disk/lun.0/file'
                if not lun.exists():
                    raise ValueError('Storage profile is not configured')
                name = obj.get('image')
                with self.state['media_lock']:
                    if lun.read_text().strip() and name is not None:
                        raise ValueError('Eject the current image first')
                    if name is not None and (lun.parent / 'cdrom').read_text().strip() == '1' and not str(name).lower().endswith('.iso'):
                        raise ValueError('CD-ROM mode only accepts ISO images')
                    write(lun, '' if name is None else image_path(self.state['args'].images, name))
            else:
                return self.reply(404, {'error': 'Not found'})
        self.reply(200, {'ok': True})


def token_file(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        fd = None
    if fd is not None:
        token = secrets.token_urlsafe(32)
        with os.fdopen(fd, 'w') as stream:
            stream.write(token + '\n')
        print(f'New access token (saved in {path}): {token}', flush=True)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ValueError('Token file must not be a symlink and must have permissions 0600')
    token = path.read_text().strip()
    if len(token) < 24 or not token.isascii():
        raise ValueError('Use an ASCII access token with at least 24 characters')
    return token


def doctor(args):
    import shutil
    print('Python:', os.sys.version.split()[0])
    print('FFmpeg:', shutil.which('ffmpeg') or 'MISSING (sudo apt install ffmpeg)')
    print('Controllers:', ', '.join(p.name for p in Path('/sys/class/udc').glob('*')) or 'NONE')
    print('Video nodes:', ', '.join(str(p) for p in Path('/dev').glob('video*')) or 'NONE')
    print('Configured:', ROOT.exists())
    if ROOT.exists():
        print('Bound UDC:', (ROOT / 'UDC').read_text().strip() or 'unbound')
        for name in ('keyboard', 'mouse'):
            with contextlib.suppress(OSError, KeyError):
                print(name + ':', hid_path(name))
    print('Capture modes: v4l2-ctl --device ' + args.video + ' --list-formats-ext')
    print('Audio devices: arecord -l; aplay -l')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['setup', 'teardown', 'serve', 'doctor'])
    parser.add_argument('--profile', choices=['storage', 'audio'], default='storage')
    parser.add_argument('--udc')
    parser.add_argument('--reuse', action='store_true', help='Setup: reuse a matching bound gadget')
    parser.add_argument('--vid', default='0x1d6b', help='Development default; assign your own for distribution')
    parser.add_argument('--pid', default='0x0104')
    parser.add_argument('--serial', default='rpi-kvm-001')
    parser.add_argument('--images', default='./images')
    parser.add_argument('--image', help='Initial image basename in --images')
    parser.add_argument('--cdrom', action='store_true', help='Expose storage as CD-ROM (ISO only)')
    parser.add_argument('--video', default='/dev/video0')
    parser.add_argument('--format', choices=['mjpeg', 'yuyv422'], default='mjpeg')
    parser.add_argument('--size', default='1280x720')
    parser.add_argument('--fps', type=int, default=30)
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--token-file', default='./kvm.token')
    parser.add_argument('--cert', help='TLS PEM certificate')
    parser.add_argument('--key', help='TLS PEM private key')
    parser.add_argument('--audio-device', help='Experimental duplex ALSA device, e.g. hw:CARD=UAC2Gadget,DEV=0')
    parser.add_argument('--demo', action='store_true', help='Test video and UI without USB writes (serve only)')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(levelname)s %(message)s')
    if not re.fullmatch(r'[1-9][0-9]{1,3}x[1-9][0-9]{1,3}', args.size) or not 1 <= args.fps <= 120:
        parser.error('Use a valid size (e.g. 1280x720) and fps in 1..120')
    if bool(args.cert) != bool(args.key):
        parser.error('--cert and --key must be supplied together')
    if args.cdrom and args.image and not args.image.lower().endswith('.iso'):
        parser.error('--cdrom requires an ISO')
    if args.demo and args.command != 'serve':
        parser.error('--demo is only available for serve')
    if args.command == 'doctor':
        doctor(args)
        return
    if args.command == 'teardown':
        teardown()
        return
    if args.command == 'setup':
        configure(args)
        return
    if not args.demo:
        if not (ROOT / 'UDC').read_text().strip():
            raise RuntimeError('Gadget is unbound; teardown/setup first')
        for name in ('keyboard', 'mouse'):
            if not hid_path(name).exists():
                raise RuntimeError('Configure the gadget first with sudo python3 rpi_kvm.py setup')
    if args.audio_device and (args.demo or not (ROOT / 'functions/uac2.audio').exists()):
        parser.error('--audio-device requires the audio gadget profile')
    Path(args.images).mkdir(parents=True, exist_ok=True)
    # One service owns the gadget; prevents independent watchdogs fighting each other.
    lock_path = Path(args.token_file).absolute().parent / '.rpi-kvm.lock' if args.demo else Path('/run/lock/rpi-kvm.lock')
    lock = open(lock_path, 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    token = token_file(args.token_file)
    hid, video, audio, server = None, None, None, None
    try:
        hid = HID(args.demo)
        video = Video(args)
        audio = Audio(args.audio_device) if args.audio_device else None
        state = {'args': args, 'token': token, 'session': secrets.token_urlsafe(32),
                 'csrf': secrets.token_urlsafe(32), 'hid': hid, 'video': video,
                 'audio': audio, 'media_lock': threading.Lock()}
        server = Server((args.listen, args.port), state)
        if args.cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(args.cert, args.key)
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
        LOG.info('Open %s://%s:%s', 'https' if args.cert else 'http', args.listen, args.port)
        def terminate(_signum, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, terminate)
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.server_close()
        if video:
            video.close()
        if audio:
            audio.close()
        if hid:
            hid.close()
        lock.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        LOG.error('%s', error)
        raise SystemExit(1)
