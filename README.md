# rpi-kvm

A minimal, independently written IP-KVM for an **existing Raspberry Pi OS / Linux installation**. One Python script, embedded browser UI, no pip packages, Docker, Node build, or custom OS image. FFmpeg is the only extra runtime executable.

**Status: hardware-unverified prototype.** Automated HTTP/HID/media tests and a real FFmpeg test-pattern capture run in development. Embedded JavaScript passes a syntax check; browser interaction remains unverified because this development environment has no Chromium executable. A physical Raspberry Pi, capture card, BIOS and UAC2 audio have not been tested. This is a small alternative inspired by PiKVM's feature set, not a copy of its implementation or a claim of full compatibility.

| Feature | Implementation | Status |
|---|---|---|
| Keyboard | DWC2/configfs USB HID, boot keyboard, six-key rollover | Implemented; needs target/BIOS testing |
| Mouse | Separate absolute USB HID pointer, buttons and wheel | Implemented; firmware support varies |
| Mass storage | Removable read-only ISO/IMG, insert/eject without rebinding HID | Implemented; storage profile |
| Video | USB V4L2 capture → FFmpeg → browser MJPEG | FFmpeg demo verified; physical card untested |
| Duplex audio | USB UAC2 ↔ ALSA ↔ FFmpeg ↔ browser PCM | Experimental; separate audio profile |
| Access | Token login, HttpOnly/SameSite cookie, CSRF/origin checks, optional TLS | Automated tests |

## Hardware that fits this design

Use a **Pi 4 or Pi 5**, Ethernet/Wi-Fi, and a UVC USB HDMI capture card. The USB-C connector exposes the SoC's gadget controller; USB-A ports serve the capture card. Connect the target's HDMI output to the capture card and the target's USB host port to the Pi's USB-C gadget port.

Pi Zero models have one USB data controller: it cannot be a USB host for the capture card and a USB gadget for the target simultaneously. They are therefore unsuitable for this exact USB-capture design without extra hardware. A CSI capture design would be a different implementation.

Power the Pi reliably. Do not tie two independent 5 V supplies together with an ordinary Y cable. Use suitable isolated power/data wiring or a properly designed power splitter; follow Raspberry Pi's OTG wiring guidance. The target USB port may not supply enough power, especially for a Pi 5 plus capture card. The physical connector must support data; a charge-only cable will not work.

## Quick start

Python 3.9+ on a normal Linux installation with configfs, libcomposite, DWC2, HID and mass-storage gadget drivers. UAC2 is only required for audio.

1. Install FFmpeg (skip if already installed):

   ```sh
   sudo apt install ffmpeg
   ```

2. In `/boot/firmware/config.txt` (older OS installations use `/boot/config.txt`), add under an appropriate `[all]` section:

   ```ini
   dtoverlay=dwc2,dr_mode=peripheral
   ```

   Reboot once. Stop any existing USB gadget service or legacy `g_*` module that owns the controller. Newer Raspberry Pi OS gadget networking services may also claim it. This script refuses to overwrite another gadget.

3. Put `rpi_kvm.py` in a directory on the Pi. Create its media directory and copy an ISO/IMG there:

   ```sh
   mkdir -p images
   # Copy your existing ISO/IMG into images/ using scp, sftp, etc.
   sudo python3 rpi_kvm.py setup --images ./images
   sudo python3 rpi_kvm.py serve --images ./images
   ```

   The first serve creates `kvm.token` with mode 0600 and prints the login token once. Later, retrieve it locally with `sudo cat kvm.token`. Keep the token private. By default the service listens only on `127.0.0.1:8080`.

4. On your client computer, open a tunnel:

   ```sh
   ssh -N -L 8080:127.0.0.1:8080 YOUR_USER@PI_ADDRESS
   ```

   Open **http://localhost:8080**, enter the token, then click **Control**. Keyboard and pointer events go to the target, not the Pi's desktop. Use the dedicated Ctrl+Alt+Del button for that reserved shortcut.

Setup persists in the running kernel until teardown/reboot. Restarting `serve` does not re-enumerate USB, eject the inserted image, or modify the boot configuration. Run setup again after reboot, or use the optional systemd unit below. Stop the server before teardown:

```sh
sudo python3 rpi_kvm.py teardown
```

### Read-only CD-ROM / initial media

Normal storage mode exposes a read-only removable disk; whether an ISO boots as such depends on the ISO and firmware. For an optical drive presentation:

```sh
sudo python3 rpi_kvm.py setup --cdrom --images ./images --image installer.iso
```

CD-ROM mode accepts ISOs only. Switching between disk and CD-ROM requires teardown/setup and re-enumerates the gadget. The UI inserts existing files; it does not upload images, create filesystems or expose arbitrary device paths. Eject before inserting another image. A target can prevent removal; if eject fails, eject/unmount the device in the target OS first. There is deliberately no forced-eject button.

All media is exported **read-only**. Do not modify an image locally while the target has it inserted, and do not locally mount writable copies of live images. No writable mass-storage mode is provided.

## Capture tuning

The default is 1280×720 at 30 FPS using the capture card's MJPEG output. One FFmpeg process serves all viewers; Python retains only the newest compressed JPEG. MJPEG is passed through without decoding or re-encoding. Slow viewers skip frames instead of growing a queue. Four simultaneous streams are allowed.

Check card capabilities with the optional `v4l-utils` package:

```sh
v4l2-ctl --device /dev/video0 --list-formats-ext
sudo python3 rpi_kvm.py doctor
sudo python3 rpi_kvm.py serve --video /dev/video0 --size 1920x1080 --fps 30
```

Choose a mode the card actually supports. For raw YUYV cards:

```sh
sudo python3 rpi_kvm.py serve --format yuyv422 --size 1280x720 --fps 15
```

Raw capture needs USB bandwidth and JPEG encoding CPU; MJPEG capture is preferable. On some cards `/dev/video1` is metadata rather than capture. Use a stable `/dev/v4l/by-id/...` path when available. No audio comes from the HDMI card in this implementation; audio uses the target's USB audio gadget instead.

MJPEG keeps the stack small and widely compatible, but uses more network bandwidth than inter-frame codecs. At an average 100 KiB/frame and 30 FPS, expect roughly 25 Mbit/s per viewer. Real card quality, frame sizes and latency need measurement. There is no measured Pi CPU/latency claim and no WebRTC/H.264 stack hidden in the dependencies.

## Experimental bidirectional audio

Audio is an optional alternative profile, **without mass storage**. DWC2 has a limited endpoint budget. Two HID functions + storage + duplex UAC2 including feedback may exceed it; this implementation does not promise all four USB functions together. Even the audio profile needs testing on the particular kernel/controller. On kernels supporting `no_out_endpoint`, unused interrupt OUT endpoints are disabled for HID.

```sh
# Stop serve first; this intentionally disconnects and re-enumerates USB.
sudo python3 rpi_kvm.py teardown
sudo python3 rpi_kvm.py setup --profile audio
arecord -l
aplay -l
# Substitute the actual ALSA card identifier reported above:
sudo python3 rpi_kvm.py serve --audio-device hw:CARD=UAC2Gadget,DEV=0
```

Optional discovery commands `arecord`/`aplay` are from `alsa-utils`. The runtime audio bridge itself uses FFmpeg built with ALSA support. Pick the **gadget ALSA card**, not your HDMI capture card.

- **Listen to target:** target USB speaker output → gadget ALSA capture → browser playback.
- **Send microphone:** browser microphone → gadget ALSA playback → target USB microphone input.
- Select the USB audio device in the target OS. Use headphones to avoid acoustic feedback.
- Open through an SSH localhost tunnel or HTTPS for microphone permissions.
- Format is fixed 48 kHz, stereo, signed 16-bit PCM. Each direction uses about 1.54 Mbit/s before overhead. The browser mic is duplicated to stereo.
- Browser audio uses Web Audio and the older ScriptProcessor API to keep a single-file implementation; modern Chromium/Firefox are the intended initial test clients. No Opus, adaptive jitter buffer, echo cancellation guarantee, clock drift correction, or automatic audio-device recovery is claimed. Audio processes restart with the service; video capture retries automatically.
- One active audio listener/microphone is intended. The audio queue is bounded and shared; it does not broadcast to multiple listeners.

If a gadget fails to bind with an endpoint allocation error, return to the storage profile. Audio is a prototype extension, not a hardware-validated feature.

## Network and control behavior

SSH tunnelling is the shortest secure route. For direct LAN access, supply a certificate trusted by the client:

```sh
sudo python3 rpi_kvm.py serve --listen 0.0.0.0 --cert /path/server.crt --key /path/server.key
```

Plain HTTP on a LAN transports the login token and target screen/input unencrypted; use the tunnel or TLS for actual access. The built-in server is intended for a private network/tunnel, not public internet exposure. Reverse proxies must preserve the expected origin/scheme; forwarded headers are deliberately not trusted. This is not a hardened public multi-user service.

One tab holds a two-second input lease. An inactivity watchdog releases keys/buttons after failed/disconnected input and retries release when the target returns. Switching tabs or losing focus releases input. This depends on the kernel accepting the release report; unplugged targets cannot receive reports until reconnected. HID writes have timeouts, the browser input queue is bounded, and resource limits cap HTTP workers/video viewers. Browser/OS-reserved shortcuts and secure attention keys require explicit buttons or remain unavailable.

Keyboard events use physical key codes; the **target's** keyboard layout determines characters. The mouse is absolute and accounts for video letterboxing. Some BIOS/UEFI implementations may accept the boot keyboard but not the absolute mouse; this needs physical testing. No clipboard, text paste, ATX/reset, serial console, virtual network, VNC, image upload, or GPIO functionality is included.

Gadget setup and the simple default serve command run as root. The HTTP service therefore has substantial local privilege: keep the script, token, image directory, and TLS key protected from untrusted local users. A future privilege-separated helper could reduce this at the cost of the single-process design. Default VID/PID are development placeholders; obtain/use an appropriate assigned pair before distributing hardware. Override with `--vid`, `--pid`, and a unique `--serial`.

## Optional start at boot

After installing the script as `/opt/rpi-kvm/rpi_kvm.py` and media under `/opt/rpi-kvm/images`, adapt `rpi-kvm.service`, place it in `/etc/systemd/system/`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rpi-kvm
```

The sample stays on loopback. Reboot still requires the DWC2 overlay from Quick start. This unit uses the storage profile; edit both setup and serve arguments for an audio profile. It leaves gadget configuration and inserted media intact on service stop; run teardown explicitly when desired. The unit reuses a matching bound gadget on restart and refuses profile/identity mismatches; use teardown/setup when changing those options.

## Development and verification

```sh
python3 -m unittest discover -s tests -v
python3 rpi_kvm.py serve --demo --port 8080
```

Demo mode generates an FFmpeg test pattern and suppresses USB HID writes. It does not create a gadget or simulate kernel storage/UAC2. `tests/browser_smoke.cjs` is optional development tooling requiring an installed Playwright + Chromium; neither is a Pi runtime dependency. Run it against the demo URL with the token file path as its second argument.

Automated coverage includes HID encoding/bounds, input lease/watchdog, partial release failures, JPEG chunk boundaries/memory bounds, image allowlists, capture commands, login/cookies/CSP, cross-origin/CSRF rejection, input validation, media insert/eject and multipart streaming. Real Linux configfs operations, USB enumeration/endpoint allocation, hotplug, firmware interaction, physical capture and duplex audio still need a Pi test matrix. A filesystem mock cannot validate those.

## Design references

- [PiKVM project](https://github.com/pikvm/pikvm) — original inspiration and a much larger feature set.
- [Linux gadget/configfs](https://docs.kernel.org/usb/gadget_configfs.html)
- [Linux HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [Linux mass-storage gadget](https://docs.kernel.org/usb/mass-storage.html)
- [Linux gadget function testing / UAC2](https://docs.kernel.org/usb/gadget-testing.html)
- [Raspberry Pi OTG application note](https://pip.raspberrypi.com/categories/685-app-notes-guides-whitepapers/documents/RP-009276-WP/Using-OTG-mode-on-Raspberry-Pi-SBCs.pdf)
- [FFmpeg device documentation](https://ffmpeg.org/ffmpeg-devices.html)

Independently written code; no PiKVM source copied. MIT license.
