# zcan_usb — Linux SocketCAN Driver for NXP USB CANFD DEBUG

A fully reverse-engineered Linux kernel driver for the **NXP USB CANFD DEBUG**
adapter (USB ID `04d8:0053`), also sold as:
- Zhiyuan Electronics USBCANFD-200U
- Waveshare USB-CAN-FD-B

The vendor provides a proprietary Linux library (`libcontrolcanfd.so`) but no
kernel driver. This driver exposes the device as standard SocketCAN interfaces
(`can0`, `can1`), compatible with all Linux CAN tools (`candump`, `cansend`,
`python-can`, etc.).

> **All protocol information was reverse-engineered from USB traffic captures
> and static analysis of `libcontrolcanfd.a`. See [PROTOCOL.md](PROTOCOL.md)
> for full details.**

---

## Features

- Two independent CAN channels (`can0` / `can1`)
- Classic CAN (up to 1 Mbit/s)
- CAN FD (up to 64-byte payload), verified end-to-end on real hardware -
  see [CAN FD](#can-fd) below for the current limitation
- Standard SocketCAN interface — works with `can-utils`, `python-can`, etc.
- Automatic DKMS support for kernel updates

---

## Requirements

- Linux kernel ≥ 5.10
- Kernel headers for your running kernel
- `can-utils` (optional, for testing)

```bash
# Arch Linux
sudo pacman -S linux-headers can-utils

# Ubuntu / Debian
sudo apt install linux-headers-$(uname -r) linux-modules-extra-$(uname -r) can-utils
```

> On Ubuntu, `can-dev` lives in `linux-modules-extra`, which is not installed
> by default on cloud/minimal images — without it `insmod` fails with
> unknown-symbol errors for `alloc_candev`, `open_candev` and friends.

---

## Build & Install

### Manual

```bash
git clone https://github.com/youruser/zcan_usb
cd zcan_usb
make
sudo modprobe can_dev
sudo insmod zcan_usb.ko
```

> After a kernel upgrade, a manual (non-DKMS) build needs the headers and
> modules for the *new* kernel before it will build and load again:
>
> ```bash
> sudo apt install --reinstall linux-headers-$(uname -r) linux-modules-extra-$(uname -r)
> sudo reboot
> ```

### DKMS (survives kernel updates)

```bash
sudo cp -r . /usr/src/zcan_usb-0.5.1
sudo dkms add -m zcan_usb -v 0.5.1
sudo dkms build -m zcan_usb -v 0.5.1
sudo dkms install -m zcan_usb -v 0.5.1
```

### Load at boot (after DKMS install)

```bash
echo "zcan_usb" | sudo tee /etc/modules-load.d/zcan_usb.conf
```

---

## Usage

```bash
# Bring up CAN interface at 500 kbit/s
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# Receive frames
candump can0

# Send a frame
cansend can0 7DF#0201050000000000

# Bring down
sudo ip link set can0 down
```

Verify the driver loaded correctly:
```bash
dmesg | grep zcan
# usb 1-1: device handshake OK
# usb 1-1: fw=0x0200 hw=0x0212 serial=FD212606182356USBCAN
# usb 1-1: registered can0 (channel 0)
# usb 1-1: registered can1 (channel 1)
# usb 1-1: ZCAN USB CANFD connected (2 channels) [v0.5.1]
```

---

## Supported Bitrates

| Bitrate    | Command               |
|------------|-----------------------|
| 125 kbit/s | `bitrate 125000`      |
| 250 kbit/s | `bitrate 250000`      |
| 500 kbit/s | `bitrate 500000`      |
| 1 Mbit/s   | `bitrate 1000000`     |

---

## CAN FD

```bash
# Bring up CAN FD at 500 kbit/s (arbitration and data phase, see note below)
sudo ip link set can0 type can bitrate 500000 dbitrate 500000 fd on
sudo ip link set can0 up

# Send a 64-byte CAN FD frame ("##1" marks it as CAN FD in cansend syntax)
cansend can0 123##1AABBCCDDEEFF00112233445566778899001122334455667788990011223344556677889900112233
```

**Known limitation:** the CAN FD implementation was reverse-engineered from
a live USB capture in which the vendor's own demo only ever ran the data
phase at the *same* bitrate as arbitration - no register encoding for a
genuinely faster, bit-rate-switched (BRS) data phase has been found or
tested. The driver enforces `dbitrate == bitrate`; anything else is
rejected by `do_set_data_bittiming()`. Real BRS operation is unverified.

Tested with `tools/pingpong_test.py --fd --fd-len 64` bridging `can0` and
`can1` on real hardware: 2000/2000 frames round-tripped correctly (100%
success, 0 CRC/counter errors, ~1.8 ms average RTT at 500 kbit/s).

---

## Fault detection and automatic recovery

Disconnecting the physical bus mid-transmission (e.g. unplugging the
`can0`/`can1` bridge on a test setup) reliably breaks the channel - and,
before 0.9.0, reconnecting it did **not** recover it; the channel stayed
stuck losing frames until it was brought down and back up.

The driver now polls `CMD_GET_STATUS` every second and, when it sees the
device-reported fault byte, automatically re-applies the exact same
reset+reinit sequence that a manual `down`/`up` already does. No user
action is required to recover once the physical bus issue is actually
fixed.

While a channel is flagged faulty, frames handed to it are counted as
`tx_errors` instead of `tx_packets` (visible via `ip -details -statistics
link show can0`), so failures are at least observable - **this is a
driver-side approximation, not a real per-frame ACK/error result**: no
function that reports back a real send-error count or rate could be found
anywhere in `libcontrolcanfd.a`/`.so` (checked via disassembly of every
object file and the full exported `.so` symbol table - `CMD_GET_STATUS` is
never issued by the vendor's own code, and its generic `IProperty`
config-tree interface, which is where such info would normally live on
ZLG-derived devices, has `GetPropertys()` implemented as a stub that just
returns 0). See the "Fault detection / recovery" note in the header of
`zcan_usb.c` for the full empirical derivation, and
[PROTOCOL.md](PROTOCOL.md#fault-detection) for the byte-level details.

---

## How It Works

The device uses a custom USB bulk transfer protocol with BEEF/DEAD framing and
AES-128 ECB authentication on open. See [PROTOCOL.md](PROTOCOL.md) for the
complete reverse-engineered protocol specification including:

- Packet framing and checksum algorithm
- AES-128 challenge-response handshake
- All command payloads (INIT_CAN, SET_BAUD, START_CAN, TRANSMIT, etc.)
- TX and RX frame formats
- Endpoint routing
- Initialization sequence quirks

---

## Reverse Engineering Notes

The driver was reverse-engineered using:

1. **USB traffic captures** — Wireshark with `usbmon` on the original
   vendor library (`libcontrolcanfd.so`) running on Linux
2. **Static analysis** — `objdump`, `nm`, and GDB on the static library
   `libcontrolcanfd.a` to recover function names, identify the AES key,
   decode the checksum algorithm, and understand command payloads

Key findings that were non-obvious:
- The device sends 2-byte polling packets on EP1 IN every ~16ms; these must
  be discarded when waiting for command responses
- A channel must be sent `INIT_CAN` **twice** — the second time while it is
  already started, with no `CMD_RESET_CAN` in between — before the device
  populates the RX arbitration word and DLC. With only one `INIT_CAN` the
  payload bytes still arrive on the bulk IN endpoint, but every record has
  `id == 0` and `dlc == 0` and is discarded as a null record, so the
  interface looks dead
- TX frames use `0xF1` marker (classic CAN) or `0xF2` (CAN FD), with a
  26-byte payload for classic CAN and an 86-byte payload for CAN FD
- `transmit_type = 0x00` (auto-retry) is required; `0x01` causes ~50% packet
  loss
- The `type` byte in INIT_CAN must be `0x01` even for classic CAN
- The 86-byte CAN FD TX payload and 76-byte CAN FD RX record were
  reconstructed from disassembly of `GVar::generate_fd_send_frame()` in
  `libcontrolcanfd.a` and cross-checked against a live usbmon capture of
  the vendor's own CAN FD demo (see [PROTOCOL.md](PROTOCOL.md#can-fd) and
  the file header of `zcan_usb.c`) - INIT_CAN/SET_BAUD turned out to need
  no changes at all for CAN FD

---

## License

GPL v2 — see [SPDX header](zcan_usb.c).
