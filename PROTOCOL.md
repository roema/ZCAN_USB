# ZCAN USB Protocol Documentation

**Device:** NXP USB CANFD DEBUG / Zhiyuan Electronics USBCANFD-200U
**USB ID:** 04d8:0053
**Firmware tested:** fw=0x0200 hw=0x0212

> **Note:** This documentation was entirely reverse-engineered from USB traffic
> captures and static analysis of `libcontrolcanfd.a`. No official protocol
> documentation was available.

---

## USB Endpoints

| Endpoint | Direction | Purpose |
|----------|-----------|---------|
| EP1 OUT (0x01) | Host → Device | Commands (BEEF-framed) + CH0 TX frames |
| EP1 IN  (0x81) | Device → Host | Command responses (BEEF-framed) + 2-byte polling |
| EP2 OUT (0x02) | Host → Device | CH1 TX frames |
| EP2 IN  (0x82) | Device → Host | RX frames received by **CH0** |
| EP3 IN  (0x83) | Device → Host | RX frames received by **CH1** |

> **Important:** EP1 IN continuously sends 2-byte polling packets every ~16ms.
> When reading command responses, these must be discarded until a real
> BEEF-framed response is received.

---

## Command Packet Format

All commands use BEEF/DEAD framing:

```
+--------+--------+--------+--------+--------+--------+--------+--------+
|  0xBE  |  0xEF  | datalen (16-bit BE)      | pkgall | pkgcur |
+--------+--------+--------+--------+--------+--------+--------+--------+
| cmd (16-bit BE) | data[datalen]                                        |
+--------+--------+----...----+--------+--------+--------+--------+
| check (16-bit BE)           |  0xDE  |  0xAD  |
+--------+--------+--------+--------+
```

| Field    | Size       | Description                            |
|----------|------------|----------------------------------------|
| head     | 2 bytes    | Fixed: `0xBEEF`                        |
| datalen  | 2 bytes    | Big-endian, length of data field       |
| pkgall   | 1 byte     | Total packet count (always `0x01`)     |
| pkgcur   | 1 byte     | Current packet number (always `0x01`)  |
| cmd      | 2 bytes    | Command code, big-endian               |
| data     | datalen    | Command-specific payload               |
| check    | 2 bytes    | Checksum                               |
| tail     | 2 bytes    | Fixed: `0xDEAD`                        |

### Checksum Algorithm

Reverse-engineered from `gen_package()` in `gvar.o` (libcontrolcanfd.a):

```c
check = datalen
      + 2 * cmd
      + (pkgall << 8)
      + (pkgcur << 8)
      + sum_of_16bit_bigendian_words(data)
      + 0xBEAD   /* PKG_MAGIC */
```

Result masked to 16 bits.

---

## Initialization Sequence

The following sequence must be followed exactly (verified from USB captures).
Both channels must be fully initialized even when only one is used — otherwise
the device stops delivering RX frames after a TX.

```
1. Wait 1500ms after USB enumeration
2. CMD 0x8001  OPEN_DEVICE    AES-128 challenge-response
3. CMD 0x8005  GET_INFO       Read firmware/hardware version
4. CMD 0x8002  INIT_CAN (ch0) Configure channel 0
5. CMD 0x8002  INIT_CAN (ch1) Configure channel 1
6. CMD 0x800B  SET_BAUD (ch0) Set bitrate
7. CMD 0x8003  START_CAN (ch0) Enable bus
8. CMD 0x800B  SET_BAUD (ch1)
9. CMD 0x8003  START_CAN (ch1)
```

---

## Command Reference

### CMD 0x8001 – OPEN_DEVICE (AES-128 Challenge-Response)

**Direction:** Host → Device (challenge), Device → Host (encrypted response)

This is an authentication handshake. The host sends a 32-byte challenge
plaintext and the device responds with AES-128 ECB encrypted output.

**Host sends 32-byte challenge:**
```
[0..1]  = 0xDE 0xFF  (magic)
[2..5]  = 0x00 0x00 0x00 0x00  (MUST be zero - device rejects non-zero)
[6..7]  = 0x43 0x01  (fixed)
[8..11] = 0xF2 0x89 0x82 0xEE  (fixed)
[12..15]= timestamp / random value
[16..21]= 0xD0 0x1F 0x07 0x11 0x5F 0x68  (fixed)
[22..25]= random bytes
[26..31]= 0xC2 0x3E 0xC8 0x26 0x52 0x36  (fixed tail)
```

**Device responds with 32-byte encrypted output:**
```
response = AES_128_ECB_encrypt(key, challenge[0:16])
         + AES_128_ECB_encrypt(key, challenge[16:32])
```

**AES-128 Key** (extracted from `controlcanfd.o` via GDB):
```
61 62 0B 1A 65 74 63 70 3B 40 75 00 38 22 71 65
```

---

### CMD 0x8005 – GET_INFO

**Direction:** Host → Device (empty payload), Device → Host (info)

**Response payload:**
```
[0..1]  = hw_version (BE)
[2..3]  = fw_version (BE)
[4..5]  = dr_version (BE)
[6..7]  = in_version (BE)
[8..9]  = irq_num
[10..11]= can_num (number of channels)
[12..23]= serial number (ASCII)
[24..39]= hardware type string (ASCII)
```

---

### CMD 0x8002 – INIT_CAN

**Direction:** Host → Device (32 bytes), Device → Host (ACK)

**Payload (verified from USB captures):**
```
[0]     = 0x55  magic
[1]     = 0x02  fixed
[2]     = channel index (0 or 1)
[3]     = 0x01  type (must be 0x01, even for classic CAN)
[4..5]  = 0x00 0x00
[6..9]  = acc_code = 0x00000001
[10..13]= acc_mask = 0xFFFFFFFF
[14..17]= abit_timing = 0x00000000
[18..21]= dbit_timing (bitrate-dependent, see table below)
[22..25]= 0x03 0x01 0x0A 0x02  (fixed, from capture)
[26..29]= 0x00000000
[30]    = 0x00  (termination disabled — hardware has fixed 120Ω)
[31]    = 0x00
```

**dbit_timing values:**

| Bitrate     | dbit_timing  |
|-------------|--------------|
| 125 kbit/s  | `0x0114BE2F` |
| 250 kbit/s  | `0x0014BE2F` |
| 500 kbit/s  | `0x00025E17` |
| 1 Mbit/s    | `0x00022E0B` |

---

### CMD 0x800B – SET_BAUD

**Direction:** Host → Device, Device → Host (ACK)

**4-byte variant (set bitrate):**
```
[0]    = 0x7E  magic
[1]    = channel index
[2..3] = baud_code (BE)
```

**Baud codes:**

| Bitrate     | baud_code |
|-------------|-----------|
| 125 kbit/s  | `0x3FFF`  |
| 250 kbit/s  | `0x1FFF`  |
| 500 kbit/s  | `0x0FFF`  |
| 1 Mbit/s    | `0x007F`  |

**12-byte variant (set hardware ID filter):**
```
[0]     = 0x7E  magic
[1]     = channel index
[2]     = filter mode (0xA0 = ID range, 0xB0 = single ID)
[3]     = 0x01  fixed
[4..7]  = start_id (BE uint32)
[8..11] = end_id   (BE uint32)
```

---

### CMD 0x8003 – START_CAN

**Direction:** Host → Device (4 bytes), Device → Host (ACK)

```
[0] = 0x55  magic
[1] = 0x80
[2] = 0x03
[3] = channel index
```

---

### CMD 0x8008 – RESET_CAN

**Direction:** Host → Device (4 bytes)

```
[0] = 0x55
[1] = 0x80
[2] = 0x03
[3] = channel index
```

---

### CMD 0x8004 – TRANSMIT (TX Frame)

**Direction:** Host → Device via EP1 OUT (CH0) or EP2 OUT (CH1)

TX frames are BEEF-wrapped commands with `cmd = 0x8004`.

**Classic CAN payload (26 bytes, verified from captures):**
```
[0]     = 0x55  magic
[1]     = 0xF1  classic CAN marker (0xF2 = CAN FD)
[2..7]  = 0x00  reserved
[8..9]  = CAN ID, big-endian 16-bit (11-bit SFF)
[10]    = DLC (0..8)
[11..11+dlc-1] = CAN frame data
[12+dlc..21]   = 0x00 padding
[21]    = transmit_type:
          0x00 = normal (auto-retry on arbitration loss or error)
          0x01 = single send (no retry)
[22..25]= 0x00 padding
```

**Example** (ID=0x111, DLC=4, data=AA BB CC 00, normal send):
```
55 F1 00 00 00 00 00 00  01 11 04  AA BB CC 00  00 00 00 00 00 00 00  00 00 00 00
magic type  [reserved ]  ID   DLC  [data      ]  [padding             ] txtype [pad]
```

---

## CAN FD

Reconstructed by disassembling `GVar::generate_fd_send_frame()` /
`GVar::generate_send_frame()` in `gvar.o` (`libcontrolcanfd.a`) with
`objdump`/`nm`, then cross-checked byte-for-byte against a live usbmon
capture of the vendor's own demo (`orig/main.cpp`, which already exercises
`ZCAN_TransmitFD`/`ZCAN_ReceiveFD`) with `can0`/`can1` bridged together.
10/10 captured round trips (5 CH0→CH1, 5 CH1→CH0, IDs 0..9, 64-byte
payloads) matched this layout exactly, and it has since been confirmed
working on real hardware via `tools/pingpong_test.py --fd` (2000/2000
frames, 100% success).

### CMD_TRANSMIT (0x8004) - CAN FD TX Frame

**Direction:** Host → Device via EP1 OUT (CH0) or EP2 OUT (CH1), same as
classic CAN.

**CAN FD payload (86 bytes):**
```
[0]     = 0x55  magic
[1]     = 0xF2  CAN FD marker (0xF1 = classic CAN)
[2..3]  = 0x00  reserved
[4]     = EFF flag (0 = standard, 1 = extended)
[5]     = RTR flag (0 = data, 1 = remote)
[6..9]  = CAN ID, big-endian 32-bit, masked to 29 bits
[10]    = len - actual data byte count 0..64 (NOT a DLC code, unlike the
          RX side - this is the same value as struct canfd_frame.len)
[11]    = flags - raw canfd_frame.flags (CANFD_BRS / CANFD_ESI bits)
[12]    = 0x01  fixed (always 1 in the vendor packer, unconditional)
[13]    = channel index (0 or 1) - NOTE: different offset than classic
          CAN, which uses byte[20]
[14..14+len-1] = CAN FD data
[81]    = transmit_type (0x00 = normal, auto-retry - same convention as
          classic CAN)
```
All other bytes are 0x00 padding; the payload is always the fixed 86
bytes regardless of `len` (mirrors classic CAN's fixed 26-byte payload).

**Example** (ID=0x000, len=64, data=00 01 02 ... 3F, channel 0, normal send):
```
55 F2 00 00 00 00  00 00 00 00  40 7F 01 00  00 01 02 ... 3F  [zero padding]  00  [zero padding]
magic type  [rsv]  EFF RTR [ID (32-bit BE)]  len fl  fx  ch   [data (64B)  ]                  txtype
```
(`flags`/`transmit_type` in this specific example reflect uninitialized
fields in the vendor demo's own struct, not a meaningful value - set them
explicitly when generating real traffic; see `zcan_usb.c`.)

---

## RX Frame Format, CAN FD (EP2 IN / EP3 IN)

Same endpoint routing as classic CAN (EP2 → CH0, EP3 → CH1), raw packets
without BEEF framing, but a fixed **76-byte** record instead of 21 bytes.

**Frame structure:**
```
[0..3]  = arbitration word, little-endian 32-bit (identical to classic
          CAN - same layout, same decode; see "The arbitration word" under
          the classic RX frame format below)
[4..5]  = 0x00 0x00
[6]     = lower nibble = CAN FD DLC CODE (0..15, translate via the
          standard CAN FD DLC table: 9→12, 10→16, 11→20, 12→24, 13→32,
          14→48, 15→64, otherwise code == length); upper nibble = 0x3 in
          every captured sample (vs. 0x0 for classic CAN) - this is what
          the driver uses to tell a 21-byte classic record apart from a
          76-byte CAN FD record when demultiplexing an RX URB. Classic
          RTR/error frames were never captured, so it is unverified
          whether their byte[6] upper nibble is also always 0x0.
[7]     = 0xFF (fixed marker, same as classic CAN)
[8..8+len-1] = CAN FD data (len from the DLC code above, up to 64)
[72..75]     = running hardware timestamp counter, little-endian,
               ticking at roughly 100us per LSB (not decoded by the
               driver)
```
Always a fixed 76-byte record regardless of actual `len`, mirroring both
the classic CAN 21-byte RX record and the fixed 86-byte CAN FD TX payload.

**Example** (standard ID=0x001, len=64, data=00 01 02 ... 3F):
```
00 00  04 00  00 00  3F FF  00 01 02 ... 3F  <4-byte timestamp>
↑↑↑↑↑↑↑↑↑↑↑↑               ↑↑
ID=1 (0x00040000>>18)       DLC code=0xF=15 → len=64
```

### Known limitation: no verified bit-rate-switched (BRS) data phase

INIT_CAN/SET_BAUD are sent identically for CAN FD and classic CAN channels
(same acc_code/acc_mask/dbit_timing/baud_code, `type=0x01` was already
required for classic CAN too - see CMD_INIT_CAN above). The capture used
to reverse-engineer this only exercised CAN FD at the *same* bitrate for
arbitration and data phase; the vendor demo itself left `abit_timing`
uninitialized (it differed between the two channels in the capture with no
correlation to the configured rate), yet 64-byte CAN FD frames still
transmitted and received correctly end-to-end. No register encoding for a
genuinely faster, bit-rate-switched data phase has been found or tested.
The driver requires `dbitrate == bitrate` and rejects anything else.

---

## RX Frame Format (EP2 IN / EP3 IN)

RX frames arrive as **raw 21-byte packets** without BEEF framing.

**Endpoint routing:**
- **EP2 IN (0x82):** Frames received by CH0
- **EP3 IN (0x83):** Frames received by CH1

> **Warning:** Both channels must be started (INIT + BAUD + START) for both
> endpoints to deliver data. If CH1 is not initialized, EP3 stays silent and
> the device stops sending frames on EP2 after any TX is performed.

**Frame structure (verified from live USB captures):**
```
[0..3]  = arbitration word, little-endian 32-bit (see below)
[4..5]  = 0x00 0x00
[6]     = lower nibble = DLC  (upper nibble = frame flags)
[7]     = 0xFF  (fixed marker)
[8..8+dlc-1] = CAN frame data
[8+dlc..20]  = 0x00 padding
```

### The arbitration word `[0..3]`

Bytes `[0..3]` are a little-endian 32-bit word holding the raw CAN
arbitration field as the controller latched it — not a packed CAN ID:

```
bits  0..28 = identifier
bit      30 = IDE  (1 = extended / 29-bit frame, 0 = standard / 11-bit)
```

ISO 11898-1 defines a 29-bit extended identifier as an 11-bit **base ID**
followed by an 18-bit **extension**, so the identifier of a *standard*
frame lands at bits 18..28 — **not** at bits 0..10. Bytes `[0..1]`, which
earlier revisions of this document described as "flags / partial
timestamp", are in fact the low 18 bits of an extended identifier (they
read as zero on standard frames).

**Decoding:**
```c
u32 raw = (u32)frame[0] | ((u32)frame[1] << 8) |
	  ((u32)frame[2] << 16) | ((u32)frame[3] << 24);

if (raw & BIT(30))
	can_id = (raw & CAN_EFF_MASK) | CAN_EFF_FLAG;	/* 29-bit */
else
	can_id = (raw >> 18) & CAN_SFF_MASK;		/* 11-bit  */

u8  dlc  = frame[6] & 0x0f;   /* lower nibble */
u8 *data = frame + 8;
```

The standard-frame branch is arithmetically identical to the older
`(((u32)frame[3] << 8) | frame[2]) >> 2` formula, so 11-bit decoding is
unchanged.

**Example** (standard ID=0x111, DLC=4, data=AA BB CC 00):
```
00 00  44 04  00 00  04 FF  AA BB CC 00  00 00 00 00 00 00 00 00 00 00 00
↑↑↑↑↑↑↑↑↑↑↑↑               ↑↑
arbitration word            DLC=4 (lower nibble of 0x04)
```
CAN ID calculation: `0x04440000 >> 18 = 0x111` ✓
(equivalently `0x0444 >> 2 = 0x111`)

**Example** (extended ID=0x04DA0081, DLC=8):
```
81 00  DA 44  00 00  08 FF  <8 data bytes>  00 ... 00
↑↑↑↑↑↑↑↑↑↑↑↑
arbitration word = 0x44DA0081
```
`0x44DA0081 & BIT(30)` is set → extended frame,
`0x44DA0081 & CAN_EFF_MASK = 0x04DA0081` ✓

Decoding this frame with the standard-frame formula instead yields
`0x44DA >> 2 = 0x1136`, masked to 11 bits `0x136` — i.e. the base ID
alone. This is the truncation reported in issue #1.

---

## Notes

- The 1500ms startup delay is required — the device firmware needs time to
  initialize after USB enumeration before it will accept the AES handshake.
- The AES key was extracted from `controlcanfd.o` using GDB on a
  statically linked test binary.
- The `PKG_MAGIC = 0xBEAD` constant was found in the disassembly of
  `gen_package()` in `gvar.o`.
- `transmit_type = 0x00` (auto-retry) is required for reliable transmission;
  `0x01` (single send) causes ~50% packet loss in practice.
- The `type = 0x01` field in INIT_CAN must always be set to `0x01` even when
  using classic CAN — the device ignores the distinction at the frame level.

---

## Fault Detection

### CMD_GET_STATUS (0x800D)

**Direction:** Host → Device (4 bytes), Device → Host (response)

```
[0] = 0x55  magic
[1] = 0x80
[2] = 0x0D
[3] = channel index
```

This command was long marked unverified in this project (its opcode came
from a dead DWARF enumerator, not from any observed traffic - see the
`CMD_GET_STATUS` note in `zcan_usb.c`). It **is** real: the device returns
a well-formed 64-byte BEEF-framed response, and the request's `[3]`
channel-index byte turns out **not to matter** - the response always
contains status for both channels, back to back:

```
data[0..11]  = CH0 status block
data[12..23] = CH1 status block
```

**This per-channel-block structure was initially missed**: an early
empirical pass only ever induced a fault on CH0 and (wrongly) assumed a
single fixed response offset applied to both channels; a follow-up test
that induced the fault on CH1 instead showed the exact same signal 12
bytes further into the response, confirming the block layout above. The
driver originally always inspected only the CH0 block regardless of which
channel it was actually checking - meaning `zcan_status_poll()` never
detected CH1 faults at all until this was fixed.

Within each 12-byte block, relative byte 6 has a confirmed meaning:

```
block[6] = 0x00   while that channel's frames are actually reaching the
                   bus (idle or actively transmitting/receiving without
                   errors)
block[6] = 0x80   while that channel's transmission is reliably failing
                   (confirmed by disconnecting the physical bridge
                   between two bridged channels and hammering TX with
                   tools/pingpong_test.py - reproduced independently for
                   both CH0 and CH1)
```

i.e. `data[6]` for CH0's fault state, `data[18]` for CH1's. Confirmed
across three independent test runs by sampling the `status_ch0`/
`status_ch1` sysfs attributes every 0.5s: the fault byte was *never*
observed to be anything other than exactly `0x00` or exactly `0x80` - no
intermediate values, no other bits set alongside bit 7. It takes roughly
2 seconds of continuously failing sends for it to flip from `0x00` to
`0x80`, consistent with an internal error count that needs to accumulate
before crossing some threshold, rather than a per-frame result. After
reconnecting the physical bus, it moves away from `0x80` (observed as
`0x4c` in one capture) but does not reliably settle back to a clean
`0x00` on its own - a full reset+reinit (`CMD_RESET_CAN` + `CMD_INIT_CAN`
+ `CMD_SET_BAUD` + `CMD_START_CAN`, i.e. the same sequence a manual
`ip link down`/`up` triggers) was required to actually restore
transmission, which is what `zcan_usb.c`'s periodic `zcan_status_poll()`
now automates.

Whether this represents genuine ISO 11898-1 bus-off or a firmware-internal
"gave up retrying" flag tied to `transmit_type = 0x00` (auto-retry mode)
could not be determined - both would produce exactly this observed
behavior, and telling them apart isn't possible from the host side
without lower-level access to the CAN controller.

The rest of each block (bytes other than relative offset 6) looks like it
may carry status/error-counter-like fields (relative offset 10 was seen
at `0x0f` idle, fluctuating `0x08`-`0x18` during real healthy traffic, and
pinned at `0x7b` throughout the fault condition) but is **not decoded or
relied on** - it did not behave like a live, continuously-incrementing
counter in testing (it jumps to a value and then stays constant for many
consecutive samples despite continued TX attempts), and there is no
vendor reference for it: `libcontrolcanfd.a`/`.so` was checked in full
(disassembly of every object file, plus the complete exported `.so`
symbol table) for any function that reads back a real error count/rate,
and there isn't one. `CMD_GET_STATUS` is never issued anywhere in the
vendor's own compiled code, and the generic `IProperty` config-tree
interface it exposes (`GetValue`/`SetValue`/`GetPropertys`, normally how
ZLG-derived devices expose things like error info or bus usage) has
`GetPropertys()` implemented as a stub that unconditionally returns 0.

### Driver behavior

`zcan_usb.c` polls `CMD_GET_STATUS` once per second (a single query
covers both channels, see above) while at least one channel is up. For
each running channel, when its block's fault byte reads `0x80`:
- The channel is flagged internally so `ndo_start_xmit` counts subsequent
  frames as `tx_errors` instead of `tx_packets` (a driver-side
  approximation for visibility via `ip -details -statistics link show`,
  not a real per-frame result - see above).
- The reset+reinit sequence is re-applied automatically for that channel,
  so it recovers on its own once the underlying physical issue is
  actually fixed, without requiring a manual `down`/`up`.
