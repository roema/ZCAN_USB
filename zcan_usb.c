// SPDX-License-Identifier: GPL-2.0
/*
 * zcan_usb - Linux SocketCAN Driver for NXP USB CANFD DEBUG
 *
 * Supports: NXP USB CANFD DEBUG / Zhiyuan Electronics USBCANFD-200U
 * USB ID:   04d8:0053
 * Version:  0.9.0
 *
 * This driver was completely reverse-engineered from USB traffic captures
 * and static analysis of the vendor library (libcontrolcanfd.a).
 * No official protocol documentation was available.
 *
 * Key findings:
 *  - Commands use BEEF/DEAD framing with checksum
 *  - AES-128 ECB challenge-response authentication on open
 *  - TX frames use 0xF1 (classic CAN) or 0xF2 (CANFD) marker
 *  - TX payload is 26 bytes for classic CAN, 86 bytes for CANFD, BEEF-wrapped
 *  - RX frames arrive as raw packets on EP2/EP3: 21 bytes (classic CAN) or
 *    76 bytes (CANFD), no BEEF wrapper
 *  - A channel must be INIT_CAN'd twice before it reports RX frame
 *    headers; a single INIT yields records with id == 0 and dlc == 0
 *
 * CAN FD support (added in 0.8.0):
 *  - The 86-byte TX payload layout was reconstructed byte-exact from
 *    disassembly of GVar::generate_fd_send_frame() in gvar.o
 *    (libcontrolcanfd.a) and cross-checked against a live usbmon capture
 *    of the vendor's own demo (orig/main.cpp, ZCAN_TransmitFD/ReceiveFD)
 *    with both channels bridged - see zcan_dump.pcapng.
 *  - The 76-byte RX record layout was reconstructed purely from that same
 *    capture (5 CH0->CH1 and 5 CH1->CH0 CANFD round trips, IDs/lengths/
 *    channel byte all matched exactly).
 *  - INIT_CAN/SET_BAUD do NOT change for CAN FD: the capture shows the
 *    vendor demo initializing FD channels with the exact same acc_code/
 *    acc_mask/dbit_timing/baud_code as classic CAN (type=0x01 was already
 *    required for classic CAN too, see below) - abit_timing was left
 *    uninitialized by the vendor demo itself (differed between channels
 *    with no correlation to the configured rate) and 64-byte CANFD frames
 *    still transmitted/received correctly end-to-end on real hardware, so
 *    it is set to 0 here, matching the classic path.
 *  - CONSEQUENCE / KNOWN LIMITATION: no evidence of a genuine faster data
 *    phase (BRS) was found or tested - the capture only exercises CAN FD
 *    at the *same* bitrate as arbitration. do_set_data_bittiming() below
 *    therefore requires the data bitrate to equal the nominal bitrate.
 *    Real bit-rate-switched operation is unverified.
 *  - RX record framing (21 vs 76 bytes) is distinguished by the upper
 *    nibble of byte[6] (0x00 = classic, non-zero = CANFD carrying the DLC
 *    code) - confirmed consistently across all 10 captured RX frames, but
 *    classic RTR/error frames were never captured, so it is unverified
 *    whether their byte[6] upper nibble is always 0x00 too. If a classic
 *    RTR/error frame is ever seen to be swallowed as garbage (netdev RX
 *    frames come out corrupted), this discriminator is the place to
 *    revisit.
 *
 * Fault detection / recovery (added in 0.9.0):
 *  - Symptom: disconnecting the physical bridge between can0/can1 mid-test
 *    causes TX frames to never arrive (expected - nothing is listening),
 *    but reconnecting the bridge does NOT recover it: frames keep getting
 *    lost until the channel is brought down and back up.
 *  - CMD_GET_STATUS (0x800D, see the comment on that command below) was
 *    probed empirically by sampling the status_ch0/status_ch1 sysfs
 *    attributes with a Python script (tools/pingpong_test.py) hammering
 *    TX with the bridge disconnected. The response always contains BOTH
 *    channels' status back to back in fixed 12-byte blocks - data[0..11]
 *    for CH0, data[12..23] for CH1 - REGARDLESS of which channel index
 *    was put in the request (an early pass only ever exercised a CH0
 *    fault and wrongly assumed a single fixed offset; a CH1 fault test
 *    showed the exact same signal 12 bytes further in). Within a
 *    channel's block, relative byte 6 (see ZCAN_STATUS_FAULT_OFFSET) was
 *    0x00 in every sample taken while that channel's frames were
 *    actually getting through (idle or active, bridge connected) and
 *    exactly 0x80 in every sample taken once its transmission was
 *    reliably failing (bridge disconnected, observed across three
 *    independent test runs, both channels). It takes a couple of seconds
 *    of continuous failed sends for that byte to flip to 0x80,
 *    consistent with an internal error counter that needs to accumulate
 *    before some threshold is crossed (either genuine ISO 11898 bus-off,
 *    or a firmware-internal "given up retrying" flag tied to the
 *    transmit_type=0x00 auto-retry mode - these could not be told apart
 *    without further hardware-level access).
 *  - IMPORTANT: libcontrolcanfd.a/.so was checked (disassembly of every
 *    object file plus the exported .so symbol table) for any function
 *    that reads back a real error count/rate - there isn't one.
 *    CMD_GET_STATUS is never issued anywhere in the vendor's own compiled
 *    code, and the generic IProperty config-tree interface it exposes
 *    (GetValue/SetValue/GetPropertys, normally used on other ZLG-derived
 *    devices to read out error info) has GetPropertys() implemented as a
 *    stub that just returns 0. There is no vendor ground truth to
 *    validate this response layout against, and no real per-frame
 *    ACK/error feedback available to this driver at all.
 *  - Given that, netdev->stats.tx_errors/tx_packets accounting below is a
 *    driver-synthesized approximation, NOT a real hardware error count:
 *    while a channel's fault byte reads ZCAN_STATUS_FAULT_VALUE, every
 *    frame whose TX URB completes on that channel is counted as
 *    tx_errors instead of tx_packets (the USB transfer itself still
 *    completes normally - we have no way to know if any individual frame
 *    actually reached the bus). See zcan_status_poll().
 *
 * Author: Manuel Rösel
 * manuel.roesel@ros-it.ch
 * Reverse-engineered from USB captures and libcontrolcanfd.a
 * License: GPL v2
 */

#include <linux/module.h>
#include <linux/usb.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/error.h>
#include <linux/can/skb.h>
#include <linux/can/length.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#define DRIVER_VERSION	"0.9.0"
#define DRIVER_NAME	"zcan_usb"

#define ZCAN_VENDOR_ID		0x04d8
#define ZCAN_PRODUCT_ID		0x0053

/* -------------------------------------------------------------------------
 * Protocol constants
 * -------------------------------------------------------------------------
 * All commands use BEEF/DEAD framing:
 *   BE EF | datalen(2BE) | pkgall(1) | pkgcur(1) | cmd(2BE) |
 *   data[datalen] | check(2) | DE AD
 *
 * Checksum = datalen + 2*cmd + (pkgall<<8) + (pkgcur<<8)
 *           + sum_of_16bit_BE_words(data) + 0xBEAD
 */
#define PKG_HEAD_B0		0xBE
#define PKG_HEAD_B1		0xEF
#define PKG_TAIL_B0		0xDE
#define PKG_TAIL_B1		0xAD
#define PKG_MAGIC		0xBEADu	/* added to checksum */

/* Command codes (big-endian) */
#define CMD_OPEN_DEVICE		0x8001	/* AES handshake */
#define CMD_GET_INFO		0x8005	/* read device info */
#define CMD_INIT_CAN		0x8002	/* initialize CAN channel */
#define CMD_SET_BAUD		0x800b	/* set bitrate / hardware filter */
#define CMD_START_CAN		0x8003	/* start CAN channel */
#define CMD_TRANSMIT		0x8004	/* transmit CAN frame */
#define CMD_RESET_CAN		0x8008	/* reset / stop channel */

/*
 * CMD_GET_STATUS - EXPERIMENTAL / UNVERIFIED.
 *
 * 0x800D comes from the DW_TAG_enumerator "CMD_GET_STATUS" found in the
 * DWARF debug info of gvar.o (libcontrolcanfd.a), which also defines
 * ZCAN_CHANNEL_STATUS/ZCAN_CHANNEL_ERR_INFO (regTECounter, regRECounter,
 * bus-off etc.) - exactly the kind of real controller error state this
 * device's netdev stats cannot provide (see zcan_netdev_xmit/zcan_tx_complete:
 * tx_packets is incremented when the USB URB completes, with no feedback
 * on whether the frame was ever ACKed on the physical bus).
 *
 * However, the SAME enum's CMD_RESET_CAN = 0x8009 does NOT match the value
 * verified for this actual device via live USB capture (0x8008, see
 * zcan_reset_channel() below) - so this vendor lib build's command numbering
 * does not reliably match this device's firmware one-to-one.
 *
 * UPDATE (0.9.0): 0x800D DOES get a real, well-formed BEEF-framed response
 * from this device (confirmed via the status_ch0/status_ch1 sysfs
 * attributes on real hardware), and response byte data[6] (resp[8+6], see
 * ZCAN_STATUS_FAULT_OFFSET below) was empirically confirmed to track TX
 * failure - see the "Fault detection / recovery" note in the file header
 * for the full story. The REST of the response layout (regTECounter/
 * regRECounter/bus-off bit positions per ZCAN_CHANNEL_STATUS) is still
 * unconfirmed - libcontrolcanfd.a never issues this command itself, so
 * there is no vendor reference to check the full layout against.
 */
#define CMD_GET_STATUS		0x800d

/*
 * CMD_GET_STATUS response layout (data[], i.e. resp[8 + N] in the raw
 * BEEF-framed response - see zcan_get_status()): the response always
 * contains BOTH channels' status, back to back, in fixed 12-byte blocks -
 * data[0..11] = CH0, data[12..23] = CH1 - REGARDLESS of which channel
 * index was put in the request. (Originally missed: an early empirical
 * pass only ever exercised CH0 faults and assumed a single fixed offset;
 * a CH1 fault test showed the exact same signal 12 bytes further in,
 * confirming the per-channel block layout below.)
 *
 * Within each channel's 12-byte block, byte ZCAN_STATUS_FAULT_OFFSET is
 * empirically observed to be exactly 0x00 whenever TX was actually
 * reaching the bus and exactly ZCAN_STATUS_FAULT_VALUE whenever it
 * reliably wasn't (bridge disconnected, hammering TX) - see the "Fault
 * detection / recovery" note in the file header. Never observed to be
 * any other value in either state.
 */
#define ZCAN_STATUS_CHANNEL_BLOCK_SIZE	12
#define ZCAN_STATUS_FAULT_OFFSET	6
#define ZCAN_STATUS_FAULT_VALUE		0x80

/* USB endpoints */
#define EP_CMD_OUT		0x01	/* commands + CH0 TX out */
#define EP_CMD_IN		0x81	/* command responses in */
#define EP_CH1_TX		0x02	/* CH1 TX out */
#define EP_CH0_RX		0x82	/* CH0 RX in (frames received by CH0) */
#define EP_CH1_RX		0x83	/* CH1 RX in (frames received by CH1) */

/* TX frame type markers */
#define TX_TYPE_CAN		0xF1	/* classic CAN frame */
#define TX_TYPE_CANFD		0xF2	/* CAN FD frame */

/* TX frame layout (classic CAN, payload = 26 bytes):
 *  [0]     = 0x55  magic
 *  [1]     = 0xF1  classic CAN
 *  [2..7]  = 0x00  reserved
 *  [8..9]  = CAN ID, big-endian 16-bit
 *  [10]    = DLC
 *  [11..11+dlc-1] = data bytes
 *  [20]    = channel index (0 or 1) - VERIFIED via usbmon capture of the
 *            vendor library's own ZCAN_Transmit() (main_classic.cpp in
 *            zcan_orig/, built against libcontrolcanfd.so): CH0 sends have
 *            0x00 here, CH1 sends have 0x01, identical otherwise. This was
 *            previously assumed to be byte[2] (wrong guess, never actually
 *            verified) - with byte[20] always 0x00 in our own TX, every
 *            frame was silently routed to channel 0 regardless of which
 *            netdev/endpoint it was sent from, which is why CH1 TX never
 *            reached the physical bus while CH0 TX always worked.
 *  [21]    = transmit_type (0x00 = normal with auto-retry)
 */
#define TX_CAN_PAYLOAD_LEN	26
#define TX_CAN_EFF_OFFSET	4
#define TX_CAN_RTR_OFFSET	5
#define TX_CAN_ID32_OFFSET	6	/* full 29-bit ID, BE, [6..9] - [8..9] alias TX_CAN_ID_OFFSET */
#define TX_CAN_ID_OFFSET	8
#define TX_CAN_DLC_OFFSET	10
#define TX_CAN_DATA_OFFSET	11
#define TX_CAN_CH_OFFSET	20
#define TX_CAN_TXTYPE_OFFSET	21

/*
 * TX frame layout (CANFD, payload = 86 bytes, BEEF-wrapped), reconstructed
 * byte-exact from GVar::generate_fd_send_frame() in gvar.o and confirmed
 * against a live usbmon capture (zcan_dump.pcapng) of ZCAN_TransmitFD():
 *  [0]     = 0x55  magic
 *  [1]     = 0xF2  CANFD marker
 *  [2..3]  = 0x00  reserved
 *  [4]     = EFF flag (0 = standard, 1 = extended)
 *  [5]     = RTR flag (0 = data, 1 = remote)
 *  [6..9]  = CAN ID, big-endian 32-bit, masked to 29 bits
 *  [10]    = len - actual byte count 0..64 (canfd_frame.len, NOT a DLC code)
 *  [11]    = flags - raw canfd_frame.flags (CANFD_BRS/CANFD_ESI)
 *  [12]    = 0x01  fixed (always 1, unconditional in the vendor packer)
 *  [13]    = channel index (0 or 1) - NOTE: different offset than classic!
 *  [14..14+len-1] = data
 *  [81]    = transmit_type (0x00 = normal, auto-retry)
 * All other bytes are 0x00 padding.
 */
#define TX_CANFD_PAYLOAD_LEN	86
#define TX_FD_EFF_OFFSET	4
#define TX_FD_RTR_OFFSET	5
#define TX_FD_ID_OFFSET		6	/* 4 bytes, BE */
#define TX_FD_LEN_OFFSET	10
#define TX_FD_FLAGS_OFFSET	11
#define TX_FD_FIXED_OFFSET	12
#define TX_FD_CH_OFFSET		13
#define TX_FD_DATA_OFFSET	14
#define TX_FD_TXTYPE_OFFSET	81

/* RX frame layout (raw, 21 bytes, no BEEF wrapper):
 *  [0..3]  = arbitration word, little-endian 32-bit (see below)
 *  [4..5]  = 0x00 0x00
 *  [6]     = lower nibble = DLC
 *  [7]     = 0xFF (fixed)
 *  [8..8+dlc-1] = CAN data
 *  [9+dlc..20]  = padding
 */
#define RX_FRAME_SIZE		21
#define RX_DLC_OFFSET		6
#define RX_DATA_OFFSET		8

/*
 * RX arbitration word at [0..3], little-endian 32-bit. This is the raw CAN
 * arbitration field as the controller latched it, not a packed CAN ID:
 *
 *   bits  0..28 = identifier
 *   bit      30 = IDE (1 = extended/29-bit frame, 0 = standard/11-bit)
 *
 * Because a 29-bit extended identifier is defined by ISO 11898-1 as an
 * 11-bit *base* ID followed by an 18-bit extension, the 11-bit ID of a
 * standard frame lands at bits 18..28 - NOT at bits 0..10. That is why the
 * standard-frame decode needs a >> 18, and why bytes [0..1] (previously
 * documented here as "flags / partial timestamp") are in fact the low 18
 * bits of an extended identifier.
 *
 * Worked example, standard ID 0x111, from the capture in PROTOCOL.md:
 *   [0..3] = 00 00 44 04 → 0x04440000 → >> 18 = 0x111 ✓
 * which is exactly what the previous ([3]<<8 | [2]) >> 2 formula computed,
 * so standard-frame decoding is unchanged by this.
 */
#define RX_ID_IDE_FLAG		BIT(30)	/* extended (29-bit) frame */
#define RX_ID_SFF_SHIFT		18	/* base ID sits at bits 18..28 */

/*
 * RX frame layout (raw, 76 bytes, no BEEF wrapper), reconstructed from a
 * live usbmon capture (zcan_dump.pcapng) of ZCAN_ReceiveFD() with both
 * channels bridged - 5 round trips each direction, IDs 0..9:
 *  [0..3]  = arbitration word, little-endian 32-bit (same as classic, see
 *            the RX_ID_IDE_FLAG comment above)
 *  [4..5]  = 0x00 0x00
 *  [6]     = lower nibble = CAN FD DLC CODE (0..15, use can_fd_dlc2len()),
 *            upper nibble = 0x3 in every captured sample (vs. 0x0 for
 *            classic) - used as the RX demux discriminator, see the
 *            "KNOWN LIMITATION" note in the file header.
 *  [7]     = 0xFF (fixed, same as classic)
 *  [8..8+len-1] = CAN data (len from the DLC code, up to 64)
 *  [72..75]     = running ~100us hardware timestamp counter, little-endian
 *                 (not consumed by this driver)
 * Always a fixed 76-byte record regardless of actual len (mirrors the
 * classic 21-byte record and the fixed-size 86-byte TX payload).
 */
#define RX_FD_FRAME_SIZE	76

/* Driver limits */
#define ZCAN_MAX_PKG_SIZE	512
#define ZCAN_RX_BUF_SIZE	1024
#define ZCAN_MAX_CHANNELS	2
#define ZCAN_NUM_RX_URBS	2	/* one per RX endpoint */

/* Magic bytes in init/baud commands */
#define MAGIC_INIT		0x55
#define MAGIC_BAUD		0x7E

/* Fault poll / auto-recovery interval, see zcan_status_poll() */
#define ZCAN_STATUS_POLL_MS	1000

/* -------------------------------------------------------------------------
 * Data structures
 * -------------------------------------------------------------------------
 */
struct zcan_priv;

struct zcan_channel {
	struct can_priv		 can;		/* must be first for can_priv cast */
	struct zcan_priv	*priv;
	struct net_device	*netdev;
	int			 channel_idx;
};

struct zcan_priv {
	struct usb_device	*udev;
	struct net_device	*netdevs[ZCAN_MAX_CHANNELS];
	int			 num_channels;

	/* Persistent RX URBs - one per data endpoint */
	struct urb		*rx_urbs[ZCAN_NUM_RX_URBS];
	u8			*rx_bufs[ZCAN_NUM_RX_URBS];

	/* Per-channel async TX URBs */
	struct urb		*tx_urbs[ZCAN_MAX_CHANNELS];
	u8			*tx_bufs[ZCAN_MAX_CHANNELS];
	atomic_t		 tx_active[ZCAN_MAX_CHANNELS];

	/*
	 * Whether INIT_CAN/SET_BAUD/START_CAN has actually been sent to each
	 * channel's hardware. Guards against re-initializing/re-starting a
	 * channel that is already running as the "sibling" of the channel
	 * currently being opened - see zcan_netdev_open(). Protected by
	 * cmd_lock.
	 */
	bool			 ch_started[ZCAN_MAX_CHANNELS];

	/*
	 * Whether channel i's last CMD_GET_STATUS poll read that channel's
	 * fault byte (data[i*ZCAN_STATUS_CHANNEL_BLOCK_SIZE + FAULT_OFFSET])
	 * as ZCAN_STATUS_FAULT_VALUE. Drives both tx_errors vs
	 * tx_packets accounting in zcan_netdev_xmit() and automatic
	 * recovery in zcan_status_poll() - see the "Fault detection /
	 * recovery" note in the file header.
	 */
	bool			 ch_fault[ZCAN_MAX_CHANNELS];

	/* Command serialization (probe/open/close use blocking bulk_msg) */
	struct mutex		 cmd_lock;
	u8			 cmd_buf[ZCAN_MAX_PKG_SIZE];
	u8			 resp_buf[ZCAN_MAX_PKG_SIZE];

	/* Periodic CMD_GET_STATUS poll for fault detection/recovery, see
	 * zcan_status_poll(). Self-reschedules only while >=1 channel is up. */
	struct delayed_work	 status_work;
};

/* -------------------------------------------------------------------------
 * Protocol helpers
 * -------------------------------------------------------------------------
 */

/*
 * Calculate packet checksum.
 * Formula reverse-engineered from gen_package() in gvar.o (libcontrolcanfd.a):
 *   sum = datalen + 2*cmd + (pkgall<<8) + (pkgcur<<8)
 *       + sum_of_16bit_BE_words(data[])
 *       + PKG_MAGIC (0xBEAD)
 */
static u16 zcan_calc_checksum(const u8 *buf)
{
	u16 datalen = ((u16)buf[2] << 8) | buf[3];
	u16 cmd     = ((u16)buf[6] << 8) | buf[7];
	u8  pkgall  = buf[4];
	u8  pkgcur  = buf[5];
	const u8 *data = buf + 8;
	u32 sum;
	int i;

	sum = (u32)datalen + 2u * (u32)cmd
	    + ((u32)pkgall << 8) + ((u32)pkgcur << 8);

	for (i = 0; i + 1 < (int)datalen; i += 2)
		sum += ((u16)data[i] << 8) | data[i + 1];

	sum += PKG_MAGIC;
	return (u16)(sum & 0xFFFF);
}

/*
 * Build a BEEF/DEAD framed command packet into buf.
 * Returns total packet length.
 */
static int zcan_build_pkt(u8 *buf, u16 cmd, const u8 *data, u16 datalen)
{
	u16 check;
	int total;

	buf[0] = PKG_HEAD_B0;
	buf[1] = PKG_HEAD_B1;
	buf[2] = (datalen >> 8) & 0xff;
	buf[3] =  datalen       & 0xff;
	buf[4] = 0x01;  /* pkgall */
	buf[5] = 0x01;  /* pkgcur */
	buf[6] = (cmd >> 8) & 0xff;
	buf[7] =  cmd       & 0xff;

	if (data && datalen)
		memcpy(buf + 8, data, datalen);

	total = 8 + datalen;
	check = zcan_calc_checksum(buf);

	buf[total]     = (check >> 8) & 0xff;
	buf[total + 1] =  check       & 0xff;
	buf[total + 2] = PKG_TAIL_B0;
	buf[total + 3] = PKG_TAIL_B1;

	return total + 4;
}

/*
 * Send a command on EP1 OUT and optionally wait for a BEEF response on EP1 IN.
 *
 * The device continuously sends 2-byte polling packets on EP1 IN (every ~16ms).
 * These must be discarded when waiting for a real command response, which is
 * identified by starting with 0xBE 0xEF.
 *
 * Pass resp=NULL to skip reading the response (for commands after netdev_open
 * where EP1 IN is no longer exclusively used for command responses).
 */
static int zcan_cmd(struct zcan_priv *priv, u16 cmd,
		    const u8 *data, u16 datalen,
		    u8 *resp, int *resp_len)
{
	int pkt_len, actual, ret, i;

	pkt_len = zcan_build_pkt(priv->cmd_buf, cmd, data, datalen);

	ret = usb_bulk_msg(priv->udev,
			   usb_sndbulkpipe(priv->udev, EP_CMD_OUT),
			   priv->cmd_buf, pkt_len, &actual, 3000);
	if (ret) {
		dev_err(&priv->udev->dev, "cmd 0x%04x send failed: %d\n",
			cmd, ret);
		return ret;
	}

	if (!resp)
		return 0;

	/* Discard 2-byte polling packets, wait for real BEEF response */
	for (i = 0; i < 20; i++) {
		ret = usb_bulk_msg(priv->udev,
				   usb_rcvbulkpipe(priv->udev, EP_CMD_IN),
				   priv->resp_buf, ZCAN_MAX_PKG_SIZE,
				   &actual, 3000);
		if (ret) {
			dev_err(&priv->udev->dev,
				"cmd 0x%04x recv failed: %d\n", cmd, ret);
			return ret;
		}
		if (actual >= 2 &&
		    priv->resp_buf[0] == PKG_HEAD_B0 &&
		    priv->resp_buf[1] == PKG_HEAD_B1)
			break;
	}

	if (resp_len)
		*resp_len = actual;
	if (actual > 0)
		memcpy(resp, priv->resp_buf, actual);

	return 0;
}

/* -------------------------------------------------------------------------
 * AES-128 ECB (used for device authentication)
 * -------------------------------------------------------------------------
 */

/*
 * Encrypt 16 bytes with AES-128 ECB using the kernel crypto API.
 */
static int zcan_aes128_ecb_encrypt(const u8 key[16], const u8 *in, u8 *out)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg_in, sg_out;
	u8 *ibuf, *obuf;
	int ret;

	tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_skcipher_setkey(tfm, key, 16);
	if (ret)
		goto free_tfm;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) { ret = -ENOMEM; goto free_tfm; }

	ibuf = kmemdup(in, 16, GFP_KERNEL);
	obuf = kmalloc(16, GFP_KERNEL);
	if (!ibuf || !obuf) { ret = -ENOMEM; goto free_bufs; }

	sg_init_one(&sg_in,  ibuf, 16);
	sg_init_one(&sg_out, obuf, 16);
	skcipher_request_set_crypt(req, &sg_in, &sg_out, 16, NULL);

	ret = crypto_skcipher_encrypt(req);
	if (!ret)
		memcpy(out, obuf, 16);

free_bufs:
	kfree(ibuf);
	kfree(obuf);
	skcipher_request_free(req);
free_tfm:
	crypto_free_skcipher(tfm);
	return ret;
}

/* -------------------------------------------------------------------------
 * Device initialization sequence
 * -------------------------------------------------------------------------
 */

/*
 * CMD_OPEN_DEVICE (0x8001) - AES-128 challenge-response handshake.
 *
 * Protocol (reverse-engineered from libcontrolcanfd.a):
 *  1. Build 32-byte challenge with fixed magic bytes and timestamp
 *  2. Send challenge plaintext to device
 *  3. Device responds with AES_128_ECB(key, challenge[0:16])
 *                                    + AES_128_ECB(key, challenge[16:32])
 *  4. Driver verifies response matches expected encryption
 *
 * AES-128 key extracted from controlcanfd.o via GDB on statically linked binary.
 * Key: 61 62 0B 1A 65 74 63 70 3B 40 75 00 38 22 71 65
 *
 * Challenge format:
 *  [0..1]  = 0xDE 0xFF  (magic)
 *  [2..5]  = 0x00 (MUST be zero - device rejects non-zero)
 *  [6..7]  = 0x43 0x01  (fixed)
 *  [8..11] = 0xF2 0x89 0x82 0xEE  (fixed)
 *  [12..15]= timestamp (32-bit)
 *  [16..21]= 0xD0 0x1F 0x07 0x11 0x5F 0x68  (fixed)
 *  [22..25]= random value
 *  [26..31]= 0xC2 0x3E 0xC8 0x26 0x52 0x36  (fixed)
 */
static int zcan_open_device(struct zcan_priv *priv)
{
	static const u8 aes_key[16] = {
		0x61, 0x62, 0x0b, 0x1a, 0x65, 0x74, 0x63, 0x70,
		0x3b, 0x40, 0x75, 0x00, 0x38, 0x22, 0x71, 0x65
	};
	u8 challenge[32] = {};
	u8 expected[32]  = {};
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0;
	struct timespec64 ts;
	u32 rand_val;
	int ret;

	ktime_get_real_ts64(&ts);
	rand_val = (u32)(ts.tv_nsec / 1000);

	/* Fixed magic */
	challenge[0]  = 0xde;  challenge[1]  = 0xff;
	/* [2..5] must be zero */
	challenge[6]  = 0x43;  challenge[7]  = 0x01;
	challenge[8]  = 0xf2;  challenge[9]  = 0x89;
	challenge[10] = 0x82;  challenge[11] = 0xee;
	/* Timestamp */
	challenge[12] = (rand_val >> 24) & 0xff;
	challenge[13] = (rand_val >> 16) & 0xff;
	challenge[14] = (rand_val >>  8) & 0xff;
	challenge[15] =  rand_val        & 0xff;
	/* Fixed */
	challenge[16] = 0xd0;  challenge[17] = 0x1f;
	challenge[18] = 0x07;  challenge[19] = 0x11;
	challenge[20] = 0x5f;  challenge[21] = 0x68;
	/* Random */
	rand_val = (u32)(ts.tv_sec ^ ts.tv_nsec);
	challenge[22] = (rand_val >> 24) & 0xff;
	challenge[23] = (rand_val >> 16) & 0xff;
	challenge[24] = (rand_val >>  8) & 0xff;
	challenge[25] =  rand_val        & 0xff;
	/* Fixed tail */
	challenge[26] = 0xc2;  challenge[27] = 0x3e;
	challenge[28] = 0xc8;  challenge[29] = 0x26;
	challenge[30] = 0x52;  challenge[31] = 0x36;

	/* Pre-compute expected response */
	ret  = zcan_aes128_ecb_encrypt(aes_key, challenge,      expected);
	ret |= zcan_aes128_ecb_encrypt(aes_key, challenge + 16, expected + 16);
	if (ret)
		dev_warn(&priv->udev->dev, "AES setup failed: %d\n", ret);

	ret = zcan_cmd(priv, CMD_OPEN_DEVICE, challenge, sizeof(challenge),
		       resp, &resp_len);
	if (ret)
		return 0; /* non-fatal, continue */

	if (resp_len >= 8 + 32 &&
	    resp[0] == PKG_HEAD_B0 && resp[1] == PKG_HEAD_B1 &&
	    memcmp(resp + 8, expected, 32) == 0)
		dev_info(&priv->udev->dev, "device handshake OK\n");
	else
		dev_warn(&priv->udev->dev,
			 "handshake: unexpected response len=%d\n", resp_len);

	return 0;
}

/*
 * CMD_GET_INFO (0x8005) - Read device firmware/hardware version and serial.
 */
static int zcan_get_info(struct zcan_priv *priv)
{
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0, ret;

	ret = zcan_cmd(priv, CMD_GET_INFO, NULL, 0, resp, &resp_len);
	if (ret)
		return ret;

	if (resp_len >= 14)
		dev_info(&priv->udev->dev,
			 "fw=0x%02x%02x hw=0x%02x%02x serial=%.20s\n",
			 resp[8], resp[9], resp[10], resp[11],
			 resp_len > 22 ? (char *)&resp[22] : "?");
	return 0;
}

/* -------------------------------------------------------------------------
 * Baud rate table
 * -------------------------------------------------------------------------
 * Values reverse-engineered from USB captures of ZCAN_SetAbitBaud + InitCAN.
 * dbit_timing: used in INIT_CAN payload bytes [18..21]
 * baud_code:   used in SET_BAUD payload bytes [2..3]
 */
static const struct {
	u32 bitrate;
	u32 dbit_timing;
	u16 baud_code;
} zcan_baud_table[] = {
	{ 1000000, 0x00022e0b, 0x007f },
	{  500000, 0x00025e17, 0x0fff },
	{  250000, 0x0014be2f, 0x1fff },
	{  125000, 0x0114be2f, 0x3fff },
};

static u32 zcan_dbit_timing(u32 bitrate)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(zcan_baud_table); i++)
		if (zcan_baud_table[i].bitrate == bitrate)
			return zcan_baud_table[i].dbit_timing;
	return 0x00025e17; /* default 500k */
}

static u16 zcan_baud_code(u32 bitrate)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(zcan_baud_table); i++)
		if (zcan_baud_table[i].bitrate == bitrate)
			return zcan_baud_table[i].baud_code;
	return 0x0fff; /* default 500k */
}

/*
 * CMD_INIT_CAN (0x8002) - Configure CAN channel timing and mode.
 *
 * Payload format (32 bytes), verified from USB captures:
 *  [0]     = 0x55  magic
 *  [1]     = 0x02  fixed
 *  [2]     = channel index (0 or 1)
 *  [3]     = 0x01  type = CANFD mode (required even for classic CAN)
 *  [4..5]  = 0x00 0x00
 *  [6..9]  = acc_code = 0x00000001
 *  [10..13]= acc_mask = 0xFFFFFFFF
 *  [14..17]= abit_timing = 0x00000000
 *  [18..21]= dbit_timing (bitrate-dependent, see zcan_baud_table)
 *  [22..25]= 0x03 0x01 0x0A 0x02  (fixed, from capture)
 *  [26..29]= 0x00000000
 *  [30]    = 0x00  (termination disabled - hardware always has 120Ω)
 *  [31]    = 0x00
 */
static int zcan_init_channel(struct zcan_priv *priv, int ch)
{
	struct zcan_channel *zch = netdev_priv(priv->netdevs[ch]);
	u32 bitrate = zch->can.bittiming.bitrate ?: 500000;
	u32 dbit    = zcan_dbit_timing(bitrate);
	u8 data[32] = {
		0x55, 0x02,
		(u8)ch, 0x01,		/* channel, type (must be 0x01) */
		0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,	/* acc_code */
		0xff, 0xff, 0xff, 0xff,	/* acc_mask */
		0x00, 0x00, 0x00, 0x00,	/* abit_timing */
		0x00, 0x00, 0x00, 0x00,	/* dbit_timing (filled below) */
		0x03, 0x01, 0x0a, 0x02,	/* fixed (from capture) */
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00		/* termination off */
	};
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0;

	int ret;

	data[18] = (dbit >> 24) & 0xff;
	data[19] = (dbit >> 16) & 0xff;
	data[20] = (dbit >>  8) & 0xff;
	data[21] =  dbit        & 0xff;

	ret = zcan_cmd(priv, CMD_INIT_CAN, data, sizeof(data),
			resp, &resp_len);
	dev_info(&priv->udev->dev, "INIT_CAN ch%d ret=%d resp(%d)=%*ph\n",
		 ch, ret, resp_len, resp_len, resp);
	return ret;
}

/*
 * CMD_SET_BAUD (0x800B, 4-byte variant) - Set channel bitrate.
 */
static int zcan_set_baud(struct zcan_priv *priv, int ch, u32 bitrate)
{
	u16 code = zcan_baud_code(bitrate);
	u8 data[4] = {
		MAGIC_BAUD, (u8)ch,
		(code >> 8) & 0xff, code & 0xff
	};
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0;
	int ret;

	ret = zcan_cmd(priv, CMD_SET_BAUD, data, sizeof(data),
			resp, &resp_len);
	dev_info(&priv->udev->dev, "SET_BAUD ch%d ret=%d resp(%d)=%*ph\n",
		 ch, ret, resp_len, resp_len, resp);
	return ret;
}

/*
 * CMD_START_CAN (0x8003) - Start CAN channel (enable bus).
 */
static int zcan_start_channel(struct zcan_priv *priv, int ch)
{
	u8 data[4] = { 0x55, 0x80, 0x03, (u8)ch };
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0;
	int ret;

	ret = zcan_cmd(priv, CMD_START_CAN, data, sizeof(data),
			resp, &resp_len);
	dev_info(&priv->udev->dev, "START_CAN ch%d ret=%d resp(%d)=%*ph\n",
		 ch, ret, resp_len, resp_len, resp);
	return ret;
}

/*
 * CMD_RESET_CAN (0x8008) - Stop / reset a CAN channel.
 *
 * Must be sent before a running channel's INIT_CAN/SET_BAUD/START_CAN
 * can be safely resent - the firmware does not accept reconfiguration
 * of an already-started channel.
 */
static int zcan_reset_channel(struct zcan_priv *priv, int ch)
{
	u8 data[4] = { 0x55, 0x80, 0x08, (u8)ch };
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0;

	return zcan_cmd(priv, CMD_RESET_CAN, data, sizeof(data),
			resp, &resp_len);
}

/*
 * CMD_GET_STATUS (0x800D) - see the #define above for how confirmed this is.
 *
 * Payload follows the same convention already verified for START_CAN/
 * RESET_CAN: [0]=0x55 magic, [1..2]=cmd big-endian, [3]=channel index.
 * The device does understand this command and returns a well-formed
 * BEEF-framed response; only data[ZCAN_STATUS_FAULT_OFFSET] has a
 * confirmed meaning so far (see ZCAN_STATUS_FAULT_VALUE).
 *
 * NOTE: EP_CMD_OUT (0x01) is shared with CH0 TX frames (see
 * zcan_netdev_xmit()). Querying status while CH0 is actively transmitting
 * real CAN traffic can race with that traffic on the same endpoint - this
 * is polled periodically by zcan_status_poll() at a modest 1s interval to
 * keep that risk low, same tradeoff already accepted for the on-demand
 * status_ch0/status_ch1 sysfs attributes below.
 */
static int zcan_get_status(struct zcan_priv *priv, int ch,
			    u8 *resp, int *resp_len)
{
	u8 data[4] = { 0x55, 0x80, 0x0d, (u8)ch };

	return zcan_cmd(priv, CMD_GET_STATUS, data, sizeof(data),
			 resp, resp_len);
}

/*
 * Periodic CMD_GET_STATUS poll: detects the fault byte described at
 * ZCAN_STATUS_FAULT_OFFSET/ZCAN_STATUS_FAULT_VALUE and, while it is set,
 * repeatedly re-applies the exact same CMD_RESET_CAN + INIT_CAN +
 * SET_BAUD + START_CAN sequence that zcan_netdev_open()/zcan_set_bittiming()
 * already use - by hand, this is exactly the 'ip link set canX down; ...
 * up' sequence that was confirmed to actually clear the stuck state (see
 * the "Fault detection / recovery" note in the file header). This just
 * automates that instead of requiring the user to notice and do it
 * manually. If the physical bus is still broken (e.g. bridge still
 * disconnected), this recovery attempt will simply fail to help and the
 * next poll will find the fault byte set again and retry.
 *
 * ch_fault[] is also consulted by zcan_netdev_xmit() to (approximately)
 * account TX frames as tx_errors instead of tx_packets while a channel is
 * faulty - see the "Fault detection / recovery" note in the file header
 * for why this is a driver-side approximation, not a real error count.
 */
static void zcan_status_poll(struct work_struct *work)
{
	struct zcan_priv *priv = container_of(to_delayed_work(work),
					      struct zcan_priv, status_work);
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int i, resp_len, ret;
	bool any_up = false;
	int min_len;

	for (i = 0; i < priv->num_channels; i++) {
		if (priv->netdevs[i] && netif_running(priv->netdevs[i])) {
			any_up = true;
			break;
		}
	}
	if (!any_up)
		return;

	/*
	 * The response always contains BOTH channels' status back to back
	 * (see ZCAN_STATUS_CHANNEL_BLOCK_SIZE) regardless of which channel
	 * index is put in the request, so a single query per poll cycle is
	 * enough - query channel 0's slot arbitrarily.
	 */
	mutex_lock(&priv->cmd_lock);
	ret = zcan_get_status(priv, 0, resp, &resp_len);
	mutex_unlock(&priv->cmd_lock);

	min_len = 8 + priv->num_channels * ZCAN_STATUS_CHANNEL_BLOCK_SIZE;
	if (ret || resp_len < min_len)
		goto reschedule;

	for (i = 0; i < priv->num_channels; i++) {
		struct net_device *netdev = priv->netdevs[i];
		int fault_idx = 8 + i * ZCAN_STATUS_CHANNEL_BLOCK_SIZE + ZCAN_STATUS_FAULT_OFFSET;
		bool faulty;

		if (!netdev || !netif_running(netdev))
			continue;

		faulty = resp[fault_idx] == ZCAN_STATUS_FAULT_VALUE;
		priv->ch_fault[i] = faulty;

		if (faulty) {
			struct zcan_channel *ch = netdev_priv(netdev);
			u32 bitrate = ch->can.bittiming.bitrate ?: 500000;

			netdev_warn_once(netdev,
					 "fault detected (CMD_GET_STATUS), attempting recovery - see zcan_usb.c header\n");
			mutex_lock(&priv->cmd_lock);
			zcan_reset_channel(priv, i);
			priv->ch_started[i] = false;
			ret = zcan_init_channel(priv, i);
			if (!ret)
				ret = zcan_set_baud(priv, i, bitrate);
			if (!ret)
				ret = zcan_start_channel(priv, i);
			if (!ret)
				priv->ch_started[i] = true;
			mutex_unlock(&priv->cmd_lock);
		}
	}

reschedule:
	schedule_delayed_work(&priv->status_work,
			      msecs_to_jiffies(ZCAN_STATUS_POLL_MS));
}

/* -------------------------------------------------------------------------
 * Diagnostics / sysfs
 * -------------------------------------------------------------------------
 * Read-only attributes that trigger a live CMD_GET_STATUS query on demand,
 * so the raw response can be inspected (dmesg / sysfs) - see
 * ZCAN_STATUS_FAULT_OFFSET for the one confirmed field.
 */
static ssize_t zcan_status_show(struct device *dev, int ch, char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct zcan_priv *priv = usb_get_intfdata(intf);
	u8 resp[ZCAN_MAX_PKG_SIZE];
	int resp_len = 0, ret, i, n = 0;

	if (!priv)
		return -ENODEV;

	mutex_lock(&priv->cmd_lock);
	ret = zcan_get_status(priv, ch, resp, &resp_len);
	mutex_unlock(&priv->cmd_lock);

	if (ret)
		return scnprintf(buf, PAGE_SIZE, "cmd failed: %d\n", ret);

	n = scnprintf(buf, PAGE_SIZE, "len=%d data=", resp_len);
	for (i = 0; i < resp_len && n < PAGE_SIZE - 3; i++)
		n += scnprintf(buf + n, PAGE_SIZE - n, "%02x ", resp[i]);
	n += scnprintf(buf + n, PAGE_SIZE - n, "\n");
	return n;
}

static ssize_t status_ch0_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return zcan_status_show(dev, 0, buf);
}

static ssize_t status_ch1_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	return zcan_status_show(dev, 1, buf);
}

static DEVICE_ATTR_RO(status_ch0);
static DEVICE_ATTR_RO(status_ch1);

/* -------------------------------------------------------------------------
 * RX path
 * -------------------------------------------------------------------------
 */

/*
 * Decode the SocketCAN identifier (including CAN_EFF_FLAG) from the 4-byte
 * arbitration word at the head of an RX record. Shared by the classic and
 * CAN FD RX paths - both records carry the identical field, see the
 * RX_ID_IDE_FLAG comment above for the layout and how it was derived.
 *
 * The bytes are assembled by hand rather than with get_unaligned_le32() so
 * that this builds unmodified across the whole supported kernel range (the
 * header moved from <asm/unaligned.h> to <linux/unaligned.h> in 6.12).
 */
static canid_t zcan_rx_decode_id(const u8 *buf)
{
	u32 raw = (u32)buf[0] | ((u32)buf[1] << 8) |
		  ((u32)buf[2] << 16) | ((u32)buf[3] << 24);

	if (raw & RX_ID_IDE_FLAG)
		return (raw & CAN_EFF_MASK) | CAN_EFF_FLAG;

	return (raw >> RX_ID_SFF_SHIFT) & CAN_SFF_MASK;
}

/*
 * Parse a received CAN frame from a 21-byte raw RX packet.
 *
 * RX frame format (verified from live USB captures, fw=0x0200 hw=0x0212):
 *  [0..3]  = arbitration word, little-endian (see RX_ID_IDE_FLAG above)
 *  [4..5]  = 0x00 0x00
 *  [6]     = lower nibble = DLC  (NOT upper nibble)
 *  [7]     = 0xFF (fixed marker)
 *  [8..8+dlc-1] = CAN data bytes
 *
 * Endpoint routing:
 *  EP2 IN (0x82) → frames received by CH0
 *  EP3 IN (0x83) → frames received by CH1
 */
static void zcan_rx_frame(struct zcan_channel *ch, const u8 *buf, int len)
{
	struct net_device *netdev = ch->netdev;
	struct can_frame *cf;
	struct sk_buff *skb;
	u8 dlc;

	if (len < 9)
		return;

	dlc = buf[RX_DLC_OFFSET] & 0x0f;

	if (dlc > 8)
		dlc = 8;

	skb = alloc_can_skb(netdev, &cf);
	if (!skb)
		return;

	cf->can_id  = zcan_rx_decode_id(buf);
	cf->can_dlc = dlc;
	if (len >= RX_DATA_OFFSET + (int)dlc)
		memcpy(cf->data, buf + RX_DATA_OFFSET, dlc);

	netdev->stats.rx_packets++;
	netdev->stats.rx_bytes += dlc;
	netif_rx(skb);
}

/*
 * Parse a received CAN FD frame from a 76-byte raw RX packet.
 * See the RX_FD_FRAME_SIZE comment above for the format.
 */
static void zcan_rx_canfd_frame(struct zcan_channel *ch, const u8 *buf, int len)
{
	struct net_device *netdev = ch->netdev;
	struct canfd_frame *cf;
	struct sk_buff *skb;
	u8 dlc_code, dlen;

	if (len < RX_DATA_OFFSET + 1)
		return;

	dlc_code = buf[RX_DLC_OFFSET] & 0x0f;
	dlen = can_fd_dlc2len(dlc_code);
	if (dlen > CANFD_MAX_DLEN)
		dlen = CANFD_MAX_DLEN;

	skb = alloc_canfd_skb(netdev, &cf);
	if (!skb)
		return;

	cf->can_id = zcan_rx_decode_id(buf);
	cf->len    = dlen;
	if (len >= RX_DATA_OFFSET + (int)dlen)
		memcpy(cf->data, buf + RX_DATA_OFFSET, dlen);

	netdev->stats.rx_packets++;
	netdev->stats.rx_bytes += dlen;
	netif_rx(skb);
}

static void zcan_rx_complete(struct urb *urb)
{
	struct zcan_priv *priv = urb->context;
	u8 *buf = urb->transfer_buffer;
	int len = urb->actual_length;
	int ret, ch_idx, offset;

	switch (urb->status) {
	case 0:
		break;
	case -ENOENT:
	case -EPIPE:
	case -EPROTO:
	case -ESHUTDOWN:
		return;
	default:
		goto resubmit;
	}

	/* Determine channel from endpoint:
	 * EP2 (pipe endpoint 2) → CH0, EP3 → CH1 */
	ch_idx = (usb_pipeendpoint(urb->pipe) == 2) ? 0 : 1;

	/*
	 * Parse RX frames (21 bytes for classic CAN, 76 for CAN FD - may
	 * have multiple per URB). Record type is told apart by the upper
	 * nibble of byte[6]: 0x0 = classic, non-zero = CAN FD carrying the
	 * DLC code there instead of a plain DLC (see RX_FD_FRAME_SIZE
	 * comment above for the caveat on untested RTR/error frames).
	 */
	offset = 0;
	while (offset + 9 <= len) {
		u8 *frame = buf + offset;
		bool is_fd;
		int frame_len;

		/* Skip empty/null frames (idle polling packets) */
		if (frame[2] == 0 && frame[3] == 0 && frame[6] == 0)
			break;

		is_fd = (frame[RX_DLC_OFFSET] & 0xf0) != 0;
		frame_len = is_fd ? RX_FD_FRAME_SIZE : RX_FRAME_SIZE;

		if (offset + frame_len > len)
			break;

		if (ch_idx < priv->num_channels && priv->netdevs[ch_idx]) {
			struct zcan_channel *rch =
				netdev_priv(priv->netdevs[ch_idx]);
			if (is_fd)
				zcan_rx_canfd_frame(rch, frame, frame_len);
			else
				zcan_rx_frame(rch, frame, frame_len);
		}
		offset += frame_len;
	}

resubmit:
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		dev_err(&priv->udev->dev,
			"rx urb resubmit ep%d failed: %d\n",
			usb_pipeendpoint(urb->pipe), ret);
}

/* -------------------------------------------------------------------------
 * TX path
 * -------------------------------------------------------------------------
 */

static void zcan_tx_complete(struct urb *urb)
{
	struct net_device *netdev = urb->context;
	struct zcan_channel *ch = netdev_priv(netdev);
	struct zcan_priv *priv = ch->priv;
	unsigned int dlen;

	if (urb->status) {
		netdev->stats.tx_errors++;
		can_free_echo_skb(netdev, 0, NULL);
	} else {
		/*
		 * Loop the frame back to SocketCAN and account it. The echo
		 * is unconditional on a successful URB: ch_fault is a coarse,
		 * polled approximation (see the file header) and must not be
		 * allowed to swallow an application's view of its own sends.
		 * Only the counter it lands in reflects the fault state.
		 */
		dlen = can_get_echo_skb(netdev, 0, NULL);

		if (priv->ch_fault[ch->channel_idx]) {
			netdev->stats.tx_errors++;
		} else {
			netdev->stats.tx_packets++;
			netdev->stats.tx_bytes += dlen;
		}
	}

	atomic_set(&priv->tx_active[ch->channel_idx], 0);
	netif_wake_queue(netdev);
}

/*
 * Build a classic CAN TX payload (26 bytes). See TX_CAN_* offsets above.
 *
 * Channel routing: CH0 -> EP1 OUT, CH1 -> EP2 OUT (endpoint), AND the
 * channel index at byte[20] (both matter, not just the endpoint).
 *
 * ROOT CAUSE (found and fixed): byte[20] was always 0x00 (i.e. "channel 0")
 * regardless of which channel actually transmitted - it used to be treated
 * as unused padding. VERIFIED via usbmon capture of the vendor library's
 * own ZCAN_Transmit() (see zcan_orig/main_classic.cpp, a modified copy of
 * the reference demo using the classic, non-FD transmit call): CH0 sends
 * have 0x00 at byte[20], CH1 sends have 0x01, byte-identical otherwise.
 * With byte[20] always 0, every TX from this driver was silently routed to
 * CH0's physical transceiver regardless of source endpoint - the USB
 * transfer itself always succeeded (status 0), so nothing ever surfaced
 * this as an error. This is why CH0->CH1 sends were visible on the bus but
 * CH1->CH0 sends never were, confirmed by the vendor demo's CH1 LEDs/bus
 * traffic only appearing once the classic ZCAN_Transmit() call (which sets
 * this byte correctly) was used instead of this driver's old code.
 *
 * EFF encoding (added when CAN FD support was implemented): disassembly of
 * GVar::generate_send_frame() showed the classic packer also writes an EFF
 * flag at [4], an RTR flag at [5], and the FULL 29-bit ID across [6..9] (of
 * which [8..9] is the same field this driver already used for the 16-bit
 * SFF case) - extended (29-bit) classic CAN IDs were previously silently
 * truncated to their low 16 bits since [6..7] was never written.
 */
static void zcan_build_can_tx(u8 *tx_data, u8 ch_idx, struct can_frame *cf)
{
	u32 can_id = cf->can_id & CAN_ERR_MASK;
	bool eff = cf->can_id & CAN_EFF_FLAG;
	bool rtr = cf->can_id & CAN_RTR_FLAG;
	int dlc = cf->can_dlc;

	memset(tx_data, 0, TX_CAN_PAYLOAD_LEN);
	tx_data[0] = MAGIC_INIT;	/* 0x55 */
	tx_data[1] = TX_TYPE_CAN;	/* 0xF1 */
	tx_data[TX_CAN_EFF_OFFSET] = eff ? 1 : 0;
	tx_data[TX_CAN_RTR_OFFSET] = rtr ? 1 : 0;
	tx_data[TX_CAN_ID32_OFFSET]     = (can_id >> 24) & 0xff;
	tx_data[TX_CAN_ID32_OFFSET + 1] = (can_id >> 16) & 0xff;
	tx_data[TX_CAN_ID_OFFSET]       = (can_id >>  8) & 0xff;
	tx_data[TX_CAN_ID_OFFSET + 1]   =  can_id        & 0xff;
	tx_data[TX_CAN_DLC_OFFSET] = dlc;
	/*
	 * A remote frame carries no data - it requests dlc bytes from the
	 * remote node. struct can_frame.data is undefined for an RTR skb, so
	 * copying it here would put uninitialised kernel memory into the USB
	 * payload; leave the (already zeroed) data field alone instead.
	 */
	if (!rtr)
		memcpy(tx_data + TX_CAN_DATA_OFFSET, cf->data, dlc);
	tx_data[TX_CAN_CH_OFFSET] = ch_idx;
	tx_data[TX_CAN_TXTYPE_OFFSET] = 0x00;	/* normal, auto-retry */
}

/*
 * Build a CAN FD TX payload (86 bytes). See TX_CANFD_PAYLOAD_LEN comment
 * above for the format and how it was reconstructed.
 */
static void zcan_build_canfd_tx(u8 *tx_data, u8 ch_idx, struct canfd_frame *cf)
{
	u32 can_id = cf->can_id & CAN_ERR_MASK;
	bool eff = cf->can_id & CAN_EFF_FLAG;
	bool rtr = cf->can_id & CAN_RTR_FLAG;
	int len = cf->len;

	memset(tx_data, 0, TX_CANFD_PAYLOAD_LEN);
	tx_data[0] = MAGIC_INIT;	/* 0x55 */
	tx_data[1] = TX_TYPE_CANFD;	/* 0xF2 */
	tx_data[TX_FD_EFF_OFFSET] = eff ? 1 : 0;
	tx_data[TX_FD_RTR_OFFSET] = rtr ? 1 : 0;
	tx_data[TX_FD_ID_OFFSET]     = (can_id >> 24) & 0xff;
	tx_data[TX_FD_ID_OFFSET + 1] = (can_id >> 16) & 0xff;
	tx_data[TX_FD_ID_OFFSET + 2] = (can_id >>  8) & 0xff;
	tx_data[TX_FD_ID_OFFSET + 3] =  can_id        & 0xff;
	tx_data[TX_FD_LEN_OFFSET]   = len;
	tx_data[TX_FD_FLAGS_OFFSET] = cf->flags;
	tx_data[TX_FD_FIXED_OFFSET] = 0x01;	/* fixed, unconditional in vendor packer */
	tx_data[TX_FD_CH_OFFSET]    = ch_idx;
	memcpy(tx_data + TX_FD_DATA_OFFSET, cf->data, len);
	tx_data[TX_FD_TXTYPE_OFFSET] = 0x00;	/* normal, auto-retry */
}

static netdev_tx_t zcan_netdev_xmit(struct sk_buff *skb,
				    struct net_device *netdev)
{
	struct zcan_channel *ch = netdev_priv(netdev);
	struct zcan_priv *priv = ch->priv;
	int ch_idx = ch->channel_idx;
	u8 tx_data[TX_CANFD_PAYLOAD_LEN];
	bool is_fd = can_is_canfd_skb(skb);
	int pkt_len, payload_len;
	unsigned int ep_out;

	if (can_dev_dropped_skb(netdev, skb))
		return NETDEV_TX_OK;

	if (atomic_cmpxchg(&priv->tx_active[ch_idx], 0, 1) != 0) {
		netif_stop_queue(netdev);
		return NETDEV_TX_BUSY;
	}

	if (is_fd) {
		zcan_build_canfd_tx(tx_data, (u8)ch_idx,
				    (struct canfd_frame *)skb->data);
		payload_len = TX_CANFD_PAYLOAD_LEN;
	} else {
		zcan_build_can_tx(tx_data, (u8)ch_idx,
				  (struct can_frame *)skb->data);
		payload_len = TX_CAN_PAYLOAD_LEN;
	}

	ep_out  = (ch_idx == 0) ? EP_CMD_OUT : EP_CH1_TX;
	pkt_len = zcan_build_pkt(priv->tx_bufs[ch_idx], CMD_TRANSMIT,
				 tx_data, payload_len);

	usb_fill_bulk_urb(priv->tx_urbs[ch_idx], priv->udev,
			  usb_sndbulkpipe(priv->udev, ep_out),
			  priv->tx_bufs[ch_idx], pkt_len,
			  zcan_tx_complete, netdev);

	/*
	 * Hand the skb to the CAN echo buffer instead of freeing it. This
	 * netdev sets IFF_ECHO, which tells the CAN core the driver performs
	 * the local echo itself - so without this, frames sent from this host
	 * are never looped back and candump/python-can on the sending
	 * interface see nothing at all of their own traffic.
	 *
	 * This must happen before usb_submit_urb(): the completion handler
	 * can run the moment the URB is submitted, and it is what delivers
	 * (or, on failure, drops) the echo skb. The echo buffer holds a
	 * single entry, which matches the one-TX-in-flight tx_active guard
	 * above, so slot 0 is always free here.
	 */
	can_put_echo_skb(skb, netdev, 0, 0);

	if (usb_submit_urb(priv->tx_urbs[ch_idx], GFP_ATOMIC)) {
		can_free_echo_skb(netdev, 0, NULL);
		netdev->stats.tx_errors++;
		atomic_set(&priv->tx_active[ch_idx], 0);
		return NETDEV_TX_OK;
	}

	/*
	 * tx_packets/tx_bytes are accounted in zcan_tx_complete() now that
	 * the skb outlives this function. Note that a completed URB still
	 * says nothing about whether the frame reached the physical bus -
	 * see the "Fault detection / recovery" note in the file header.
	 */
	return NETDEV_TX_OK;
}

/* -------------------------------------------------------------------------
 * netdev callbacks
 * -------------------------------------------------------------------------
 */

/*
 * Open a CAN channel.
 *
 * Initialization sequence matches the vendor library exactly
 * (verified from USB captures):
 *   INIT CH0 → INIT CH1 → BAUD CH0 → START CH0 → BAUD CH1 → START CH1
 *
 * The sibling channel is initialized here as well, matching the vendor
 * library. Note that this is NOT what makes RX work - that requires the
 * second INIT_CAN + START_CAN on the channel being opened (see the
 * comment on it below). Measured on a 1 Mbit bus: opening can0 alone
 * with the sibling setup present but only one INIT yields 33 usable
 * frames in 8 s, while a second INIT with no sibling commands at all
 * yields 878.
 *
 * The sibling setup must only happen once: if the sibling is already running
 * (opened independently, e.g. "ip link set can0 up" followed later by
 * "ip link set can1 up"), re-sending INIT/BAUD/START to it here would
 * silently reset its bitrate to the hardcoded default and restart an
 * already-active channel without a prior CMD_RESET_CAN, which the
 * firmware does not handle cleanly - this was observed to leave the
 * sibling channel stuck receiving nothing.
 *
 * BUGFIX: the exact same hazard applies to THIS channel, not just the
 * sibling - if it was already started as the *other* netdev's sibling
 * (e.g. "ifconfig can0 up" already started ch1 as its sibling, and
 * "ifconfig can1 up" runs afterwards), re-running INIT/BAUD/START here
 * unconditionally re-triggers the same "no prior CMD_RESET_CAN" failure
 * mode on THIS channel. This was the actual cause of CH1 TX silently
 * not reaching the physical bus while CH0 TX worked fine: whichever
 * channel's netdev was brought up *second* got double-initialized.
 */
static int zcan_netdev_open(struct net_device *netdev)
{
	struct zcan_channel *ch = netdev_priv(netdev);
	struct zcan_priv *priv = ch->priv;
	int other = 1 - ch->channel_idx;
	u32 baud = ch->can.bittiming.bitrate ?: 500000;
	int ret;

	ret = open_candev(netdev);
	if (ret)
		return ret;

	mutex_lock(&priv->cmd_lock);

	if (priv->ch_started[ch->channel_idx])
		goto already_started;

	/* INIT this channel, and the sibling too if it isn't already
	 * running - but never re-init an already-started sibling. */
	ret = zcan_init_channel(priv, ch->channel_idx);
	if (ret) {
		dev_err(&priv->udev->dev, "INIT_CAN ch%d failed: %d\n",
			ch->channel_idx, ret);
		goto out;
	}
	if (!priv->ch_started[other])
		zcan_init_channel(priv, other); /* non-fatal */

	/* BAUD + START this channel */
	ret = zcan_set_baud(priv, ch->channel_idx, baud);
	if (ret) {
		dev_err(&priv->udev->dev, "SET_BAUD ch%d failed: %d\n",
			ch->channel_idx, ret);
		goto out;
	}
	ret = zcan_start_channel(priv, ch->channel_idx);
	if (ret) {
		dev_err(&priv->udev->dev, "START_CAN ch%d failed: %d\n",
			ch->channel_idx, ret);
		goto out;
	}

	/* The device only starts filling in the RX arbitration word and DLC
	 * once a channel has been INIT_CAN'd a second time while already
	 * running. After a single INIT_CAN/START_CAN the frame payloads do
	 * arrive on the bulk IN endpoint, but every record carries id == 0
	 * and dlc == 0, so the null-record check in zcan_rx_complete()
	 * discards them and the interface looks dead. Repeating INIT_CAN +
	 * START_CAN here, with no CMD_RESET_CAN in between, is what makes RX
	 * work; a CMD_RESET_CAN puts the channel back into the state that
	 * needs two INITs again.
	 */
	zcan_init_channel(priv, ch->channel_idx);
	ret = zcan_start_channel(priv, ch->channel_idx);
	if (ret) {
		dev_err(&priv->udev->dev, "START_CAN ch%d (2nd) failed: %d\n",
			ch->channel_idx, ret);
		goto out;
	}
	priv->ch_started[ch->channel_idx] = true;

	/* BAUD + START the sibling channel, only if it isn't already
	 * running. Use its own configured bitrate (set independently via
	 * its netdev, even if not yet opened) instead of hardcoding
	 * 500000, so we don't clobber a different intended rate. */
	if (!priv->ch_started[other]) {
		struct zcan_channel *och = netdev_priv(priv->netdevs[other]);
		u32 obaud = och->can.bittiming.bitrate ?: 500000;

		zcan_set_baud(priv, other, obaud);
		zcan_start_channel(priv, other);
		priv->ch_started[other] = true;
	}

already_started:
	ch->can.state = CAN_STATE_ERROR_ACTIVE;
	priv->ch_fault[ch->channel_idx] = false;
	netif_start_queue(netdev);
	dev_info(&priv->udev->dev, "channel %d opened at %u bps\n",
		 ch->channel_idx, baud);

out:
	mutex_unlock(&priv->cmd_lock);
	if (ret) {
		close_candev(netdev);
	} else {
		/* idempotent: no-op if already scheduled */
		schedule_delayed_work(&priv->status_work,
				      msecs_to_jiffies(ZCAN_STATUS_POLL_MS));
	}
	return ret;
}

static int zcan_netdev_stop(struct net_device *netdev)
{
	struct zcan_channel *ch = netdev_priv(netdev);
	struct zcan_priv *priv = ch->priv;

	netif_stop_queue(netdev);
	ch->can.state = CAN_STATE_STOPPED;

	mutex_lock(&priv->cmd_lock);
	zcan_reset_channel(priv, ch->channel_idx);
	priv->ch_started[ch->channel_idx] = false;
	mutex_unlock(&priv->cmd_lock);

	close_candev(netdev);
	return 0;
}

/*
 * do_set_bittiming callback.
 * Skip if the channel is not yet open (called by 'ip link set bitrate'
 * before 'ip link set up'). The correct baud rate is applied during open.
 *
 * If the channel is already running, the firmware will not accept a new
 * SET_BAUD/START_CAN without a preceding CMD_RESET_CAN, so reset and
 * fully reinitialize it here rather than just poking SET_BAUD.
 */
static int zcan_set_bittiming(struct net_device *netdev)
{
	struct zcan_channel *ch = netdev_priv(netdev);
	struct zcan_priv *priv = ch->priv;
	int ret = 0;

	if (ch->can.state == CAN_STATE_STOPPED)
		return 0;

	mutex_lock(&priv->cmd_lock);
	zcan_reset_channel(priv, ch->channel_idx);
	priv->ch_started[ch->channel_idx] = false;

	zcan_init_channel(priv, ch->channel_idx);
	ret = zcan_set_baud(priv, ch->channel_idx,
			    ch->can.bittiming.bitrate);
	if (!ret)
		ret = zcan_start_channel(priv, ch->channel_idx);
	if (!ret)
		priv->ch_started[ch->channel_idx] = true;
	mutex_unlock(&priv->cmd_lock);
	return ret;
}

/*
 * do_set_data_bittiming callback (CAN FD data phase).
 *
 * KNOWN LIMITATION: the live capture used to reverse-engineer CAN FD
 * support only exercised the data phase at the SAME bitrate as arbitration
 * (see the "CAN FD support" note in the file header) - no register
 * encoding for a genuinely faster data phase (BRS) has been verified.
 * Reject anything else here rather than silently ignoring it, so a wrong
 * dbitrate fails loudly ('ip link set ... fd on') instead of quietly
 * transmitting at the wrong rate.
 */
static int zcan_set_data_bittiming(struct net_device *netdev)
{
	struct zcan_channel *ch = netdev_priv(netdev);

	if (ch->can.fd.data_bittiming.bitrate != ch->can.bittiming.bitrate) {
		netdev_err(netdev,
			   "dbitrate must equal bitrate (%u != %u) - bit-rate-switched CAN FD is unverified on this device, see zcan_usb.c header\n",
			   ch->can.fd.data_bittiming.bitrate,
			   ch->can.bittiming.bitrate);
		return -EINVAL;
	}
	return 0;
}

static void zcan_set_rx_mode(struct net_device *netdev)
{
	/* Hardware filtering not needed; accept all in default config */
}

static const struct net_device_ops zcan_netdev_ops = {
	.ndo_open	 = zcan_netdev_open,
	.ndo_stop	 = zcan_netdev_stop,
	.ndo_start_xmit	 = zcan_netdev_xmit,
	.ndo_set_rx_mode = zcan_set_rx_mode,
};

/* -------------------------------------------------------------------------
 * Bittiming constants
 * -------------------------------------------------------------------------
 * Used by the SocketCAN framework to validate user-supplied bitrates.
 */
static const struct can_bittiming_const zcan_bittiming_const = {
	.name      = DRIVER_NAME,
	.tseg1_min = 1,
	.tseg1_max = 16,
	.tseg2_min = 1,
	.tseg2_max = 8,
	.sjw_max   = 4,
	.brp_min   = 1,
	.brp_max   = 64,
	.brp_inc   = 1,
};

/* -------------------------------------------------------------------------
 * USB probe / disconnect
 * -------------------------------------------------------------------------
 */

static int zcan_probe(struct usb_interface *intf,
		      const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(intf);
	struct zcan_priv *priv;
	int i, ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->udev = udev;
	priv->num_channels = ZCAN_MAX_CHANNELS;
	mutex_init(&priv->cmd_lock);
	INIT_DELAYED_WORK(&priv->status_work, zcan_status_poll);
	usb_set_intfdata(intf, priv);

	/*
	 * Device needs ~1.5s after USB enumeration before it accepts
	 * the AES handshake. Without this delay CMD_OPEN_DEVICE times out.
	 */
	msleep(1500);

	ret = zcan_open_device(priv);
	if (ret)
		dev_warn(&udev->dev, "handshake failed: %d\n", ret);

	ret = zcan_get_info(priv);
	if (ret)
		dev_warn(&udev->dev, "get_info failed: %d\n", ret);

	/* Register a netdev (canX) for each channel */
	for (i = 0; i < priv->num_channels; i++) {
		struct net_device *netdev;
		struct zcan_channel *ch;

		netdev = alloc_candev(sizeof(*ch), 1);
		if (!netdev) {
			ret = -ENOMEM;
			goto err_free;
		}

		ch = netdev_priv(netdev);
		ch->priv        = priv;
		ch->netdev      = netdev;
		ch->channel_idx = i;

		netdev->netdev_ops = &zcan_netdev_ops;
		netdev->flags     |= IFF_ECHO;

		ch->can.clock.freq         = 80000000;
		ch->can.bittiming_const    = &zcan_bittiming_const;
		ch->can.do_set_bittiming   = zcan_set_bittiming;
		ch->can.ctrlmode_supported = CAN_CTRLMODE_LOOPBACK | CAN_CTRLMODE_FD;

		/* CAN FD data phase - see zcan_set_data_bittiming() for the
		 * same-rate-only limitation. */
		ch->can.fd.data_bittiming_const  = &zcan_bittiming_const;
		ch->can.fd.do_set_data_bittiming = zcan_set_data_bittiming;

		SET_NETDEV_DEV(netdev, &intf->dev);
		/* can_set_default_mtu() isn't exported on all kernels; set
		 * it directly. Actual FD gating happens via ctrlmode
		 * (can_dev_dropped_skb()), not MTU alone. */
		netdev->mtu = CANFD_MTU;

		ret = register_candev(netdev);
		if (ret) {
			free_candev(netdev);
			goto err_free;
		}

		priv->netdevs[i] = netdev;
		dev_info(&udev->dev, "registered %s (channel %d)\n",
			 netdev->name, i);
	}

	/* Setup RX URBs - one per data endpoint */
	{
		unsigned int rx_eps[ZCAN_NUM_RX_URBS] = {
			EP_CH0_RX,	/* EP2 (0x82): received by CH0 */
			EP_CH1_RX,	/* EP3 (0x83): received by CH1 */
		};

		for (i = 0; i < ZCAN_NUM_RX_URBS; i++) {
			struct urb *urb;
			u8 *buf;

			urb = usb_alloc_urb(0, GFP_KERNEL);
			if (!urb)
				break;

			buf = kmalloc(ZCAN_RX_BUF_SIZE, GFP_KERNEL);
			if (!buf) {
				usb_free_urb(urb);
				break;
			}

			usb_fill_bulk_urb(urb, udev,
					  usb_rcvbulkpipe(udev, rx_eps[i]),
					  buf, ZCAN_RX_BUF_SIZE,
					  zcan_rx_complete, priv);
			priv->rx_urbs[i] = urb;
			priv->rx_bufs[i] = buf;
			usb_submit_urb(urb, GFP_KERNEL);
		}
	}

	/* Setup TX URBs - one per channel */
	for (i = 0; i < ZCAN_MAX_CHANNELS; i++) {
		struct urb *urb;
		u8 *buf;

		urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!urb)
			break;

		buf = kmalloc(ZCAN_MAX_PKG_SIZE, GFP_KERNEL);
		if (!buf) {
			usb_free_urb(urb);
			break;
		}

		atomic_set(&priv->tx_active[i], 0);
		priv->tx_urbs[i] = urb;
		priv->tx_bufs[i] = buf;
	}

	ret = device_create_file(&intf->dev, &dev_attr_status_ch0);
	if (ret)
		dev_warn(&udev->dev, "sysfs status_ch0 failed: %d\n", ret);
	ret = device_create_file(&intf->dev, &dev_attr_status_ch1);
	if (ret)
		dev_warn(&udev->dev, "sysfs status_ch1 failed: %d\n", ret);

	dev_info(&udev->dev,
		 "ZCAN USB CANFD connected (%d channels) [v%s]\n",
		 priv->num_channels, DRIVER_VERSION);
	return 0;

err_free:
	for (i = 0; i < ZCAN_MAX_CHANNELS; i++) {
		if (priv->netdevs[i]) {
			unregister_candev(priv->netdevs[i]);
			free_candev(priv->netdevs[i]);
		}
	}
	kfree(priv);
	return ret;
}

static void zcan_disconnect(struct usb_interface *intf)
{
	struct zcan_priv *priv = usb_get_intfdata(intf);
	int i;

	if (!priv)
		return;

	cancel_delayed_work_sync(&priv->status_work);

	device_remove_file(&intf->dev, &dev_attr_status_ch1);
	device_remove_file(&intf->dev, &dev_attr_status_ch0);

	for (i = 0; i < ZCAN_NUM_RX_URBS; i++) {
		if (priv->rx_urbs[i]) {
			usb_kill_urb(priv->rx_urbs[i]);
			usb_free_urb(priv->rx_urbs[i]);
			kfree(priv->rx_bufs[i]);
		}
	}

	for (i = 0; i < ZCAN_MAX_CHANNELS; i++) {
		if (priv->tx_urbs[i]) {
			usb_kill_urb(priv->tx_urbs[i]);
			usb_free_urb(priv->tx_urbs[i]);
			kfree(priv->tx_bufs[i]);
		}
	}

	for (i = 0; i < ZCAN_MAX_CHANNELS; i++) {
		if (priv->netdevs[i]) {
			unregister_candev(priv->netdevs[i]);
			free_candev(priv->netdevs[i]);
		}
	}

	kfree(priv);
	dev_info(&intf->dev, "ZCAN USB CANFD disconnected\n");
}

static const struct usb_device_id zcan_id_table[] = {
	{ USB_DEVICE(ZCAN_VENDOR_ID, ZCAN_PRODUCT_ID) },
	{ }
};
MODULE_DEVICE_TABLE(usb, zcan_id_table);

static struct usb_driver zcan_driver = {
	.name       = DRIVER_NAME,
	.probe      = zcan_probe,
	.disconnect = zcan_disconnect,
	.id_table   = zcan_id_table,
};

module_usb_driver(zcan_driver);

MODULE_AUTHOR("Reverse-engineered from USB captures and libcontrolcanfd.a");
MODULE_DESCRIPTION("Linux SocketCAN driver for NXP USB CANFD DEBUG (04d8:0053)");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRIVER_VERSION);
