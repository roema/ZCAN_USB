# tools/

## pingpong_test.py

End-to-end test for the zcan_usb driver. It uses two SocketCAN interfaces
that are wired together on the same physical bus (e.g. can0 <-> can1 of the
same NXP USB CANFD DEBUG adapter, TX/RX crossed over) and bounces frames
between them:

1. `--ping-if` sends a frame (hop=0, counter=seq & 0xFF).
2. `--pong-if` receives it, checks the CRC, increments the counter, sets
   hop=1, and sends it back.
3. `--ping-if` receives the reply, checks CRC/seq/counter/hop, and records
   the round-trip time.

Every payload carries a CRC-16/CCITT-FALSE checksum, so bit errors,
corruption, or driver mix-ups are caught, not just packet loss. At the end
it prints a report: frames sent/received/lost, CRC/counter mismatches, send
errors, and RTT statistics (min/avg/max/stddev, throughput).

No third-party packages are required — only Python 3 and a Linux kernel
with SocketCAN (`CAN_RAW`) support.

### Setup

Bring both interfaces up first, e.g.:

```sh
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up
sudo ip link set can1 type can bitrate 500000
sudo ip link set can1 up
```

For CAN FD (needs zcan_usb >= 0.8.0):

```sh
sudo ip link set can0 type can bitrate 500000 dbitrate 500000 fd on
sudo ip link set can0 up
sudo ip link set can1 type can bitrate 500000 dbitrate 500000 fd on
sudo ip link set can1 up
```

### Usage

```sh
./pingpong_test.py --ping-if can0 --pong-if can1 -n 1000
./pingpong_test.py --ping-if can0 --pong-if can1 -n 1000 --fd --fd-len 64
```

### Options

| Option | Default | Description |
|---|---|---|
| `--ping-if` | `can0` | interface that sends the ping |
| `--pong-if` | `can1` | interface that replies with the pong |
| `-n`, `--count` | `100` | number of frames to send |
| `--id-ping` | `0x100` | CAN ID used for ping frames |
| `--id-pong` | `0x101` | CAN ID used for pong frames |
| `--extended` | off | use 29-bit extended CAN IDs |
| `--timeout` | `0.5` | per-frame reply timeout in seconds |
| `--interval` | `0` | delay between pings in seconds |
| `--fd` | off | use CAN FD frames instead of classic CAN |
| `--fd-len` | `32` | CAN FD payload length in bytes, 8..64 (only with `--fd`) |
| `-v`, `--verbose` | off | print every frame |

### Example: fault-injection / recovery test

To exercise the driver's bus-fault detection and automatic recovery
(added in v0.9.0), run a long test while physically disconnecting and
reconnecting the bridge between can0/can1 mid-run:

```sh
./pingpong_test.py --ping-if can1 --pong-if can0 -n 20000 --timeout 0.05
```

Frames lost while the bridge is disconnected show up as `LOST (timeout)`;
once the driver detects the fault and reconnects, traffic should resume
automatically without needing a manual `ip link down`/`up`. Cross-check
with `ip -details -statistics link show can1` to see `tx_errors` increment
while the fault is active.
