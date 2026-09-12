"""
Mobile game network packet simulator.

Spins up a local UDP "game server" on 127.0.0.1 and a "mobile client" that
talks to it the way a typical real-time mobile online game does:

  1. TCP-style login handshake over UDP (auth request -> session token)
  2. Matchmaking / room join
  3. Real-time gameplay loop:
       - client position/input updates ~20 Hz
       - server world snapshots ~10 Hz
       - periodic heartbeats
       - occasional action packets (shoot, use item, chat)
  4. Graceful disconnect

By default runs both sides on the loopback interface (127.0.0.1) so no
traffic leaves the machine. With --server / --client the two halves can
run on separate devices — e.g. server on a laptop, client on an iPhone
in a-Shell, sending real UDP packets over Wi-Fi.

The script prints a Wireshark-style trace of every packet: direction,
size, opcode, sequence number, and a hex preview of the payload.

Usage:
    # Both sides on this machine (loopback):
    python3 mobile_game_packet_sim.py                       # 15 s session
    python3 mobile_game_packet_sim.py --seconds 30
    python3 mobile_game_packet_sim.py --quiet

    # Real traffic between two devices on the same Wi-Fi:
    #   On the "server" machine (e.g. a laptop), listen on all interfaces:
    python3 mobile_game_packet_sim.py --server --host 0.0.0.0 --port 40000
    #   On the "client" (e.g. iPhone in a-Shell), point at the laptop's IP:
    python3 mobile_game_packet_sim.py --client --host 192.168.1.42 --port 40000
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------- Protocol definition ----------------------------------------------
#
# All packets share a small binary header (mimicking real mobile game
# protocols like those used by Unity's Mirror/Netcode, Photon, or bespoke
# UDP protocols in shipped titles):
#
#   magic     : uint16   (0xC0DE)
#   version   : uint8    (0x01)
#   opcode    : uint8
#   seq       : uint16   (monotonic per sender)
#   session   : uint32   (0 before login)
#   payload   : opcode-specific
#
# This keeps overhead low (~10 bytes) which matches what shipped mobile
# titles do to stay under typical MTU on cellular networks (~1200 bytes
# effective after IP + UDP + carrier tunneling overhead).

HEADER_FMT = ">HBBHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)
MAGIC = 0xC0DE
VERSION = 0x01

# Opcodes
OP_LOGIN_REQ = 0x01
OP_LOGIN_ACK = 0x02
OP_JOIN_REQ = 0x03
OP_JOIN_ACK = 0x04
OP_HEARTBEAT = 0x10
OP_HEARTBEAT_ACK = 0x11
OP_INPUT = 0x20        # client -> server: movement / look input
OP_SNAPSHOT = 0x21     # server -> client: world state delta
OP_ACTION = 0x22       # client -> server: shoot / cast / use item
OP_ACTION_RESULT = 0x23
OP_CHAT = 0x30
OP_DISCONNECT = 0xFF

OPCODE_NAMES = {
    OP_LOGIN_REQ: "LOGIN_REQ",
    OP_LOGIN_ACK: "LOGIN_ACK",
    OP_JOIN_REQ: "JOIN_REQ",
    OP_JOIN_ACK: "JOIN_ACK",
    OP_HEARTBEAT: "HEARTBEAT",
    OP_HEARTBEAT_ACK: "HEARTBEAT_ACK",
    OP_INPUT: "INPUT",
    OP_SNAPSHOT: "SNAPSHOT",
    OP_ACTION: "ACTION",
    OP_ACTION_RESULT: "ACTION_RESULT",
    OP_CHAT: "CHAT",
    OP_DISCONNECT: "DISCONNECT",
}


def pack(opcode: int, seq: int, session: int, payload: bytes = b"") -> bytes:
    return struct.pack(HEADER_FMT, MAGIC, VERSION, opcode, seq & 0xFFFF, session) + payload


def unpack(data: bytes) -> tuple[int, int, int, int, int, bytes]:
    magic, version, opcode, seq, session = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    return magic, version, opcode, seq, session, data[HEADER_LEN:]


# ---------- Packet trace logger ---------------------------------------------

@dataclass
class Trace:
    quiet: bool = False
    t0: float = field(default_factory=time.time)
    sent: int = 0
    recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0

    def log(self, direction: str, addr: tuple[str, int], data: bytes) -> None:
        if direction == "->":
            self.sent += 1
            self.bytes_sent += len(data)
        else:
            self.recv += 1
            self.bytes_recv += len(data)
        if self.quiet:
            return
        _, _, opcode, seq, session, payload = unpack(data)
        name = OPCODE_NAMES.get(opcode, f"0x{opcode:02X}")
        ms = (time.time() - self.t0) * 1000
        hex_preview = payload[:16].hex(" ")
        if len(payload) > 16:
            hex_preview += " ..."
        print(
            f"[{ms:8.1f} ms] {direction} {addr[0]}:{addr[1]:<5} "
            f"{name:<14} seq={seq:<5} sess=0x{session:08X} "
            f"len={len(data):<4} {hex_preview}"
        )


# ---------- Server -----------------------------------------------------------

class GameServer(threading.Thread):
    """A minimal UDP game server. One room, one client, tick-based snapshots."""

    def __init__(self, host: str, port: int, trace: Trace) -> None:
        super().__init__(daemon=True)
        self.addr = (host, port)
        self.trace = trace
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sock.settimeout(0.05)
        self.stop_flag = threading.Event()
        self.seq = 0
        # Simulated world state for the one player we know about.
        self.player_pos = [0.0, 0.0, 0.0]
        self.player_hp = 100
        self.client_addr: Optional[tuple[str, int]] = None
        self.session: int = 0
        self.last_snapshot = 0.0

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def _send(self, opcode: int, session: int, payload: bytes = b"") -> None:
        if self.client_addr is None:
            return
        pkt = pack(opcode, self._next_seq(), session, payload)
        self.sock.sendto(pkt, self.client_addr)
        self.trace.log("<-", self.client_addr, pkt)

    def run(self) -> None:
        while not self.stop_flag.is_set():
            # Drain pending client packets. Receiving side does not log
            # (the sending side already emitted a trace line for this packet).
            try:
                data, addr = self.sock.recvfrom(2048)
                self._handle(data, addr)
            except socket.timeout:
                pass
            # Server tick: send snapshot ~10 Hz once a client has joined.
            now = time.time()
            if self.session and now - self.last_snapshot >= 0.1:
                self._send_snapshot()
                self.last_snapshot = now
        self.sock.close()

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        magic, version, opcode, seq, session, payload = unpack(data)
        if magic != MAGIC or version != VERSION:
            return  # Silently drop malformed packets, as a real server would.

        if opcode == OP_LOGIN_REQ:
            self.client_addr = addr
            self.session = random.randint(1, 0xFFFFFFFF)
            # Payload: token (16 bytes) + server-assigned player id.
            token = random.randbytes(16)
            self._send(OP_LOGIN_ACK, self.session, token + struct.pack(">I", 4242))

        elif opcode == OP_JOIN_REQ and session == self.session:
            # Payload: room id (uint32), starting spawn (3 floats).
            self._send(
                OP_JOIN_ACK,
                self.session,
                struct.pack(">I3f", 1001, 0.0, 0.0, 0.0),
            )

        elif opcode == OP_HEARTBEAT and session == self.session:
            self._send(OP_HEARTBEAT_ACK, self.session, payload)

        elif opcode == OP_INPUT and session == self.session:
            # Payload: dx, dy, dz, yaw, pitch (5 floats) + input bitmask.
            if len(payload) >= 5 * 4 + 1:
                dx, dy, dz, _yaw, _pitch = struct.unpack(">5f", payload[:20])
                self.player_pos[0] += dx
                self.player_pos[1] += dy
                self.player_pos[2] += dz

        elif opcode == OP_ACTION and session == self.session:
            # Reply with a small acknowledgement: hit/miss + damage dealt.
            hit = random.random() > 0.3
            dmg = random.randint(5, 25) if hit else 0
            self._send(
                OP_ACTION_RESULT,
                self.session,
                struct.pack(">BH", 1 if hit else 0, dmg),
            )

        elif opcode == OP_CHAT and session == self.session:
            # Echo chat back to the client (in a real game: broadcast to room).
            self._send(OP_CHAT, self.session, payload)

        elif opcode == OP_DISCONNECT and session == self.session:
            self.session = 0
            self.client_addr = None

    def _send_snapshot(self) -> None:
        # Payload: server tick, player pos (3f), hp (uint16),
        # plus 2 fake other players (id, pos).
        payload = struct.pack(
            ">I3fH",
            int(time.time() * 20) & 0xFFFFFFFF,
            *self.player_pos,
            self.player_hp,
        )
        for pid in (7, 13):
            payload += struct.pack(
                ">I3f",
                pid,
                random.uniform(-50, 50),
                0.0,
                random.uniform(-50, 50),
            )
        self._send(OP_SNAPSHOT, self.session, payload)


# ---------- Client -----------------------------------------------------------

class MobileClient:
    """Simulated mobile client. Sends input at ~20 Hz plus periodic events."""

    def __init__(self, server_addr: tuple[str, int], trace: Trace) -> None:
        self.server_addr = server_addr
        self.trace = trace
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.05)
        self.seq = 0
        self.session: int = 0

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFF
        return self.seq

    def _send(self, opcode: int, payload: bytes = b"") -> None:
        pkt = pack(opcode, self._next_seq(), self.session, payload)
        self.sock.sendto(pkt, self.server_addr)
        self.trace.log("->", self.server_addr, pkt)

    def _drain(self, budget_s: float = 0.0) -> None:
        """Read any pending server packets for up to budget_s seconds."""
        deadline = time.time() + budget_s
        while True:
            self.sock.settimeout(max(0.0, deadline - time.time()) if budget_s else 0.0)
            try:
                data, _addr = self.sock.recvfrom(2048)
                # Receiving side does not log (the server logged its send).
                _, _, opcode, _, session, _payload = unpack(data)
                if opcode == OP_LOGIN_ACK:
                    self.session = session
            except (socket.timeout, BlockingIOError):
                return

    def connect(self) -> None:
        # 1. Login. Payload = device id (8 bytes) + auth token (32 bytes).
        device_id = b"mob-" + random.randbytes(4)
        auth_token = random.randbytes(32)
        self._send(OP_LOGIN_REQ, device_id + auth_token)
        # Wait briefly for LOGIN_ACK.
        deadline = time.time() + 1.0
        while self.session == 0 and time.time() < deadline:
            self._drain(0.05)
        if self.session == 0:
            raise RuntimeError("login timed out")

        # 2. Join a room. Payload = requested room (uint32).
        self._send(OP_JOIN_REQ, struct.pack(">I", 1001))
        self._drain(0.2)

    def play(self, seconds: float) -> None:
        """Main gameplay loop: 20 Hz input, periodic heartbeat & actions."""
        start = time.time()
        next_input = start
        next_heartbeat = start + 1.0
        next_action = start + random.uniform(1.5, 3.0)
        next_chat = start + random.uniform(5.0, 8.0)

        yaw = 0.0
        while time.time() - start < seconds:
            now = time.time()

            if now >= next_input:
                # 20 Hz: dx, dy, dz, yaw, pitch, input bitmask.
                dx = random.uniform(-0.2, 0.2)
                dz = random.uniform(-0.2, 0.2)
                yaw += random.uniform(-0.05, 0.05)
                bits = random.getrandbits(8)  # jump/crouch/sprint/etc.
                self._send(
                    OP_INPUT,
                    struct.pack(">5fB", dx, 0.0, dz, yaw, 0.0, bits),
                )
                next_input += 1 / 20

            if now >= next_heartbeat:
                # Heartbeat carries a client-side timestamp so the server
                # can echo it back for RTT measurement.
                self._send(OP_HEARTBEAT, struct.pack(">d", now))
                next_heartbeat += 1.0

            if now >= next_action:
                # ACTION: action id (uint16), target id (uint32).
                self._send(
                    OP_ACTION,
                    struct.pack(">HI", random.choice([1, 2, 7]), random.choice([7, 13])),
                )
                next_action += random.uniform(1.5, 4.0)

            if now >= next_chat:
                msg = random.choice([b"gg", b"nice shot", b"back me up", b"pushing B"])
                self._send(OP_CHAT, msg)
                next_chat += random.uniform(6.0, 12.0)

            self._drain(0.005)  # Read any snapshots the server pushed.

    def disconnect(self) -> None:
        self._send(OP_DISCONNECT)
        self._drain(0.1)
        self.sock.close()


# ---------- Main -------------------------------------------------------------

def _print_summary(trace: Trace) -> None:
    dur = max(time.time() - trace.t0, 1e-6)
    print()
    print(f"# Summary")
    print(f"#   duration        : {dur:.2f} s")
    print(f"#   packets sent    : {trace.sent:>5}  ({trace.bytes_sent} B, "
          f"{trace.bytes_sent / dur:.0f} B/s, {trace.sent / dur:.1f} pps)")
    print(f"#   packets received: {trace.recv:>5}  ({trace.bytes_recv} B, "
          f"{trace.bytes_recv / dur:.0f} B/s, {trace.recv / dur:.1f} pps)")


def _run_server_only(host: str, port: int, trace: Trace) -> None:
    server = GameServer(host, port, trace)
    server.start()
    print(f"# Mobile game packet simulation - SERVER MODE")
    print(f"# listening on {host}:{port} (UDP)")
    print(f"# header = magic(2) ver(1) op(1) seq(2) session(4) = {HEADER_LEN} bytes")
    print(f"# Ctrl+C to stop")
    print()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop_flag.set()
        server.join(timeout=1.0)
        _print_summary(trace)


def _run_client_only(host: str, port: int, seconds: float, trace: Trace) -> None:
    print(f"# Mobile game packet simulation - CLIENT MODE")
    print(f"# target  = {host}:{port} (UDP)")
    print(f"# session = {seconds:.1f}s")
    print(f"# header  = magic(2) ver(1) op(1) seq(2) session(4) = {HEADER_LEN} bytes")
    print()
    client = MobileClient((host, port), trace)
    try:
        client.connect()
        client.play(seconds)
    finally:
        client.disconnect()
        _print_summary(trace)


def _run_both(host: str, port: int, seconds: float, trace: Trace) -> None:
    # If port=0, grab a free one on this host first.
    if port == 0:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((host, 0))
        port = s.getsockname()[1]
        s.close()

    server = GameServer(host, port, trace)
    server.start()
    time.sleep(0.05)

    print(f"# Mobile game packet simulation - BOTH SIDES (loopback)")
    print(f"# server  = {host}:{port} (UDP)")
    print(f"# session = {seconds:.1f}s")
    print(f"# header  = magic(2) ver(1) op(1) seq(2) session(4) = {HEADER_LEN} bytes")
    print()

    client = MobileClient((host, port), trace)
    try:
        client.connect()
        client.play(seconds)
    finally:
        client.disconnect()
        server.stop_flag.set()
        server.join(timeout=1.0)
        _print_summary(trace)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--server", action="store_true",
                      help="run only the game server (listen for clients)")
    mode.add_argument("--client", action="store_true",
                      help="run only the mobile client (connect to a server)")
    mode.add_argument("--both", action="store_true",
                      help="run both sides on this machine (default)")
    ap.add_argument("--host", default=None,
                    help="server bind address (--server), or server IP to "
                         "connect to (--client). Default: 0.0.0.0 for server, "
                         "127.0.0.1 for client/both.")
    ap.add_argument("--port", type=int, default=0,
                    help="UDP port (0 = pick a free one, only valid for --both)")
    ap.add_argument("--seconds", type=float, default=15.0,
                    help="client session length (ignored for --server)")
    ap.add_argument("--quiet", action="store_true", help="hide per-packet trace")
    args = ap.parse_args()

    trace = Trace(quiet=args.quiet)

    if args.server:
        host = args.host or "0.0.0.0"
        port = args.port or 40000
        _run_server_only(host, port, trace)
    elif args.client:
        host = args.host or "127.0.0.1"
        port = args.port or 40000
        _run_client_only(host, port, args.seconds, trace)
    else:
        host = args.host or "127.0.0.1"
        _run_both(host, args.port, args.seconds, trace)


if __name__ == "__main__":
    main()
