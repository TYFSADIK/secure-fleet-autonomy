"""MAVLink 2 frame parsing and message signing / verification (from the protocol spec).

Frame:  0xFD len incompat compat seq sysid compid msgid(3) payload(len) crc(2) [signature(13)]
Signed if incompat_flags & 0x01. Signature block: link_id(1) timestamp(6, LE, 10 us units since
2015-01-01 UTC) signature(6) where
    signature = SHA256(secret_key(32) + header(10) + payload + crc(2) + link_id + timestamp)[:6]
Replay protection: for each (sysid, compid, link_id) stream, the timestamp must strictly increase,
and a new stream must be within 60 s of local time.
"""
from dataclasses import dataclass
import hashlib
import struct
import time

MAGIC_V2 = 0xFD
SIGNED = 0x01
EPOCH_2015 = 1420070400

# CRC_EXTRA per message id (subset; generate the full table from the XML with pymavlink if needed)
CRC_EXTRA = {0: 50, 1: 124, 24: 24, 30: 39, 33: 104, 74: 20, 76: 152, 77: 143, 11: 89, 23: 168, 253: 83}


def x25(data: bytes, crc=0xFFFF):
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def ts_now():
    return int((time.time() - EPOCH_2015) * 100_000)


@dataclass
class Frame:
    seq: int
    sysid: int
    compid: int
    msgid: int
    payload: bytes
    signed: bool
    link_id: int = 0
    timestamp: int = 0
    raw: bytes = b""

    @property
    def header(self):
        return self.raw[:10]


def build(sysid, compid, msgid, payload, seq=0, key=None, link_id=0, timestamp=None):
    incompat = SIGNED if key else 0
    hdr = struct.pack("<BBBBBBB", MAGIC_V2, len(payload), incompat, 0, seq, sysid, compid) + struct.pack("<I", msgid)[:3]
    crc = x25(hdr[1:] + payload + bytes([CRC_EXTRA.get(msgid, 0)]))
    body = hdr + payload + struct.pack("<H", crc)
    if key:
        timestamp = ts_now() if timestamp is None else timestamp
        tsb = struct.pack("<Q", timestamp)[:6]
        sig = hashlib.sha256(key + body + bytes([link_id]) + tsb).digest()[:6]
        body += bytes([link_id]) + tsb + sig
    return body


def parse(buf: bytes) -> Frame:
    if buf[0] != MAGIC_V2:
        raise ValueError("not MAVLink 2")
    ln, inc, _cmp, seq, sysid, compid = buf[1:7]
    msgid = int.from_bytes(buf[7:10], "little")
    payload = buf[10:10 + ln]
    crc = struct.unpack_from("<H", buf, 10 + ln)[0]
    if x25(buf[1:10] + payload + bytes([CRC_EXTRA.get(msgid, 0)])) != crc:
        raise ValueError("crc")
    f = Frame(seq, sysid, compid, msgid, payload, bool(inc & SIGNED), raw=buf)
    if f.signed:
        sb = buf[12 + ln:25 + ln]
        f.link_id = sb[0]
        f.timestamp = int.from_bytes(sb[1:7], "little")
    return f


class SignatureVerifier:
    def __init__(self, key: bytes, allow_unsigned_msgids=(), max_initial_skew_s=60):
        assert len(key) == 32
        self.key = key
        self.allow_unsigned = set(allow_unsigned_msgids)   # e.g. RADIO_STATUS from the modem
        self.streams = {}
        self.max_skew = max_initial_skew_s * 100_000

    def check(self, buf: bytes, now_ts=None) -> tuple[bool, str]:
        try:
            f = parse(buf)
        except ValueError as e:
            return False, f"malformed:{e}"
        if not f.signed:
            return (True, "unsigned-allowed") if f.msgid in self.allow_unsigned else (False, "unsigned")
        ln = len(f.payload)
        expect = hashlib.sha256(self.key + buf[:12 + ln] + buf[12 + ln:13 + ln] + buf[13 + ln:19 + ln]).digest()[:6]
        if expect != buf[19 + ln:25 + ln]:
            return False, "bad-signature"
        sk = (f.sysid, f.compid, f.link_id)
        now_ts = ts_now() if now_ts is None else now_ts
        last = self.streams.get(sk)
        if last is None and abs(f.timestamp - now_ts) > self.max_skew:
            return False, "stale-new-stream"
        if last is not None and f.timestamp <= last:
            return False, "replay"
        self.streams[sk] = f.timestamp
        return True, "ok"
