import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fleetsec import firmware, mavlink2
from fleetsec.ids import FleetIDS


class TestFleetSec(unittest.TestCase):
    def test_mavlink_signing(self):
        key = os.urandom(32)
        v = mavlink2.SignatureVerifier(key)
        f1 = mavlink2.build(255, 190, 76, bytes(33), key=key)
        self.assertEqual(v.check(f1), (True, "ok"))
        self.assertEqual(v.check(f1)[1], "replay")
        tampered = bytearray(mavlink2.build(255, 190, 76, bytes(33), key=key))
        tampered[12] ^= 1
        self.assertFalse(v.check(bytes(tampered))[0])
        old = mavlink2.build(255, 191, 0, bytes(9), key=key, timestamp=mavlink2.ts_now() - 3600 * 100_000)
        self.assertEqual(v.check(old)[1], "stale-new-stream")

    def test_signature_matches_spec_layout(self):
        key = bytes(range(32))
        f = mavlink2.build(1, 1, 0, bytes(9), key=key, link_id=2, timestamp=123456)
        p = mavlink2.parse(f)
        self.assertTrue(p.signed)
        self.assertEqual((p.link_id, p.timestamp), (2, 123456))
        self.assertEqual(len(f), 10 + 9 + 2 + 13)

    def test_byte_identical_to_pymavlink(self):
        try:
            os.environ["MAVLINK20"] = "1"
            from pymavlink.dialects.v20 import common as m2
        except ImportError:
            self.skipTest("pymavlink not installed")
        key = bytes(range(32))

        class Sink:
            buf = b""

            def write(self, b):
                self.buf += b
        sink = Sink()
        mav = m2.MAVLink(sink, srcSystem=255, srcComponent=190)
        mav.signing.secret_key, mav.signing.sign_outgoing = key, True
        mav.signing.link_id, mav.signing.timestamp = 3, 999999
        mav.heartbeat_send(6, 8, 0, 0, 4)
        ts = int.from_bytes(sink.buf[-12:-6], "little")
        ours = mavlink2.build(255, 190, 0, sink.buf[10:10 + sink.buf[1]], key=key, link_id=3, timestamp=ts)
        self.assertEqual(ours, sink.buf)

    def test_ids(self):
        ids = FleetIDS()
        self.assertTrue(ids.feed({"t": 0, "sysid": 2, "msg": "SET_MODE"}))
        self.assertFalse(ids.feed({"t": 0, "sysid": 255, "msg": "SET_MODE"}))

    def test_firmware(self):
        k = Ed25519PrivateKey.generate()
        blob = firmware.sign_image(b"abc", "Pi5", "1.2.3", k)
        self.assertEqual(firmware.verify_image(blob, k.public_key(), "Pi5", "1.0.0"), b"abc")
        for args, msg in [((Ed25519PrivateKey.generate().public_key(), "Pi5", "1.0.0"), "signature"),
                          ((k.public_key(), "Other", "1.0.0"), "board"),
                          ((k.public_key(), "Pi5", "2.0.0"), "downgrade")]:
            with self.assertRaisesRegex(ValueError, msg):
                firmware.verify_image(blob, *args)
        bad = blob[:-1] + b"X"
        with self.assertRaisesRegex(ValueError, "corrupt"):
            firmware.verify_image(bad, k.public_key(), "Pi5", "1.0.0")


if __name__ == "__main__":
    unittest.main()
