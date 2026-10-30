"""Run: python demo.py  -> signed MAVLink accept/reject/replay, IDS alerts, firmware signing, SROS2 policy."""
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fleetsec import firmware, mavlink2
from fleetsec.ids import FleetIDS
from fleetsec.sros2 import policy

key = os.urandom(32)
v = mavlink2.SignatureVerifier(key, allow_unsigned_msgids=(109,))
hb = bytes(9)
good = mavlink2.build(255, 190, 0, hb, key=key)
print("signed heartbeat:", v.check(good))
print("same frame again:", v.check(good))
print("unsigned:", v.check(mavlink2.build(255, 190, 0, hb)))
print("wrong key:", v.check(mavlink2.build(255, 190, 0, hb, key=os.urandom(32))))

ids = FleetIDS()
for ev in [{"t": 0, "sysid": 7, "msg": "COMMAND_LONG", "sig_status": "unsigned"},
           {"t": 1, "sysid": 1, "msg": "GLOBAL_POSITION_INT", "lat": 45.0, "lon": -75.0},
           {"t": 2, "sysid": 1, "msg": "GLOBAL_POSITION_INT", "lat": 45.01, "lon": -75.0},
           {"t": 3, "sysid": 255, "msg": "PARAM_SET", "param": "ARMING_CHECK"}]:
    for a in ids.feed(ev):
        print("IDS:", a)

k = Ed25519PrivateKey.generate()
blob = firmware.sign_image(b"\x00" * 1024, "CubeOrange", "4.5.7", k)
print("firmware ok:", len(firmware.verify_image(blob, k.public_key(), "CubeOrange", "4.5.0")), "bytes")
print(policy().splitlines()[3])
