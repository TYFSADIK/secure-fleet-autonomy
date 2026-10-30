# Secure Fleet Autonomy (hardening guide)

Private research repo. A hardening guide for a robot and drone fleet: MAVLink 2 signing, signed Ed25519 firmware, SROS2 enclaves, WireGuard links, IDS alerts, and tamper-proof updates. **Defensive only. Test against your own lab equipment.**

Full write-up and phase plan: [`docs/project-page.md`](docs/project-page.md)

## What's here

| Path | Phase | Purpose |
|---|---|---|
| `threat-model/STRIDE.md` | 0 | Assets, threats, controls, and the test that proves each control |
| `fleetsec/mavlink2.py` | 1 | MAVLink 2 framing, X.25 CRC, **message signing and verification from the spec**, per-stream replay protection, stale-stream check |
| `fleetsec/firmware.py` | 3 | Signed firmware container: Ed25519, board lock, **anti-downgrade**, digest |
| `fleetsec/sros2.py` | 4 | Generates SROS2 least-privilege policy XML per enclave |
| `fleetsec/ids.py` | 5 | Rule IDS: signature failures, unknown sysid, commands from non-GCS, command flood, safety-param changes, GNSS jump (spoofing) |

## Quickstart

```bash
pip install -r requirements.txt
python demo.py && python -m unittest -v
```

## Next steps
- [ ] Phase 1: enable signing on ArduPilot (`SETUP_SIGNING` from MAVProxy: `signing setup <passphrase>`) and run `SignatureVerifier` on a MAVLink router tap. Check `CRC_EXTRA` against pymavlink for every message you use
- [ ] Phase 2: WireGuard between GCS and companion computers over the IP radios
- [ ] Phase 4: `ros2 security create_enclave` per node, `ROS_SECURITY_STRATEGY=Enforce`, and confirm that telemetry → `cmd_vel` is denied
- [ ] Phase 5: Zeek or Suricata on the GCS network, plus this IDS on the decoded MAVLink stream, with alerts sent to `decision-black-box`
- [ ] Phase 7: red-team your own SITL fleet (replay, unsigned injection, GNSS jump) and record detection time for each test
