# Threat model: robot and drone fleet (Phase 0)

| Asset / flow | STRIDE | Threat | Control (this repo) | Test |
|---|---|---|---|---|
| GCS → vehicle MAVLink | Spoofing | Rogue GCS sends `COMMAND_LONG` (disarm, mode change) | MAVLink 2 signing, `SignatureVerifier`, IDS `command-from-non-gcs` | Inject an unsigned command, which must be rejected and alerted |
| GCS → vehicle MAVLink | Replay | Captured signed `SET_MODE` replayed later | Per-stream monotonic timestamp | Replay a captured frame and expect `replay` |
| Telemetry radio link | Information disclosure | Eavesdrop on position/video | WireGuard over IP radios. MAVLink signing gives integrity, **not** confidentiality | Capture on a second radio, which should show only ciphertext |
| Firmware update | Tampering | Malicious image flashed over the air | `firmware.verify_image` (Ed25519, board, anti-downgrade) + `secure-fleet-updates` | Flash a modified image and expect it to be refused |
| ROS 2 graph | Elevation of privilege | Compromised telemetry node publishes `cmd_vel` | SROS2 enclaves from `sros2.policy()` | The telemetry enclave's `cmd_vel` publish must be denied |
| GNSS | Spoofing | Position walked off by a spoofer | IDS `gnss-jump-possible-spoof`, cross-check vs LiDAR/VIO odometry | Inject a jump in SITL |
| Parameters | Tampering | `ARMING_CHECK=0`, `SIGNING` disabled | IDS `safety-param-change` | Change a param from the GCS and expect an alert |
| Operator actions | Repudiation | "I never sent that command" | Log every alert/ack to `decision-black-box` | `blackbox verify` |
| Command channel | DoS | Command flood / jamming | IDS `command-flood`. Failsafe RTL on link loss | Flood the link in SITL and confirm failsafe |

Rules of engagement for Phase 7: attack **only your own lab equipment**, on frequencies and powers you're licensed for, never someone else's aircraft or network.
