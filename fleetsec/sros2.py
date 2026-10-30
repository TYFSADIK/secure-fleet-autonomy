"""Generate SROS2 least-privilege permission policies from a node -> topics map.

    python -m fleetsec.sros2 > policy.xml
    ros2 security create_keystore keystore
    ros2 security create_permission keystore /rover1/nav policy.xml
Each enclave may publish/subscribe ONLY what it needs; everything else is denied by default.
"""
from xml.sax.saxutils import escape

FLEET = {
    "/rover1/nav": {"pub": ["cmd_vel", "odometry/filtered"], "sub": ["scan", "imu/data", "wheel/odom", "goal_pose"]},
    "/rover1/driver": {"pub": ["wheel/odom", "imu/data"], "sub": ["cmd_vel"]},
    "/rover1/telemetry": {"pub": ["telemetry"], "sub": ["odometry/filtered", "diagnostics"]},
}


def policy(fleet=FLEET, domain=0):
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<policy version="0.2.0" xmlns:xi="http://www.w3.org/2001/XInclude">', "  <enclaves>"]
    for enclave, p in fleet.items():
        out.append(f'    <enclave path="{escape(enclave)}">\n      <profiles>')
        out.append(f'        <profile ns="/" node="{escape(enclave.rsplit("/", 1)[-1])}">')
        out.append(f'          <topics publish="ALLOW" subscribe="DENY">')
        out += [f"            <topic>{escape(t)}</topic>" for t in p["pub"]]
        out.append("          </topics>")
        out.append(f'          <topics publish="DENY" subscribe="ALLOW">')
        out += [f"            <topic>{escape(t)}</topic>" for t in p["sub"]]
        out.append("          </topics>\n        </profile>\n      </profiles>\n    </enclave>")
    out += ["  </enclaves>", "</policy>"]
    return "\n".join(out)


if __name__ == "__main__":
    print(policy())
