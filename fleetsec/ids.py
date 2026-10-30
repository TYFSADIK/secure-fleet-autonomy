"""Rule-based IDS over decoded telemetry/commands. Alerts go to a human (and decision-black-box).

Events are dicts: {t, sysid, compid, msg, sig_status, ...fields}
"""
from collections import defaultdict, deque
import math


class FleetIDS:
    def __init__(self, gcs_sysids=(255,), vehicles=(1, 2, 3), max_speed_ms=30.0, cmd_rate_per_min=30):
        self.gcs, self.vehicles = set(gcs_sysids), set(vehicles)
        self.max_speed = max_speed_ms
        self.cmd_rate = cmd_rate_per_min
        self.last_pos = {}
        self.cmds = defaultdict(deque)
        self.alerts = []

    def _alert(self, ev, rule, sev="high", **kw):
        a = {"t": ev["t"], "sysid": ev.get("sysid"), "rule": rule, "severity": sev, **kw}
        self.alerts.append(a)
        return a

    def feed(self, ev):
        out = []
        s = ev.get("sysid")
        if ev.get("sig_status") in ("bad-signature", "replay", "unsigned", "stale-new-stream"):
            out.append(self._alert(ev, f"mavlink-{ev['sig_status']}"))
        if s not in self.gcs | self.vehicles:
            out.append(self._alert(ev, "unknown-sysid"))
        m = ev.get("msg")
        if m in ("COMMAND_LONG", "COMMAND_INT", "SET_MODE", "PARAM_SET", "MISSION_ITEM_INT") and s not in self.gcs:
            out.append(self._alert(ev, "command-from-non-gcs", cmd=m))
        if m in ("COMMAND_LONG", "PARAM_SET"):
            q = self.cmds[s]
            q.append(ev["t"])
            while q and ev["t"] - q[0] > 60:
                q.popleft()
            if len(q) > self.cmd_rate:
                out.append(self._alert(ev, "command-flood", "medium", per_min=len(q)))
        if m == "PARAM_SET" and str(ev.get("param", "")).startswith(("SYSID", "BRD_SAFETY", "ARMING_CHECK", "FENCE_ENABLE", "SIGNING")):
            out.append(self._alert(ev, "safety-param-change", param=ev["param"]))
        if m == "GLOBAL_POSITION_INT":
            p = (ev["t"], ev["lat"], ev["lon"])
            if s in self.last_pos:
                t0, la, lo = self.last_pos[s]
                dt = p[0] - t0
                d = 6371000 * math.hypot(math.radians(p[1] - la), math.radians(p[2] - lo) * math.cos(math.radians(la)))
                if dt > 0 and d / dt > self.max_speed:
                    out.append(self._alert(ev, "gnss-jump-possible-spoof", implied_ms=round(d / dt, 1)))
            self.last_pos[s] = p
        return out
