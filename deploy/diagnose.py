#!/usr/bin/env python3
"""Read-only, one-shot diagnostics for BOTH old and new README installations.

No restart, config change, database scan, log dump, or secret output. Run while
the slowdown is present, preferably BEFORE restarting any service.
"""
import csv
import datetime
import http.cookiejar
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import urllib.request


def command(args, timeout=10):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=timeout).strip()


def runtime_metrics(path):
    result = {}
    for query in ("show info", "show stat"):
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(str(path))
            connection.sendall((query + "\n").encode())
            chunks = []
            total = 0
            while chunk := connection.recv(65536):
                total += len(chunk)
                if total > 8 * 1024 * 1024:
                    raise ValueError("runtime response too large")
                chunks.append(chunk)
        body = b"".join(chunks).decode()
        if query == "show info":
            allowed = {"Version", "Uptime_sec", "Nbthread", "CurrConns", "Maxconn", "Idle_pct", "Tasks", "Run_queue", "SslRate", "ConnRate"}
            result["info"] = {k: v.strip() for line in body.splitlines() if ":" in line for k, v in [line.split(":", 1)] if k in allowed}
        else:
            fields = {"scur", "smax", "slim", "stot", "rate", "ereq", "dreq", "status"}
            result["frontends"] = {row["# pxname"]: {k: v for k, v in row.items() if k in fields} for row in csv.DictReader(io.StringIO(body)) if row.get("svname") == "FRONTEND" and row.get("# pxname") in {"public_sni", "internal_tls", "public_direct"}}
    return result


def main():
    root = Path(os.environ.get("FLUXGATE_DIR", "/opt/fluxgate"))
    project = os.environ.get("FLUXGATE_PROJECT", "fluxgate")
    compose = ["docker", "compose", "-p", project, "--project-directory", str(root), "-f", str(root / "compose.yaml")]
    report = {"time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        report["checkout_revision"] = command(["git", "-C", str(root), "rev-parse", "--short", "HEAD"])
    except Exception:
        report["checkout_revision"] = "unavailable"
    containers = {}
    ids = []
    for service in ("panel", "haproxy"):
        identifier = command(compose + ["ps", "-q", service])
        if not identifier:
            report[service] = {"running": False}
            continue
        info = json.loads(command(["docker", "inspect", identifier]))[0]
        containers[service] = info
        ids.append(identifier)
        state = info["State"]
        report[service] = {"image_id": info["Image"], "started_at": state["StartedAt"], "oom_killed": state["OOMKilled"], "restart_count": info["RestartCount"], "health": state.get("Health", {}).get("Status", "not configured")}
    if ids:
        report["docker_stats"] = [json.loads(line) for line in command(["docker", "stats", "--no-stream", "--format", "{{json .}}"] + ids, 20).splitlines()]
    if "panel" in containers:
        panel = containers["panel"]
        environment = dict(value.split("=", 1) for value in panel["Config"]["Env"])
        # Credentials remain in this process only; never in argv or report.
        base = os.environ.get("FLUXGATE_PANEL_URL", "http://127.0.0.1:9389") + "/" + environment.get("PANEL_SECRET_PATH", "admin").strip("/") + "/api"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        try:
            login = urllib.request.Request(base + "/login", data=json.dumps({"token": environment["PANEL_TOKEN"]}).encode(), headers={"Content-Type": "application/json"})
            with opener.open(login, timeout=5):
                pass
            with opener.open(base + "/system", timeout=5) as response:
                report["system"] = json.load(response)
        except Exception as error:
            report["system"] = {"error_type": type(error).__name__}
        for mount in panel["Mounts"]:
            if mount["Destination"] != "/data":
                continue
            data = Path(mount["Source"])
            report["database_files"] = {name: (data / name).stat().st_size for name in ("panel.db", "panel.db-wal", "panel.db-shm") if (data / name).exists()}
            try:
                report["haproxy_runtime"] = runtime_metrics(data / "haproxy.sock")
            except Exception as error:
                report["haproxy_runtime"] = {"error_type": type(error).__name__}
    for key, args in {"vmstat": ["vmstat", "1", "3"], "socket_summary": ["ss", "-s"], "disk": ["df", "-h", str(root)]}.items():
        try:
            report[key] = command(args)
        except Exception:
            report[key] = "unavailable"
    report["kernel_network_limits"] = {}
    for key in ("net.ipv4.ip_local_port_range", "net.ipv4.tcp_tw_reuse", "net.netfilter.nf_conntrack_count", "net.netfilter.nf_conntrack_max"):
        try:
            report["kernel_network_limits"][key] = command(["sysctl", "-n", key])
        except Exception:
            report["kernel_network_limits"][key] = "unavailable"
    allowed = {"CurrEstab", "ActiveOpens", "PassiveOpens", "AttemptFails", "EstabResets", "RetransSegs", "InErrs", "OutRsts", "ListenOverflows", "ListenDrops", "TCPTimeouts", "TCPMemoryPressures", "TCPBacklogDrop", "TCPSynRetrans"}
    report["tcp_counters"] = {}
    for path in (Path("/proc/net/snmp"), Path("/proc/net/netstat")):
        if not path.exists():
            continue
        lines = path.read_text().splitlines()
        for names, values in zip(lines[0::2], lines[1::2]):
            report["tcp_counters"].update({key: value for key, value in zip(names.split()[1:], values.split()[1:]) if key in allowed})
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"diagnostics_error_type": type(error).__name__, "hint": "Run with sudo on the Docker host; check FLUXGATE_DIR."}))
        raise SystemExit(1)
