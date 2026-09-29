#!/usr/bin/env python3
"""Local updater checks. Credentials come from stdin, never argv or logs."""
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import urllib.request
import zipfile


def panel_client(env):
    base = os.environ.get("FLUXGATE_PANEL_URL", "http://127.0.0.1:9389").rstrip("/")
    path = env.get("PANEL_SECRET_PATH", "admin").strip("/")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    login = urllib.request.Request(base + "/" + path + "/api/login", data=json.dumps({"token": env["PANEL_TOKEN"]}).encode(), headers={"Content-Type": "application/json"})
    with opener.open(login, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("Panel login failed")
    return opener, base + "/" + path + "/api"


def backup(env, destination):
    opener, base = panel_client(env)
    path = Path(destination)
    partial = path.with_suffix(".partial")
    try:
        with opener.open(base + "/backup", timeout=120) as source, partial.open("xb") as out:
            os.chmod(partial, 0o600)
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        with zipfile.ZipFile(partial) as archive:
            if not {"panel.db", "manifest.json", "certs/fallback.pem"}.issubset(archive.namelist()) or archive.testzip() is not None:
                raise RuntimeError("Backup archive is incomplete or corrupt")
        partial.replace(path)
    finally:
        partial.unlink(missing_ok=True)


def verify(env):
    deadline = time.monotonic() + 90
    while True:
        try:
            opener, base = panel_client(env)
            with opener.open(base + "/routes", timeout=5) as response:
                if not isinstance(json.load(response), list):
                    raise RuntimeError("Invalid route response")
            with opener.open(base + "/settings", timeout=5) as response:
                domain = json.load(response)["domain"]
            # The proxy intentionally uses self-signed certificates. Check the
            # actual SNI/fallback path, including the Go relay, at the local host.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=domain) as tls:
                    tls.sendall(("GET / HTTP/1.1\r\nHost: " + domain + "\r\nConnection: close\r\n\r\n").encode())
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    if response.status != 200:
                        raise RuntimeError("Proxy fallback check failed")
            return
        except (OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise RuntimeError("Panel/API/TLS proxy did not become ready") from None
            time.sleep(2)


def rollback_config(source, destination, stamp):
    config = json.loads(Path(source).read_text())
    for name in ("panel", "haproxy"):
        service = config["services"][name]
        service.pop("build", None)
        service["image"] = "fluxgate-rollback-" + name + ":" + stamp
        service["pull_policy"] = "never"
    Path(destination).write_text(json.dumps(config, indent=2) + "\n")
    os.chmod(destination, 0o600)


def configure_env(source, destination, value):
    """Preserve secrets/comments verbatim; change only the explicit capacity key."""
    content = Path(source).read_text()
    if value:
        if not re.fullmatch(r"[0-9]{1,6}", value) or not 1 <= int(value) <= 100000:
            raise ValueError("Invalid connection limit")
        lines = content.splitlines(keepends=True)
        content = "".join(line for line in lines if not re.match(r"^\s*(?:export\s+)?PANEL_MAX_CONNECTIONS\s*=", line))
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"PANEL_MAX_CONNECTIONS={int(value)}\n"
    with open(destination, "x") as output:
        os.chmod(destination, 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def main():
    os.umask(0o077)
    if sys.argv[1] == "rollback-config":
        rollback_config(*sys.argv[2:])
    elif sys.argv[1] == "configure-env":
        configure_env(*sys.argv[2:])
    else:
        env = dict(item.split("=", 1) for item in json.load(sys.stdin))
        if sys.argv[1] == "backup":
            backup(env, sys.argv[2])
        elif sys.argv[1] == "verify":
            verify(env)
        else:
            raise RuntimeError("Unknown updater command")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print exception text that could contain a credential or URL.
        print("FluxGate update check failed (" + type(error).__name__ + "). Existing backups are retained.", file=sys.stderr)
        sys.exit(1)
