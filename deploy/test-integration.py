#!/usr/bin/env python3
"""End-to-end checks against an isolated Docker stack on loopback ports.

Run: python3 deploy/test-integration.py [--seconds 30]
Builds are done before startup. Only this script's test containers/volume are
removed in finally; production containers and data are never addressed.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import tempfile
import threading
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parent.parent
COMPOSE=["docker","compose","-p","fluxgate-integration-test","-f",str(ROOT/"deploy/compose.test.yaml")]
TOKEN="integration-only-token-not-a-real-secret"
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

class TruncatedDownload(Exception): pass

def compose(*args):
    return subprocess.check_output(COMPOSE+list(args),text=True).strip()

def api(path,method="GET",data=None):
    request=urllib.request.Request("http://127.0.0.1:19389/admin/api"+path,method=method,data=None if data is None else json.dumps(data).encode(),headers={"Content-Type":"application/json"})
    with opener.open(request,timeout=20) as response:
        return json.load(response)

def tls_socket(domain):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname=False
    context.verify_mode=ssl.CERT_NONE
    return context.wrap_socket(socket.create_connection(("127.0.0.1",19443),timeout=20),server_hostname=domain)

def download(domain,size=2):
    with tls_socket(domain) as connection:
        connection.sendall(f"GET /?size={size} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
        response=http.client.HTTPResponse(connection)
        response.begin()
        count=0
        while chunk:=response.read(256*1024):
            count+=len(chunk)
        if response.status==200 and domain!="fallback.example.test":
            if count!=size: raise TruncatedDownload((count,size))
        return response.status,count

def wait_for(fn,timeout=30):
    end=time.monotonic()+timeout
    while True:
        try:
            result=fn()
            if result:
                return result
        except (OSError,AssertionError,ValueError,http.client.HTTPException,TruncatedDownload):
            pass
        if time.monotonic()>end:
            raise AssertionError("Timed out waiting for test condition")
        time.sleep(.2)

def config_hash():
    return compose("exec","-T","panel","sha256sum","/data/haproxy.cfg").split()[0]

def master_command(command):
    return compose("exec","-T","origin","node","-e","const n=require('net');const c=n.createConnection('/data/haproxy-master.sock',()=>c.write(process.argv[1]+'\\n'));c.on('data',b=>process.stdout.write(b));c.on('end',()=>process.exit());setTimeout(()=>process.exit(),3000)",command)

def route(rid):
    return next(r for r in api("/routes") if r["id"]==rid)

def update(rid,**changes):
    r=route(rid)
    r.update(changes)
    return api(f"/routes/{rid}","PUT",r)

def set_mode(mode, **settings):
    current=api('/settings')
    payload={k:current[k] for k in ['domain','fallback_html','tg_api','tg_chat']}
    return api('/settings','PUT',dict(payload,proxy_mode=mode,**settings))

def assert_tunnel_closed(tunnel):
    tunnel.settimeout(5)
    try:
        assert tunnel.recv(1)==b'', 'blocked tunnel still transfers bytes'
    except TimeoutError as error:
        raise AssertionError('blocked tunnel remained open') from error
    except (ConnectionResetError,ssl.SSLEOFError):
        pass

def tls_rejected(domain):
    try:
        with tls_socket(domain):
            return False
    except (OSError,ssl.SSLError):
        return True

def check_passthrough(ip, ids):
    domain='opaque.example.test'
    with tempfile.TemporaryDirectory(prefix='fluxgate-origin-tls-') as directory:
        key,cert=Path(directory)/'key.pem',Path(directory)/'cert.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
                        '-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=*.example.test',
                        '-addext','subjectAltName=DNS:*.example.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        compose('cp',str(key),'origin:/tmp/origin-key.pem')
        compose('cp',str(cert),'origin:/tmp/origin-cert.pem')
        certificate=cert.read_text()
    expected=ssl.PEM_cert_to_DER_cert(certificate)
    value=api('/routes','POST',dict(name='Opaque TLS',sni='*.example.test',ip=ip,port=8443,tls=True,tls_passthrough=True,
              verify=False,verify_name='',paused=False,daily_limit=0,monthly_limit=0,count_mode='both',down_bps=0,up_bps=0,threshold=80,monitor=False))
    rid=value['id']
    for mode in ['relay','direct']:
        set_mode(mode,direct_limits=True)
        frontend='public_direct' if mode=='direct' else 'public_sni'
        wait_for(lambda:f'{frontend},FRONTEND,' in master_command('@1 show stat'))
        wait_for(lambda:download(domain)[0]==200)
        assert route(rid)['tls_passthrough']
        # Trust only the origin certificate: a panel-generated cert cannot pass.
        context=ssl.create_default_context(cadata=certificate)
        context.set_alpn_protocols(['fg-opaque-test'])
        with context.wrap_socket(socket.create_connection(('127.0.0.1',19443),timeout=5),server_hostname=domain) as connection:
            assert connection.getpeercert(binary_form=True)==expected
            assert connection.selected_alpn_protocol()=='fg-opaque-test','proxy changed ALPN'
        # Exact normal route and primary fallback must beat the opaque wildcard.
        assert download('route0.example.test')[0]==200
        assert download('fallback.example.test')[0]==200
        with tls_socket('route0.example.test') as connection:
            assert connection.getpeercert(binary_form=True)!=expected
        wait_for(lambda:f'Maxconn: 200256' in master_command('@1 show info'))
        if mode=='direct':
            subprocess.run(COMPOSE+['exec','-T','origin','node','/test/capacity.mjs'],check=True)
            wait_for(lambda:download(domain)[0]==200)

        # A closed download is counted once, not again at the TCP dispatcher.
        time.sleep(6)
        before=route(rid)['down_total']
        assert download(domain,1024*1024)[0]==200
        wait_for(lambda:route(rid)['down_total']>=before+1024*1024)
        assert route(rid)['down_total']<before+2*1024*1024,'passthrough double-counted'
        tunnel=open_tunnel(domain)
        before=route(rid)['down_total']
        update(ids[1],sni=f'passthrough-reload-{mode}.example.test')
        wait_for(lambda:download(f'passthrough-reload-{mode}.example.test')[0]==200)
        for _ in range(6):
            echo_bytes(tunnel,64*1024)
            time.sleep(1)
        wait_for(lambda:route(rid)['down_total']>=before+6*64*1024)
        request_stats=next(s for s in api('/request-stats') if s['route_id']==rid)
        assert request_stats['http_visible'] is False and request_stats['requests']==0
        if mode=='direct':
            before=route(rid)['down_total']
            compose('restart','-t','45','panel')
            wait_for(lambda:api('/settings')['proxy_mode']=='direct')
            echo_bytes(tunnel,512*1024)
            wait_for(lambda:route(rid)['down_total']>=before+512*1024)
            assert route(rid)['down_total']<before+1024*1024,'restart doubled passthrough traffic'
        update(rid,paused=True)
        wait_for(lambda:tls_rejected(domain))
        assert_tunnel_closed(tunnel)
        tunnel.close()
        update(rid,paused=False)
        wait_for(lambda:download(domain)[0]==200)

        # A live stream from an old worker must also be stopped by a quota.
        tunnel=open_tunnel(domain)
        update(ids[1],sni=f'quota-pass-{mode}.example.test')
        wait_for(lambda:download(f'quota-pass-{mode}.example.test')[0]==200)
        update(rid,daily_limit=1)
        wait_for(lambda:tls_rejected(domain))
        assert_tunnel_closed(tunnel)
        tunnel.close()
        api(f'/routes/{rid}/topup','POST',{'kind':'daily','bytes':route(rid)['daily_used']+1024**2})
        wait_for(lambda:download(domain)[0]==200)
        update(rid,daily_limit=0,monthly_limit=1)
        wait_for(lambda:tls_rejected(domain))
        api(f'/routes/{rid}/topup','POST',{'kind':'monthly','bytes':route(rid)['monthly_used']+1024**2})
        wait_for(lambda:download(domain)[0]==200)
        update(rid,monthly_limit=0,down_bps=128*1024,up_bps=128*1024)
        time.sleep(4)
        start=time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            result=list(pool.map(lambda _:download(domain,128*1024),range(4)))
        elapsed=time.monotonic()-start
        assert all(r[0]==200 for r in result) and elapsed>=2,(mode,elapsed)
        tunnel=open_tunnel(domain)
        start=time.monotonic()
        echo_bytes(tunnel,256*1024)
        assert time.monotonic()-start>=1,'passthrough tunnel bypassed shaping'
        tunnel.close()
        update(rid,down_bps=0,up_bps=0)
        wait_for(lambda:download(domain)[0]==200)
        if mode=='relay':
            # Exercise exhaustion during copying, not just admission rejection.
            limit=route(rid)['daily_used']+128*1024
            update(rid,daily_limit=limit)
            # Daily topup from above is still valid: consume beyond the total.
            effective=limit+route(rid)['daily_extra']
            try:
                download(domain,effective-route(rid)['daily_used']+1024**2)
                raise AssertionError('passthrough relay exceeded its quota')
            except (OSError,http.client.HTTPException,TruncatedDownload):
                pass
            wait_for(lambda:tls_rejected(domain))
            assert route(rid)['daily_used']<=effective
            update(rid,daily_limit=0)
        if mode=='direct':
            # Limits remain opt-in for opaque routes, just like ordinary ones.
            set_mode('direct',direct_limits=False)
            update(rid,daily_limit=1,down_bps=1)
            assert download(domain,2*1024**2)[0]==200
            set_mode('direct',direct_limits=True)
            wait_for(lambda:tls_rejected(domain))
            update(rid,daily_limit=0,down_bps=0)
            wait_for(lambda:download(domain)[0]==200)
            update(rid,daily_limit=route(rid)['daily_used']+1024**3)
            wait_for(lambda:download(domain)[0]==200)
            tunnel=open_tunnel(domain)
            update(ids[1],sni='passthrough-watchdog.example.test')
            wait_for(lambda:download('passthrough-watchdog.example.test')[0]==200)
            compose('pause','panel')
            try:
                wait_for(lambda:tls_rejected(domain),25)
                assert download('route0.example.test')[0]==200
                assert_tunnel_closed(tunnel)
            finally:
                compose('unpause','panel')
                tunnel.close()
            wait_for(lambda:download(domain)[0]==200)
            update(rid,daily_limit=0)
        print(f'PASS: {mode} TLS identity, exact/wildcard SNI, live accounting, reload, pause, quotas/topup, shared shaping ({elapsed:.2f}s)',flush=True)
    # New field survives the real backup/restore path as well as agent restart.
    with opener.open('http://127.0.0.1:19389/admin/api/backup',timeout=30) as response:
        backup=response.read()
    update(rid,tls_passthrough=False)
    before=api('/system')['process_started_at']
    req=urllib.request.Request('http://127.0.0.1:19389/admin/api/restore',data=backup,headers={'Content-Type':'application/zip'})
    with opener.open(req,timeout=30) as response: assert response.status==202
    wait_for(lambda:api('/system')['process_started_at']!=before,60)
    assert route(rid)['tls_passthrough']
    wait_for(lambda:download(domain)[0]==200)
    api(f'/routes/{rid}','DELETE')
    set_mode('relay')
    wait_for(lambda:download('route0.example.test')[0]==200)
    print('PASS: passthrough backup/restore and removal of mixed dispatcher',flush=True)

def check_direct_limits(ids):
    # Old direct settings remain opt-in; enabling must enforce existing usage.
    set_mode('direct',direct_limits=True)
    wait_for(lambda:download('route2.example.test')[0]==503)
    assert route(ids[2])['status']=='quota'
    update(ids[2],down_bps=0)
    api(f'/routes/{ids[2]}/topup','POST',{'kind':'daily','bytes':route(ids[2])['daily_used']+2*1024*1024})
    wait_for(lambda:download('route2.example.test')[0]==200)
    update(ids[2],monthly_limit=1)
    wait_for(lambda:download('route2.example.test')[0]==503)
    api(f'/routes/{ids[2]}/topup','POST',{'kind':'monthly','bytes':route(ids[2])['monthly_used']+2*1024*1024})
    wait_for(lambda:download('route2.example.test')[0]==200)
    print('PASS: direct daily/monthly soft quotas and topups',flush=True)

    update(ids[0],down_bps=128*1024)
    time.sleep(4)
    started=time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:
        result=list(pool.map(lambda _:download('route0.example.test',128*1024),range(4)))
    elapsed=time.monotonic()-started
    assert all(r[0]==200 for r in result) and elapsed>=2,elapsed
    tunnel=open_tunnel('route0.example.test')
    started=time.monotonic()
    echo_bytes(tunnel,256*1024)
    assert time.monotonic()-started>=1,'direct WS bypassed bandwidth filter'
    update(ids[1],sni='limited-reload.example.test')
    wait_for(lambda:download('limited-reload.example.test')[0]==200)
    assert_tunnel_closed(tunnel)
    tunnel.close()
    update(ids[0],down_bps=0,daily_limit=route(ids[0])['daily_used']+1024**3)
    wait_for(lambda:download('route0.example.test')[0]==200)
    time.sleep(4)
    tunnel=open_tunnel('route0.example.test')
    pid=str(api('/system')['agent_pid'])
    compose('exec','-T','panel','kill','-STOP',pid)
    try:
        wait_for(lambda:download('route0.example.test')[0]==503,25)
        assert download('limited-reload.example.test')[0]==200,'unlimited direct route was stopped'
        assert_tunnel_closed(tunnel)
    finally:
        compose('exec','-T','panel','kill','-CONT',pid)
        tunnel.close()
    wait_for(lambda:download('route0.example.test')[0]==200)
    watchdog_tunnels=[open_tunnel('route0.example.test') for _ in range(3)]
    # Keep a quota-bearing stream on a draining generation: the watchdog must
    # close it even though ordinary server commands reject stopped backends.
    update(ids[1],sni='watchdog-reload.example.test')
    wait_for(lambda:download('watchdog-reload.example.test')[0]==200)
    for tunnel in watchdog_tunnels:
        echo_bytes(tunnel,1024)
    compose('pause','panel')
    try:
        wait_for(lambda:download('route0.example.test')[0]==503,25)
        assert download('watchdog-reload.example.test')[0]==200
        for tunnel in watchdog_tunnels:
            assert_tunnel_closed(tunnel)
    finally:
        compose('unpause','panel')
        for tunnel in watchdog_tunnels:
            tunnel.close()
    wait_for(lambda:download('route0.example.test')[0]==200)
    update(ids[0],daily_limit=0)
    update(ids[2],monthly_limit=0)
    set_mode('direct',direct_limits=False)
    print(f'PASS: direct shared bandwidth ({elapsed:.2f}s), WebSocket shaping, reload and watchdog survives frozen agent/container',flush=True)

def open_tunnel(domain):
    tunnel=tls_socket(domain)
    tunnel.sendall(f"GET /tunnel HTTP/1.1\r\nHost: {domain}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".encode())
    headers=b''
    while b'\r\n\r\n' not in headers: headers+=tunnel.recv(1024)
    assert headers.startswith(b'HTTP/1.1 101'),headers
    return tunnel

def echo_bytes(tunnel,size):
    payload=b'x'*min(size,16384)
    remaining=size
    while remaining:
        chunk=payload[:min(remaining,len(payload))]
        tunnel.sendall(chunk)
        received=b''
        while len(received)<len(chunk):
            part=tunnel.recv(len(chunk)-len(received))
            assert part,'tunnel closed'
            received+=part
        assert received==chunk
        remaining-=len(chunk)

def check_direct(ids, load=True):
    set_mode('direct')
    wait_for(lambda:'frontend public_direct' in compose('exec','-T','panel','cat','/data/haproxy.cfg'))
    # Existing exhausted quotas / 1 byte/s limits must not affect direct mode.
    update(ids[2],daily_limit=1,down_bps=1)
    wait_for(lambda:download('route2.example.test',4*1024*1024)[0]==200)
    wait_for(lambda:api('/system')['relay_connections']==0)
    assert api('/settings')['proxy_mode']=='direct'
    assert route(ids[2])['status']!='quota'
    print('PASS: direct mode routes TLS without relay, quotas/rates bypassed explicitly',flush=True)

    before=route(ids[0])['down_total']
    assert download('route0.example.test',2*1024*1024)[0]==200
    wait_for(lambda:route(ids[0])['down_total']>=before+2*1024*1024)
    tunnel=open_tunnel('route0.example.test')
    additional_tunnels=[open_tunnel('route0.example.test') for _ in range(2)]
    # Reloads must retain BOTH new and draining-worker counters.
    before=route(ids[0])['down_total']
    for i in range(3):
        domain=f'direct-reload{i}.example.test'
        update(ids[1],sni=domain)
        wait_for(lambda:download(domain)[0]==200)
        echo_bytes(tunnel,256*1024)
    # Keep the connection open: contstats must update even without a close.
    for _ in range(7):
        echo_bytes(tunnel,32768)
        time.sleep(1)
    wait_for(lambda:route(ids[0])['down_total']>=before+3*256*1024)
    assert api('/system')['relay_connections']==0
    print('PASS: live direct WebSocket accounting survives three reloads',flush=True)

    # Restart ONLY the panel while a direct connection is on an old worker.
    before=route(ids[0])['down_total']
    compose('restart','-t','45','panel')
    wait_for(lambda:api('/settings')['proxy_mode']=='direct')
    echo_bytes(tunnel,1024*1024)
    for extra in additional_tunnels:
        echo_bytes(extra,1024)
    wait_for(lambda:route(ids[0])['down_total']>=before+1024*1024)
    assert route(ids[0])['down_total']<before+2*1024*1024,'counter doubled after panel restart'
    update(ids[0],paused=True)
    wait_for(lambda:download('route0.example.test')[0]==503)
    assert_tunnel_closed(tunnel)
    tunnel.close()
    for extra in additional_tunnels:
        assert_tunnel_closed(extra)
        extra.close()
    update(ids[0],paused=False)
    wait_for(lambda:download('route0.example.test')[0]==200)
    print('PASS: panel restart recovers old-worker traffic; direct pause/resume works',flush=True)

    # Public API cannot invoke restart without a session or confirmation.
    try:
        urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:19389/admin/api/restart',data=b'{"confirm":true}',headers={'Content-Type':'application/json'}))
        raise AssertionError('unauthenticated restart accepted')
    except urllib.error.HTTPError as error: assert error.code==401
    old_start=api('/system')['process_started_at']
    old_master=master_command('show proc').splitlines()
    before=route(ids[0])['down_total']
    api('/restart','POST',{'confirm':True})
    wait_for(lambda:api('/system')['process_started_at']!=old_start,60)
    wait_for(lambda:download('route0.example.test')[0]==200)
    assert master_command('show proc').splitlines()!=old_master,'HAProxy did not restart'
    assert api('/settings')['proxy_mode']=='direct'
    assert route(ids[0])['down_total']>=before
    print('PASS: confirmed full restart brings panel and HAProxy back with mode/counters intact',flush=True)

    if load:
        subprocess.run(COMPOSE+['exec','-T','origin','node','/test/load.mjs','20','4'],check=True)
    assert api('/system')['relay_connections']==0
    check_direct_limits(ids)
    update(ids[2],daily_limit=1)
    remaining=max(0,route(ids[2])['daily_limit']+route(ids[2])['daily_extra']-route(ids[2])['daily_used'])
    wait_for(lambda:download('route2.example.test',remaining+4*1024*1024)[0]==200)
    wait_for(lambda:route(ids[2])['daily_used']>route(ids[2])['daily_limit']+route(ids[2])['daily_extra'])
    tunnel=open_tunnel('route0.example.test')
    set_mode('relay')
    wait_for(lambda:download('route2.example.test')[0]==429)
    assert_tunnel_closed(tunnel)
    tunnel.close()
    update(ids[2],daily_limit=0,down_bps=0)
    wait_for(lambda:download('route0.example.test')[0]==200)
    print('PASS: returning to relay closes direct tunnels and enforces saved quotas',flush=True)

def main(seconds, history_days):
    # Keep laptop builds bounded and sequential; throughput tests are opt-in
    # when --functional-only is selected.
    compose("build", "--build-arg", "GO_BUILD_PROCS=1", "panel")
    compose("build", "--build-arg", "GO_BUILD_PROCS=1", "haproxy")
    try:
        compose("up","-d","--wait","--wait-timeout","120")
        api("/login","POST",{"token":TOKEN})
        assert api('/system')['max_client_connections']==100000
        for mode, limit in [('relay',200256),('direct',100256),('relay',200256)]:
            set_mode(mode)
            wait_for(lambda:download('fallback.example.test')[0]==200)
            wait_for(lambda:f'Maxconn: {limit}' in master_command('@1 show info'))
        print('PASS: real HAProxy starts with 100k public cap in both modes (not a 100k load test)',flush=True)
        assert download("fallback.example.test")[0]==200
        origin=compose("ps","-q","origin")
        ip=subprocess.check_output(["docker","inspect","--format","{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",origin],text=True).strip()
        ids=[]
        for i in range(3):
            value=api("/routes","POST",dict(name=f"Test {i}",sni=f"route{i}.example.test",ip=ip,port=8080,tls=False,verify=False,verify_name="",paused=False,daily_limit=0,monthly_limit=0,count_mode="both",down_bps=0,up_bps=0,threshold=80,monitor=False))
            ids.append(value["id"])
        wait_for(lambda:download("route0.example.test")[0]==200)
        for _ in range(25):
            assert [r["id"] for r in api("/routes")]==sorted(ids)
        initial_hash=config_hash()
        update(ids[0],name="Renamed",down_bps=0)
        assert config_hash()==initial_hash,"metadata triggered a reload"
        print("PASS: routing, stable order, deterministic/no-op config",flush=True)

        # An independent web heap/process must not own the traffic lifecycle.
        agent=api('/system')['agent_pid']
        live=open_tunnel('route0.example.test')
        web=compose('exec','-T','panel','pgrep','-f','^/usr/local/bin/panel --web$')
        compose('exec','-T','panel','kill','-KILL',web)
        echo_bytes(live,256*1024)
        wait_for(lambda:api('/system')['agent_pid']==agent)
        live.close()
        print('PASS: web process crash/restart preserves relay connections',flush=True)

        tunnel=tls_socket("route0.example.test")
        tunnel.sendall(b"GET /tunnel HTTP/1.1\r\nHost: route0.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
        headers=b""
        while b"\r\n\r\n" not in headers:
            headers+=tunnel.recv(1024)
        assert headers.startswith(b"HTTP/1.1 101"),headers
        for i in range(4):
            domain=f"changed{i}.example.test"
            update(ids[1],sni=domain)
            wait_for(lambda:download(domain)[0]==200)
            tunnel.sendall(b"still alive")
            assert tunnel.recv(11)==b"still alive"
        print("PASS: upgraded tunnel survives four actual HAProxy reloads",flush=True)
        update(ids[0],paused=True)
        assert download("route0.example.test")[0]==503
        assert_tunnel_closed(tunnel)
        tunnel.close()
        update(ids[0],paused=False)
        assert download("route0.example.test")[0]==200
        # Old workers may still be finishing HTTP keep-alive/half-close timers.
        print(master_command("show proc"),flush=True)
        try:
            wait_for(lambda:sum(p.strip()=="haproxy" for p in compose("exec","-T","haproxy","ps","-o","comm").splitlines())==2,40)
        except AssertionError:
            procs=master_command("show proc")
            print(procs,flush=True)
            for line in procs.splitlines():
                values=line.split()
                if values and values[0].isdigit() and "worker" in line:
                    print(master_command("@!"+values[0]+" show sess"),flush=True)
            print(json.dumps(api('/system')),flush=True)
            raise
        print("PASS: pause closes active tunnel, resume works, old workers reaped",flush=True)

        update(ids[2],daily_limit=256*1024)
        quota_hash=config_hash()
        try:
            download("route2.example.test",1024*1024)
            raise AssertionError("Quota allowed the entire download")
        except (OSError,http.client.HTTPException,TruncatedDownload):
            pass
        assert download("route2.example.test")[0]==429
        api(f"/routes/{ids[2]}/topup","POST",{"kind":"daily","bytes":2*1024*1024})
        assert download("route2.example.test")[0]==200
        assert config_hash()==quota_hash,"quota changed HAProxy config"
        print("PASS: quotas/429/topup, no unmetered window or quota reload",flush=True)

        update(ids[0],down_bps=128*1024)
        start=time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:download("route0.example.test",64*1024),range(4)))
        elapsed=time.monotonic()-start
        assert all(status==200 for status,_ in results) and elapsed>=.85,elapsed
        update(ids[0],down_bps=0)
        print(f"PASS: four streams share one rate limit ({elapsed:.2f}s)",flush=True)

        before=route(ids[0])["down_total"]
        assert download("route0.example.test",1024*1024)[0]==200
        compose("restart","-t","45","panel")
        wait_for(lambda:download("route0.example.test")[0]==200)
        wait_for(lambda:route(ids[0])["down_total"]>=before+1024*1024)
        print("PASS: graceful restart flushes counters and preserves config",flush=True)

        with tempfile.TemporaryDirectory(prefix='fluxgate-backup-test-') as directory:
            archive=Path(directory)/'panel.zip'
            env=dict(os.environ,FLUXGATE_PANEL_URL='http://127.0.0.1:19389')
            subprocess.run(['python3',str(ROOT/'deploy/update-helper.py'),'backup',str(archive)],input=json.dumps(['PANEL_TOKEN='+TOKEN,'PANEL_SECRET_PATH=admin']),env=env,text=True,check=True)
            with zipfile.ZipFile(archive) as saved:
                assert 'panel.db' in saved.namelist() and saved.testzip() is None
            # Open web readers before replacing the DB. Restoring must stop the
            # web process first, or it can keep reading an unlinked old file.
            saved_name=route(ids[0])['name']
            api(f'/history/{ids[0]}?hours=24')
            update(ids[0],name='Changed after snapshot')
            before_restore=api('/system')['process_started_at']
            req=urllib.request.Request('http://127.0.0.1:19389/admin/api/restore',data=archive.read_bytes(),headers={'Content-Type':'application/zip'})
            with opener.open(req,timeout=30) as response: assert response.status==202
            wait_for(lambda:api('/system')['process_started_at']!=before_restore,60)
            assert route(ids[0])['name']==saved_name
            restored_history=api(f'/history/{ids[0]}?hours=24')
            assert sum(point[2] for point in restored_history)==route(ids[0])['down_total']
        print("PASS: updater creates a validated live backup using existing credentials",flush=True)
        print('PASS: restore restarts agent AND web readers and retains session credentials',flush=True)

        subprocess.run(COMPOSE+["exec","-T","origin","node","/test/capacity.mjs"],check=True)
        wait_for(lambda:download("route0.example.test")[0]==200)

        check_direct(ids, load=seconds>0)
        check_passthrough(ip,ids)

        if seconds == 0:
            wait_for(lambda:api('/system')['relay_connections']==0,40)
            print('PASS: functional-only run complete; sustained load/history generation skipped',flush=True)
            return

        if history_days:
            subprocess.run(COMPOSE+["exec","-T","origin","node","--experimental-sqlite","/test/seed-history.mjs",str(history_days)],check=True)
        poll_stop=threading.Event()
        poll_errors=[]
        latencies=[]
        def poll_history():
            while not poll_stop.is_set():
                start=time.monotonic()
                try:
                    assert api('/history/all?hours=2160')
                    assert api('/request-history/all?hours=2160')
                    stats=api('/system')
                    assert stats.get('traffic_flush_errors',0)==0,stats
                except Exception as error:
                    poll_errors.append(type(error).__name__)
                latencies.append(round(time.monotonic()-start,3))
                poll_stop.wait(5)
        poller=threading.Thread(target=poll_history,daemon=True)
        poller.start()
        process=subprocess.Popen(COMPOSE+["exec","-T","origin","node","/test/load.mjs",str(seconds),"4"],stdout=subprocess.PIPE,text=True)
        try:
            for line in process.stdout:
                print(line.rstrip(),flush=True)
            assert process.wait()==0,"Linux TLS load test failed"
        finally:
            poll_stop.set()
            poller.join(timeout=45)
        assert not poller.is_alive() and not poll_errors,("history polling",poll_errors)
        print(json.dumps({"history_poll_seconds":latencies}),flush=True)
        wait_for(lambda:api("/system")["relay_connections"]==0)
        print("PASS: sustained traffic, no remaining route connections",flush=True)
        stats=api('/system')
        print(json.dumps({"system":{k:stats.get(k) for k in ['goroutines','heap_bytes','relay_connections','db_wait_count','db_wait_seconds']}},indent=2))
    finally:
        print(compose("logs","--tail","8"))
        compose("down","-v","--timeout","45")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--seconds",type=int,default=30)
    parser.add_argument("--history-days",type=int,default=0)
    parser.add_argument("--functional-only",action="store_true",help="Skip throughput load and history generation; only small protocol/lifecycle tests")
    args=parser.parse_args()
    main(0 if args.functional_only else args.seconds,0 if args.functional_only else args.history_days)
