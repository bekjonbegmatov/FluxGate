// Run ONLY inside the isolated integration stack. Reproduce the two-frontend
// global-slot starvation at small limits; always restore the generated config.
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
const config='/data/haproxy.cfg', original=fs.readFileSync(config,'utf8');
const outer=original.includes('frontend public_sni\n')?'public_sni':'public_direct';
function apply(value){fs.writeFileSync(config+'.capacity-test',value,{mode:0o600});fs.renameSync(config+'.capacity-test',config)}
function stats(){return new Promise((resolve,reject)=>{
  const c=net.createConnection('/data/haproxy.sock',()=>c.write('show stat\n'));let body='';
  c.on('data',b=>body+=b);c.on('end',()=>{
    const lines=body.trim().split('\n').map(x=>x.split(','));
    const names=lines.shift().map(x=>x.replace(/^# /,'').trim());
    resolve(Object.fromEntries(lines.filter(x=>x[1]==='FRONTEND').map(x=>[x[0],Object.fromEntries(names.map((k,i)=>[k,x[i]]))])));
  });c.on('error',reject);c.setTimeout(2000,()=>c.destroy(new Error('stats timeout')));
})}
async function waitLimit(limit){
  for(let i=0;i<100;i++){
    try{if(Number((await stats())[outer]?.slim)===limit)return}catch{}
    await delay(200);
  }
  throw new Error(`HAProxy did not apply ${outer} limit ${limit}`);
}
async function scenario(legacy){
  let value=original.replace(/^  maxconn \d+\n/gm,'');
  value=value.replace('global\n',`global\n  maxconn ${legacy?32:40}\n`);
  if(!legacy)value=value.replace(`frontend ${outer}\n`,`frontend ${outer}\n  maxconn 16\n`).replace('frontend internal_tls\n','frontend internal_tls\n  maxconn 24\n');
  apply(value);await waitLimit(legacy?32:16);
  const sockets=[],secured=[];
  try{
    await Promise.all(Array.from({length:24},()=>new Promise((resolve,reject)=>{
      const c=net.createConnection({host:'haproxy',port:443},resolve);c.on('error',reject);sockets.push(c);
    })));
    // Establish every outer connection BEFORE allowing inner TLS handshakes.
    await delay(350);
    const accepted=Number((await stats())[outer].scur);
    assert.equal(accepted,legacy?24:16,'outer admission did not match the test setup');
    let completed=0;
    for(const socket of sockets){
      const c=tls.connect({socket,servername:'route0.example.test',rejectUnauthorized:false},()=>c.write('GET /tunnel HTTP/1.1\r\nHost: route0.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n'));
      let header='',counted=false;
      c.on('data',b=>{header+=b;if(!counted&&header.includes('\r\n\r\n')){assert.ok(header.startsWith('HTTP/1.1 101'));completed++;counted=true}});
      c.on('error',()=>{});secured.push(c);
    }
    await delay(2000);
    const snapshot=await stats();
    console.log(JSON.stringify({capacity_case:legacy?'old-shared-global':'reserved-inner-capacity',outer_accepted:accepted,tunnels_completed:completed,internal_sessions:Number(snapshot.internal_tls.scur)}));
    if(legacy)assert.ok(completed<16,'old configuration unexpectedly avoided saturation');
    else assert.equal(completed,16,'admitted clients could not complete the inner hop');
  }finally{
    for(const c of sockets){if(!c.destroyed)c.resetAndDestroy()}
    for(const c of secured)c.destroy();
    for(let i=0;i<50;i++){if(Number((await stats())[outer].scur)===0)break;await delay(100)}
  }
}
try{
  await scenario(true);
  await scenario(false);
  let closed=0;const silent=[];
  for(let i=0;i<6;i++){
    const c=net.createConnection({host:'haproxy',port:443});c.on('error',()=>{});c.on('close',()=>closed++);c.resume();silent.push(c);
  }
  await delay(6500);
  for(const c of silent)c.destroy();
  assert.equal(closed,6,'silent non-TLS clients outlived the ClientHello inspection timeout');
  console.log('PASS: two-hop admission avoids global-slot starvation; silent clients expire');
}finally{
  apply(original);
  const section=original.split(`frontend ${outer}\n`)[1];
  const limit=Number(section.match(/  maxconn (\d+)/)[1]);
  await waitLimit(limit);
}
