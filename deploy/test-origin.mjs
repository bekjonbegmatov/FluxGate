import http from 'node:http';
import crypto from 'node:crypto';
const block=Buffer.alloc(64*1024,0x61);
const server=http.createServer((req,res)=>{
  const size=Math.min(1024**3,Math.max(0,Number(new URL(req.url,'http://localhost').searchParams.get('size')||2)));
  res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Length':size});
  let remaining=size;
  const send=()=>{
    while(remaining>0){const n=Math.min(remaining,block.length);remaining-=n;if(!res.write(block.subarray(0,n))){res.once('drain',send);return}}
    res.end();
  };
  send();
});
server.on('upgrade',(req,socket)=>{
  const accept=crypto.createHash('sha1').update(req.headers['sec-websocket-key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n');
  // Exercise an opaque bidirectional upgraded stream through HAProxy and relay.
  socket.on('data',data=>socket.write(data));
  socket.on('error',()=>{});
});
server.listen(8080,'0.0.0.0');
