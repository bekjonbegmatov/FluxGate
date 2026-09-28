// Measure the server path inside Linux, excluding macOS published-port forwarding.
import https from 'node:https';
import {performance} from 'node:perf_hooks';
const seconds=Number(process.argv[2]||60),streams=Number(process.argv[3]||4);
const agent=new https.Agent({keepAlive:true,maxSockets:streams,rejectUnauthorized:false});
const started=performance.now(),deadline=started+seconds*1000;
let bytes=0,previousBytes=0,previousAt=started;
const windows=[];
function sample(){
  const now=performance.now();
  const speed=(bytes-previousBytes)*8/(now-previousAt)/1e6;
  windows.push(Number(speed.toFixed(3)));
  console.log(`TLS Linux window: ${speed.toFixed(3)} Gbit/s (${streams} streams)`);
  previousBytes=bytes;previousAt=now;
}
function download(){return new Promise((resolve,reject)=>{
  const request=https.get({hostname:'haproxy',port:443,servername:'route0.example.test',path:'/?size=67108864',headers:{Host:'route0.example.test'},agent},response=>{
    if(response.statusCode!==200){response.resume();reject(new Error(`HTTP ${response.statusCode}`));return}
    let received=0;
    response.on('data',chunk=>{bytes+=chunk.length;received+=chunk.length});
    response.on('end',()=>received===67108864?resolve():reject(new Error('truncated download')));
    response.on('error',reject);
  });
  request.setTimeout(20000,()=>request.destroy(new Error('load test timed out')));
  request.on('error',reject);
})}
const timer=setInterval(sample,5000);
try{
  await Promise.all(Array.from({length:streams},async()=>{while(performance.now()<deadline)await download()}));
  if(performance.now()-previousAt>=1000)sample();
  console.log(JSON.stringify({linux_tls_gbit_s:windows,mean_gbit_s:Number((bytes*8/(performance.now()-started)/1e6).toFixed(3)),streams,seconds}));
}finally{clearInterval(timer);agent.destroy()}
