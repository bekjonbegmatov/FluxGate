// Synthetic history in the disposable integration volume ONLY.
import {DatabaseSync} from 'node:sqlite';
const days=Number(process.argv[2]||90);
if(!Number.isInteger(days)||days<1||days>90)throw new Error('history days must be 1..90');
const db=new DatabaseSync('/data/panel.db');
db.exec('PRAGMA busy_timeout=5000; BEGIN IMMEDIATE');
try{
  const now=Math.floor(Date.now()/60000)*60;
  db.prepare(`WITH RECURSIVE minute(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM minute WHERE n<?)
INSERT OR IGNORE INTO samples(route_id,ts,up,down) SELECT id,?-n*60,1000000,2000000 FROM routes CROSS JOIN minute`).run(days*1440,now);
  db.exec('INSERT OR IGNORE INTO request_samples SELECT route_id,ts,10,9,0,1,0 FROM samples; COMMIT');
  console.log(JSON.stringify({seed_days:days,traffic_rows:db.prepare('SELECT count(*) AS n FROM samples').get().n,request_rows:db.prepare('SELECT count(*) AS n FROM request_samples').get().n}));
}catch(error){db.exec('ROLLBACK');throw error}finally{db.close()}
