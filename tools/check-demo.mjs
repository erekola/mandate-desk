import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {ROOT} from '../src/store.mjs';
// Explicit portable suite. Native wallet and historical evidence scripts are
// outside this runnable distribution and must never be discovered implicitly.
const names=['domain','state-integrity','store-concurrency','interfaces','mcp-transport','brickken-intent','brickken-executor','brickken-mandate','brickken-lifecycle','brickken-prepare','brickken-envelope','brickken-http','brickken-read','brickken-journal','brickken-postcheck','brickken-workspace','demo-recording','brickken-rpc','brickken-live-plan','brickken-live-http','brickken-live-journal','brickken-live-signer','brickken-live-workspace','brickken-live-recovery','brickken-live-a1-recheck','brickken-live-round2-recheck'];
for(const folder of ['src','public'])for(const name of fs.readdirSync(path.join(ROOT,folder)).filter(x=>x.endsWith('.mjs'))){
 const r=spawnSync(process.execPath,['--check',path.join(ROOT,folder,name)],{stdio:'inherit',windowsHide:true});if(r.status!==0)process.exit(r.status??1);
}
const r=spawnSync(process.execPath,['--test',...names.map(name=>path.join(ROOT,'test',name+'.test.mjs'))],{stdio:'inherit',cwd:ROOT,windowsHide:true});process.exitCode=r.status??1;
