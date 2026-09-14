import fs from 'node:fs';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {boundedPath} from './store.mjs';
export async function saveDemoRecording(request,directory){
  const limit=32*1024*1024, chunks=[];let length=0;
  for await(const chunk of request){length+=chunk.length;if(length>limit)throw Error('RECORDING_SIZE');chunks.push(chunk)}
  const bytes=Buffer.concat(chunks);
  if(bytes.length<16||bytes.subarray(0,4).toString('hex')!=='1a45dfa3')throw Error('RECORDING_FORMAT');
  const recordings=boundedPath(path.join(directory,'recordings'));fs.mkdirSync(recordings,{recursive:true});
  const name='mandate-desk-demo-'+randomUUID()+'.webm';
  const file=boundedPath(path.join(recordings,name));
  const fd=fs.openSync(file,'wx');try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  const result={name,bytes:length,sha256:createHash('sha256').update(bytes).digest('hex'),format:'video/webm',surface:'Mandate Desk demonstration canvas',mode:'simulation',savedAt:new Date().toISOString()};
  fs.writeFileSync(file+'.json',JSON.stringify(result,null,2),{flag:'wx'});
  return result;
}
