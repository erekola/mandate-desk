import fs from 'node:fs';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {boundedPath} from './store.mjs';
// A live recording is bound by the server to one completed run whose evidence
// is complete right now (BrickkenLiveWorkspace.recordingBinding). The client
// never supplies the binding; a live save without one is refused. The metadata
// therefore identifies the run the video shows; it does not vouch for pixels.
function validBinding(binding){
  return binding&&typeof binding==='object'&&!Array.isArray(binding)&&/^live_[a-f0-9]{32}$/.test(binding.runId??'')&&
    /^[a-f0-9]{64}$/.test(binding.approvalSha256??'')&&/^[a-f0-9]{64}$/.test(binding.proposalHash??'')&&
    binding.finality&&binding.finality.allFinalized===true&&Array.isArray(binding.transactions)&&binding.transactions.length>0;
}
export async function saveDemoRecording(request,directory,mode='simulation',binding=null){
  if(mode!=='simulation'&&mode!=='live-run-evidence')throw Error('RECORDING_MODE');
  if(mode==='live-run-evidence'&&!validBinding(binding))throw Error('RECORDING_BINDING');
  if(mode==='simulation'&&binding!==null)throw Error('RECORDING_BINDING');
  const limit=32*1024*1024, chunks=[];let length=0;
  for await(const chunk of request){length+=chunk.length;if(length>limit)throw Error('RECORDING_SIZE');chunks.push(chunk)}
  const bytes=Buffer.concat(chunks);
  if(bytes.length<16||bytes.subarray(0,4).toString('hex')!=='1a45dfa3')throw Error('RECORDING_FORMAT');
  const recordings=boundedPath(path.join(directory,'recordings'));fs.mkdirSync(recordings,{recursive:true});
  const name=(mode==='live-run-evidence'?'mandate-desk-live-run-':'mandate-desk-demo-')+randomUUID()+'.webm';
  const file=boundedPath(path.join(recordings,name));
  const fd=fs.openSync(file,'wx');try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  const result={name,bytes:length,sha256:createHash('sha256').update(bytes).digest('hex'),format:'video/webm',surface:'Mandate Desk demonstration canvas',mode,savedAt:new Date().toISOString(),
    ...(binding===null?{}:{binding:structuredClone(binding),bindingSha256:createHash('sha256').update(JSON.stringify(binding)).digest('hex')})};
  fs.writeFileSync(file+'.json',JSON.stringify(result,null,2),{flag:'wx'});
  return result;
}
