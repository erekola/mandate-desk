const canvas=document.getElementById('demo-canvas'),ctx=canvas.getContext('2d');
const button=document.getElementById('record-demo'),status=document.getElementById('recording-status');
const copy=await(await fetch('/demo-copy.json')).json();
document.getElementById('demo-title').textContent=copy.title;document.getElementById('demo-help').textContent=copy.help;button.textContent=copy.start;
let csrf,current,focusOperation,stage=0;
const pretty=n=>{const x=BigInt(n);return (x/1000000n).toString()+(x%1000000n?','+(x%1000000n).toString().padStart(6,'0').replace(/0+$/,''):'')};
function lines(text,x,y,width,size=32,color='#1b322b'){
 ctx.font=`${size}px Arial`;ctx.fillStyle=color;let line='';for(const word of text.split(' ')){const next=line?line+' '+word:word;if(ctx.measureText(next).width>width&&line){ctx.fillText(line,x,y);y+=size*1.4;line=word}else line=next}ctx.fillText(line,x,y);return y+size*1.4;
}
function draw(){
 ctx.fillStyle='#f4f5ee';ctx.fillRect(0,0,1600,900);ctx.fillStyle='#214e40';ctx.fillRect(0,0,1600,16);
 ctx.font='bold 34px Arial';ctx.fillStyle='#214e40';ctx.fillText(copy.brand,72,84);ctx.font='bold 22px Arial';ctx.fillText(copy.mode,1240,80);
 ctx.font='20px Arial';ctx.fillStyle='#68776e';ctx.fillText(`${stage+1} / ${copy.steps.length}`,72,143);
 const step=copy.steps[stage];let y=lines(step.title,72,208,1430,52);y=lines(step.body,72,y+30,1410,34);lines(step.detail,72,y+18,1410,26,'#52665b');
 if(current){const stats=[[copy.balance,pretty(current.ledger.principalBalance)+' MDT'],[copy.used,pretty(current.policy.used)+' MDT'],[copy.remaining,pretty((BigInt(current.policy.maxCumulative)-BigInt(current.policy.used)).toString())+' MDT']];stats.forEach(([label,value],i)=>{const x=72+i*500;ctx.fillStyle='#e5ede5';ctx.fillRect(x,500,460,125);lines(label,x+22,539,420,23);ctx.font='bold 40px Arial';ctx.fillStyle='#214e40';ctx.fillText(value,x+22,593)})}
 if(focusOperation){ctx.font='21px Arial';ctx.fillStyle='#52665b';ctx.fillText(copy.planHash,72,685);ctx.font='23px monospace';ctx.fillStyle='#183f30';ctx.fillText(focusOperation.planHash,72,728)}
 ctx.font='23px Arial';ctx.fillStyle='#52665b';ctx.fillText(copy.transaction,72,798);ctx.fillText(copy.footer,72,850);
}
draw();
async function post(route,body){const response=await fetch(route,{method:'POST',headers:{'content-type':'application/json','x-mandate-csrf':csrf},body:JSON.stringify(body)});const data=await response.json();if(!response.ok)throw Error(data.error??'HTTP');current=data.state;return data.result}
function ensure(value){if(!value)throw Error('DEMO_RESULT_MISMATCH')}
async function plan(amount){const op=await post('/api/plan',{operationId:crypto.randomUUID(),transfers:[{to:current.policy.recipients[0],amount}]});await post('/api/preflight',{operationId:op.id});return current.operations.find(x=>x.id===op.id)}
async function accepted(amount){const op=await plan(amount);ensure(op.status==='checked');await post('/api/approve',{operationId:op.id,planHash:op.planHash});const out=await post('/api/execute',{operationId:op.id,planHash:op.planHash});ensure(out.status==='simulated');return out}
async function denied(amount,reason){const balance=current.ledger.principalBalance;const op=await plan(amount);ensure(op.status==='blocked'&&op.receipt.reason===reason&&current.ledger.principalBalance===balance);return op}
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
button.addEventListener('click',async()=>{
 if(button.disabled)return;button.disabled=true;let recorder,stream,captureTick;const chunks=[];const observations=[];
 try{
  const mime=['video/webm;codecs=vp9','video/webm;codecs=vp8','video/webm'].find(x=>typeof MediaRecorder!=='undefined'&&MediaRecorder.isTypeSupported(x));
  if(!mime||typeof canvas.captureStream!=='function'){status.textContent=copy.unsupported;return}
  ({csrf}=await(await fetch('/api/session')).json());current=await(await fetch('/api/state')).json();const initialBalance=current.ledger.principalBalance;ensure(BigInt(initialBalance)>=80000000n);
  status.textContent=copy.recording;stream=canvas.captureStream(10);recorder=new MediaRecorder(stream,{mimeType:mime,videoBitsPerSecond:12000000});recorder.addEventListener('dataavailable',e=>{if(e.data.size)chunks.push(e.data)});
  captureTick=setInterval(()=>stream.getVideoTracks()[0]?.requestFrame?.(),100);
  const stopped=new Promise(resolve=>recorder.addEventListener('stop',resolve,{once:true}));recorder.start(1000);
  let first;
  for(stage=0;stage<copy.steps.length;stage++){
   if(stage===1)await post('/api/grant',{maxTransaction:'60',maxCumulative:'100',recipients:current.policy.recipients});
   if(stage===2){first=await plan('30');ensure(first.status==='checked');focusOperation=first}
   if(stage===3){await post('/api/approve',{operationId:first.id,planHash:first.planHash});first=await post('/api/execute',{operationId:first.id,planHash:first.planHash});ensure(first.status==='simulated');focusOperation=first}
   if(stage===4){const balance=current.ledger.principalBalance;const again=await post('/api/execute',{operationId:first.id,planHash:first.planHash});ensure(JSON.stringify(again.receipt)===JSON.stringify(first.receipt)&&current.ledger.principalBalance===balance);focusOperation=again}
   if(stage===5)focusOperation=await denied('80','TRANSACTION_LIMIT');
   if(stage===6){await accepted('50');focusOperation=await denied('25','CUMULATIVE_LIMIT');ensure(current.policy.used==='80000000')}
   if(stage===7){await post('/api/revoke',{});focusOperation=await denied('1','POLICY_ACTIVE');ensure(!current.policy.active)}
   if(stage===8)ensure(BigInt(initialBalance)-BigInt(current.ledger.principalBalance)===80000000n);
   draw();observations.push({stage,title:copy.steps[stage].title,balance:current.ledger.principalBalance,used:current.policy.used,active:current.policy.active,operation:focusOperation?.id??null});await delay(copy.steps[stage].seconds*1000);
  }
  clearInterval(captureTick);recorder.stop();await stopped;stream.getTracks().forEach(track=>track.stop());const blob=new Blob(chunks,{type:'video/webm'});
  const response=await fetch('/api/demo-recording',{method:'POST',headers:{'content-type':'video/webm','x-mandate-csrf':csrf},body:blob});ensure(response.ok);const saved=await response.json();
  status.textContent=copy.saved+' '+saved.name;status.dataset.result=JSON.stringify({saved,observations,initialBalance,finalBalance:current.ledger.principalBalance});
 }catch{if(recorder?.state==='recording')recorder.stop();stream?.getTracks().forEach(track=>track.stop());status.textContent=copy.failed}
 finally{clearInterval(captureTick);button.disabled=false;stage=Math.min(stage,copy.steps.length-1)}
});
