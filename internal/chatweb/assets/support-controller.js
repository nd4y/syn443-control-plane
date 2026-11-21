// One controller for standalone and PatternFly support surfaces. Server checks
// remain authoritative; visibility and retry state grant no permissions.
export function mountSupportChat({prefix='',embedded=false,visible=()=>!document.hidden}={}) {
const $=id=>document.getElementById(prefix+id);
const MAX=25*1024*1024,CHUNK=256*1024;
const actions=new Set(['self','inbox','messages','send','read','uploads/begin','uploads/part','uploads/status','uploads/complete','uploads/cancel','download']);
const wireId=/^[0-9a-f]{32}$/;
const fileTypes=new Set(['application/pdf','application/zip','text/plain','image/jpeg','image/png','image/webp','video/mp4']);
function confirmsMessage(receipt, draft, uploaded) {
 if(!receipt || typeof receipt.id!=='string' || !wireId.test(receipt.id) ||
    receipt.conversation!==draft.conversation || receipt.clientId!==draft.clientId || receipt.text!==draft.text ||
    !Number.isSafeInteger(receipt.sequence) || receipt.sequence<1 ||
    !Array.isArray(receipt.attachments) || receipt.attachments.length!==uploaded.size) return false;
 const remaining=new Map(uploaded);
 for(const file of receipt.attachments) {
  const expected=remaining.get(file?.id);
  if(!expected || ['name','mime','kind','size','sha256'].some(field=>file[field]!==expected[field])) return false;
  remaining.delete(file.id);
 }
 return remaining.size===0;
}
let preparedURL='',preparedTimer=null;
function releasePrepared(){if(preparedTimer)clearTimeout(preparedTimer);preparedTimer=null;if(preparedURL)URL.revokeObjectURL(preparedURL);preparedURL='';$('download-ready').replaceChildren();}
let authenticated=false,thread='',messages=[],inbox=[],pending=null,busy=false,epoch=0,nextPoll=0;
let historyPage=null,olderEnd=false,newerEnd=false,inboxPage=null,moreInbox=false,inboxEnd=null;
let workEpoch=null,authorityRequired=false,failures=0,manualAt=0,destroyed=false;
const requests=new Set();
const id=()=>crypto.randomUUID().replaceAll('-','');
const hex=bytes=>Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
const hash=async bytes=>hex(await crypto.subtle.digest('SHA-256',bytes));
function base64(bytes){let value='';for(let i=0;i<bytes.length;i+=8192)value+=String.fromCharCode(...bytes.subarray(i,i+8192));return btoa(value);}
function unbase64(value){if(typeof value!=='string'||value.length>349528)throw Error('invalid');return Uint8Array.from(atob(value),c=>c.charCodeAt(0));}
function status(text){$('status').textContent=text;}
function resetHistory(){messages=[];historyPage=null;olderEnd=false;newerEnd=false;}
function forget(){if(embedded)$('empty').hidden=true;releasePrepared();epoch++;authenticated=false;thread='';resetHistory();inbox=[];inboxPage=null;inboxEnd=null;moreInbox=false;pending=null;$('text').value='';$('file').value='';$('attachment').textContent='';$('messages').replaceChildren();$('inbox').replaceChildren();$('thread-title').textContent='Выберите диалог';}
function controls(){
 if(embedded)$('retry').disabled=busy||Date.now()<manualAt;
 for(const name of ['text','file','send'])$(name).disabled=!authenticated||!thread||busy||!!pending&&name!=='send';
 $('send').disabled||=!pending&&!$('text').value.trim()&&!$('file').files.length;
 $('discard').disabled=busy||!pending;$('login').disabled=authenticated||busy;$('logout').disabled=!authenticated||busy;
 $('older').disabled=busy||!messages.length||olderEnd;
 $('newer').hidden=$('latest').hidden=!historyPage;
 $('newer').disabled=busy||!messages.length||newerEnd;$('latest').disabled=busy;
 $('more').disabled=!authenticated||busy||!moreInbox;
 $('inbox-first').hidden=!inboxPage;$('inbox-first').disabled=busy;
}
async function request(path,body={}){
 if(destroyed||workEpoch!==epoch||!visible())throw Error('stale');
 const current=epoch,controller=new AbortController();requests.add(controller);
 const timer=setTimeout(()=>controller.abort(),25000);
 try{
 const response=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'Content-Type':'application/json','X-Syn443-CSRF':'1'},body:JSON.stringify(body),signal:controller.signal});
 if(current!==epoch)throw Error('stale');
 if(response.status===401){forget();controls();throw Error('auth');}
 if(response.status===403){forget();controls();throw Error('denied');}
 if(response.status===429){nextPoll=Date.now()+60000;throw Error('rate');}
 if(!response.ok)throw Error(response.status===403?'denied':'unavailable');
 const reader=response.body.getReader(),chunks=[];let count=0;
 try{while(true){const {done,value}=await reader.read();if(done)break;count+=value.byteLength;if(count>524288)throw Error('invalid');chunks.push(value);}}
 finally{await reader.cancel();}
 const bytes=new Uint8Array(count);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.length;}
 if(current!==epoch||workEpoch!==epoch)throw Error('stale');
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }finally{clearTimeout(timer);requests.delete(controller);}
}
const api=(action,body)=>{if(!actions.has(action))throw Error('invalid');return request('/chat/'+action,body);};
async function work(fn){
 if(busy||destroyed||!visible())return;
 const started=epoch;busy=true;workEpoch=started;controls();
 try{await fn();if(started===epoch){failures=0;nextPoll=Date.now()+10000;}}
 catch(e){if(started!==epoch&&e.message!=='auth'&&e.message!=='denied')return;
  if(e.message==='auth'||e.message==='denied'){authorityRequired=true;nextPoll=Infinity;}
  else{failures=Math.min(failures+1,4);nextPoll=Math.max(nextPoll,Date.now()+Math.min(60000*2**(failures-1),300000));}
  status(e.message==='auth'?'Войдите снова.':e.message==='denied'?'Доступ к чату не разрешён.':e.message==='rate'?'Слишком много запросов. Повторите через минуту.':'Не удалось завершить операцию. Можно повторить.');
 }finally{busy=false;workEpoch=null;$('progress').hidden=true;if(started!==epoch&&!authenticated)forget();controls();}
}
async function openConversation(row){
 if(pending||$('text').value.trim()||$('file').files.length){status('Сначала отправьте или удалите текущий черновик.');return;}
 if(thread!==row.id){
  releasePrepared();
  resetHistory();
  $('messages').replaceChildren();
  $('text').value='';
  $('file').value='';
  $('attachment').textContent='';
  thread=row.id;
 }
 $('thread-title').textContent='Диалог '+row.owner.slice(0,10);
 status('Загрузка переписки…');
 await refresh();
 status('На связи.');
}
function renderInbox(){if(embedded)$('empty').hidden=inbox.length>0;const list=$('inbox');list.replaceChildren();for(const row of inbox){const li=document.createElement('li'),button=document.createElement('button');if(embedded)button.className='pf-v6-c-button pf-m-link';button.textContent='Пользователь '+row.owner.slice(0,10)+(row.lastSeq>row.readSeq?' - новые':'');button.onclick=()=>work(()=>openConversation(row));li.append(button);list.append(li);}}
function renderMessages(peerRead){const list=$('messages');const nearEnd=list.scrollHeight-list.scrollTop-list.clientHeight<80;list.replaceChildren();for(const msg of messages){const li=document.createElement('li');li.className='message'+(msg.senderRole==='admin'?' admin':'');const role=document.createElement('div');role.className='meta';role.textContent=msg.senderRole==='admin'?'Администратор':'Пользователь';const text=document.createElement('div');text.textContent=msg.text;li.append(role,text);for(const file of msg.attachments){const button=document.createElement('button');if(embedded)button.className='pf-v6-c-button pf-m-link';button.textContent='Скачать: '+file.name+' ('+Math.ceil(file.size/1024)+' КБ)';button.onclick=()=>work(()=>download(file));li.append(button);}const date=document.createElement('div');date.className='meta';date.textContent=new Date(msg.createdAt*1000).toLocaleString()+(msg.sequence<=peerRead?' - прочитано':'');li.append(date);list.append(li);}if(nearEnd)list.scrollTop=list.scrollHeight;}
async function refresh(action='poll'){
 if(!thread)return;
 let page=historyPage;
 if(action==='older')page={before:messages[0].sequence,after:0};
 if(action==='newer')page={before:0,after:messages.at(-1).sequence};
 if(action==='latest')page=null;
 const tail=action==='poll'&&!page?messages.at(-1)?.sequence:0;
 const response=await api('messages',{conversation:thread,before:page?.before||0,after:page?.after||tail||0});
 if(!response.messages.length&&(action==='older'||action==='newer')){
  if(action==='older')olderEnd=true;else newerEnd=true;
  return;
 }
 if(action!=='poll'){olderEnd=false;newerEnd=false;}
 historyPage=page;
 const items=new Map(tail?messages.map(m=>[m.id,m]):[]);
 for(const item of response.messages)items.set(item.id,item);
 if(tail&&items.size>200)olderEnd=false;
 messages=[...items.values()].sort((a,b)=>a.sequence-b.sequence).slice(-200);
 if(page?.before&&response.messages.length<20)olderEnd=true;
 if(page?.after&&response.messages.length<20)newerEnd=true;
 renderMessages(response.peerRead);
 if(!page&&!document.hidden&&messages.length)await api('read',{conversation:thread,sequence:messages.at(-1).sequence});
}
async function loadInbox(action='poll'){
 const page=action==='more'?inbox.at(-1):action==='first'?null:inboxPage;
 const rows=await api('inbox',{before:page?.updatedAt||0,beforeId:page?.id||''});
 if(action==='first')inboxEnd=null;
 if(action==='more'&&!rows.length){inboxEnd=page;moreInbox=false;return;}
 const last=rows.at(-1);
 moreInbox=rows.length===50&&!(last.id===inboxEnd?.id&&last.updatedAt===inboxEnd.updatedAt);
 inboxPage=page?{updatedAt:page.updatedAt,id:page.id}:null;
 inbox=rows;
 renderInbox();
}
async function boot(){await request('/session');authenticated=true;const own=await api('self');if(!own.admin){forget();throw Error('denied');}await loadInbox();status('Выберите диалог.');}
$('login').onclick=()=>work(async()=>{const result=await request('/login');const url=new URL(result.url);if(url.protocol!=='https:'&&url.hostname!=='127.0.0.1')throw Error('invalid');location.assign(url.href);});
$('logout').onclick=()=>work(async()=>{await request('/logout');forget();status('Сессия завершена.');});
for(const action of ['older','newer','latest'])$(action).onclick=()=>work(()=>refresh(action));
$('more').onclick=()=>work(()=>loadInbox('more'));
$('inbox-first').onclick=()=>work(()=>loadInbox('first'));
$('text').oninput=controls;
$('file').onchange=()=>{$('attachment').textContent=Array.from($('file').files).map(f=>f.name+' ('+Math.ceil(f.size/1024)+' КБ)').join(', ');controls();};
$('discard').onclick=()=>{pending=null;status('Локальная попытка удалена. Уже доставленное сообщение остаётся у собеседника.');controls();};
$('compose').onsubmit=e=>{e.preventDefault();work(async()=>{
 if(!pending){const text=$('text').value,files=Array.from($('file').files);if([...text].length>4096||new TextEncoder().encode(text).length>16384||text.includes('\0')||!text.trim()&&!files.length||files.length>4||files.some(f=>!f.size||f.size>MAX))throw Error('invalid');pending={clientId:id(),conversation:thread,text,files:files.map(file=>({file,clientId:id(),sha256:null}))};}
 const uploaded=new Map();
 for(const item of pending.files) {
  const file=item.file;
  if(!item.sha256)item.sha256=await hash(await file.arrayBuffer());
  const metadata={name:file.name,mime:fileTypes.has(file.type)?file.type:'application/octet-stream',kind:'file',size:file.size,sha256:item.sha256};
  const result=await api('uploads/begin',{conversation:pending.conversation,clientId:item.clientId,...metadata});
  const upload=result?.attachment?.id;
  if(typeof upload!=='string'||!wireId.test(upload)||uploaded.has(upload))throw Error('invalid');
  if(!result.complete) {
   const parts=new Set(result.parts),count=Math.ceil(file.size/CHUNK);
   $('progress').hidden=false;
   for(let part=0;part<count;part++) {
    if(!parts.has(part)) {
     const data=new Uint8Array(await file.slice(part*CHUNK,(part+1)*CHUNK).arrayBuffer());
     await api('uploads/part',{upload,part,data:base64(data),sha256:await hash(data)});
    }
    $('progress').value=(part+1)*100/count;
   }
   await api('uploads/complete',{upload});
  }
  uploaded.set(upload,metadata);
 }
 const reply=await api('send',{conversation:pending.conversation,clientId:pending.clientId,text:pending.text,attachments:[...uploaded.keys()]});
 if(!confirmsMessage(reply,pending,uploaded))throw Error('invalid');
 pending=null;$('text').value='';$('file').value='';$('attachment').textContent='';status('Отправлено.');await refresh(historyPage?'latest':'poll');
 });};
async function download(file){const conversation=thread,started=epoch;if(!Number.isSafeInteger(file.size)||file.size<1||file.size>MAX)throw Error('invalid');const all=new Uint8Array(file.size);$('progress').hidden=false;for(let part=0;part<Math.ceil(file.size/CHUNK);part++){const result=await api('download',{attachment:file.id,part}),data=unbase64(result.data);if(data.length!==Math.min(CHUNK,file.size-part*CHUNK)||await hash(data)!==result.sha256)throw Error('invalid');all.set(data,part*CHUNK);$('progress').value=Math.min(100,(part+1)*CHUNK*100/file.size);}if(await hash(all)!==file.sha256)throw Error('invalid');
 if(destroyed||!authenticated||!visible()||started!==epoch||thread!==conversation)throw Error('stale');
 releasePrepared();preparedURL=URL.createObjectURL(new Blob([all],{type:'application/octet-stream'}));const a=document.createElement('a');a.href=preparedURL;a.download=file.name;a.rel='noopener';a.textContent='Сохранить файл: '+file.name;$('download-ready').append(a);preparedTimer=setTimeout(releasePrepared,120000);status('Файл проверен. Нажмите ссылку для сохранения.');}
function resume(){
 if(destroyed||!visible()||busy||authorityRequired||Date.now()<nextPoll)return;
 void work(async()=>{if(!authenticated)await boot();else await loadInbox();await refresh();status(pending?'Связь восстановлена. Повторите отправку.':thread?'На связи.':'Выберите диалог.');});
}
function suspend(){epoch++;for(const request of requests)request.abort();releasePrepared();}
function clear(){suspend();forget();authorityRequired=false;failures=0;nextPoll=0;manualAt=0;controls();}
function visibility(){if(document.hidden)suspend();else resume();}
if(embedded){$('retry').onclick=()=>{if(Date.now()<manualAt||busy)return;manualAt=Date.now()+30000;authorityRequired=false;nextPoll=0;resume();};}
const timer=setInterval(()=>{if(embedded)$('retry').disabled=busy||Date.now()<manualAt;resume();},10000);
document.addEventListener('visibilitychange',visibility);
controls();if(!embedded)resume();
return {resume,suspend,clear,dispose(){destroyed=true;suspend();forget();clearInterval(timer);document.removeEventListener('visibilitychange',visibility);}};
}
