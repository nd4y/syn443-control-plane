const $=id=>document.getElementById(id);
let authenticated=false,busy=false,pending=null,revision=0,opened=null,next='',listedOwner='';
const formFields=['draft-id','target-kind','target-id','base-revision','base-hash','plan'];
function status(message){$('status').textContent=message;}
function controls(){
 $('login').disabled=busy||authenticated;$('logout').disabled=busy||!authenticated;
 for(const id of ['load-sources','open-draft','save-draft','new-draft'])$(id).disabled=busy||!authenticated||!!pending;
 $('more-sources').disabled=busy||!authenticated||!next||!!pending;
 for(const id of ['owner',...formFields])$(id).disabled=busy||!authenticated||!!pending;
 $('pending').hidden=!pending;for(const id of ['retry-save','discard-save'])$(id).disabled=busy||!authenticated;
 for(const button of $('sources').querySelectorAll('button'))button.disabled=busy||!authenticated;
}
function erase(){pending=null;revision=0;opened=null;next='';listedOwner='';for(const id of ['owner','draft-id','target-id','base-hash','plan'])$(id).value='';$('target-kind').value='device';$('base-revision').value='0';$('draft-version').textContent='Новый черновик';for(const id of ['sources','profiles','source-details'])$(id).replaceChildren();}
async function request(path,body){
 const raw=typeof body==='string'?body:JSON.stringify(body);
 if(new TextEncoder().encode(raw).length>278528)throw Error('size');
 const response=await fetch(path,{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',headers:{'Content-Type':'application/json','X-Syn443-CSRF':'1'},body:raw});
 if(response.status===401||response.status===403){authenticated=false;erase();throw Error(response.status===401?'login':'denied');}
 if(!response.ok)throw Error(response.status===409?'conflict':response.status===400?'invalid':'network');
 return response.json();
}
const envelope=(action,payload)=>JSON.stringify({version:1,action,requestId:crypto.randomUUID(),payload});
const action=(name,payload)=>request('/control/action',envelope(name,payload));
async function work(fn){if(busy)return;busy=true;controls();try{await fn();}catch(error){status(({login:'Сессия завершена. Войдите снова.',denied:'Доступ отозван или недостаточно прав.',conflict:'Версия изменилась. Откройте текущий черновик перед новой правкой.',invalid:'Проверьте поля и структуру плана.',size:'План превышает допустимый размер.'})[error.message]||'Сервер недоступен. Правка остаётся только в памяти этой вкладки.');}finally{busy=false;controls();}}
function textItem(list,text){const item=document.createElement('li');item.textContent=text;list.append(item);return item;}
function showDraft(draft){
 if(!Number.isSafeInteger(draft.revision)||draft.revision<1)throw Error('invalid');
 opened={id:draft.id,kind:draft.targetKind,target:draft.targetId};revision=draft.revision;
 $('draft-id').value=draft.id;$('target-kind').value=draft.targetKind;$('target-id').value=draft.targetId;
 $('base-revision').value=String(draft.baseRevision);$('base-hash').value=draft.baseHash;$('plan').value=JSON.stringify(draft.plan,null,2);
 $('draft-version').textContent=`Версия черновика: ${draft.revision}`;
}
async function sources(more=false){
 const owner=$('owner').value.trim();if(!owner)throw Error('invalid');
 if(more&&owner!==listedOwner)throw Error('invalid');
 const page=await action('source.list',{owner,after:more?next:''});
 if(!Array.isArray(page.sources)||typeof page.next!=='string')throw Error('invalid');
 if(!more){$('sources').replaceChildren();$('profiles').replaceChildren();$('source-details').replaceChildren();}
 listedOwner=owner;next=page.next;
 for(const source of page.sources){
  const li=textItem($('sources'),`${source.name} (${source.id}) · ${source.state} · v${source.revision}`);
  const button=document.createElement('button');button.textContent='Показать профили';button.onclick=()=>work(async()=>{
   const view=await action('source.snapshot',{id:source.id,snapshot:source.activeSnapshot||''});
   if(!Array.isArray(view.profiles))throw Error('invalid');$('profiles').replaceChildren();
   for(const profile of view.profiles)textItem($('profiles'),`${profile.name} · ${profile.kind} · ${profile.id}`);
   $('source-details').textContent=JSON.stringify({sourceId:source.id,revision:source.revision,networkModes:source.networkModes,snapshot:view.snapshot.id,observedAt:view.snapshot.observedAt,validUntil:view.snapshot.validUntil},null,2);
   status('Метаданные профилей загружены. Учётные данные прокси не выводятся.');
  });li.append(document.createElement('br'),button);
 }
 status(page.sources.length?'Источники загружены.':'Источников для этого пользователя нет.');
}
async function openDraft(){const id=$('draft-id').value.trim();if(!id)throw Error('invalid');showDraft(await action('configuration.draft.get',{id}));status('Личный черновик загружен. VPN не изменён.');}
async function save(){
 if(pending)throw Error('invalid');
 const id=$('draft-id').value.trim(),kind=$('target-kind').value,target=$('target-id').value.trim(),base=Number($('base-revision').value);
 if(!id||!target||!Number.isSafeInteger(base)||base<0||opened&&(opened.id!==id||opened.kind!==kind||opened.target!==target))throw Error('invalid');
 let plan;try{plan=JSON.parse($('plan').value);}catch{throw Error('invalid');}
 const draft=JSON.stringify({id,revision,targetKind:kind,targetId:target,baseRevision:base,baseHash:$('base-hash').value.trim(),savedAt:0});
 const raw=JSON.stringify({version:1,action:'configuration.draft.put',requestId:crypto.randomUUID()}).slice(0,-1)+',"payload":{"draft":'+draft.slice(0,-1)+',"plan":'+$('plan').value+'}}}';
 if(new TextEncoder().encode(raw).length>278528)throw Error('size');
 pending=raw;await retry();
}
async function retry(){if(!pending)throw Error('invalid');let result;try{result=await request('/control/action',pending);}catch(error){if(error.message==='invalid')pending=null;throw error;}showDraft(result);pending=null;status('Черновик сохранён. Политики устройств не изменены.');}
$('login').onclick=()=>work(async()=>{const result=await request('/login',{});const target=new URL(result.url);if(target.protocol!=='https:'&&!(location.hostname==='127.0.0.1'&&target.protocol==='http:'&&target.hostname==='127.0.0.1'))throw Error('invalid');location.assign(target.href);});
$('logout').onclick=()=>work(async()=>{try{await request('/logout',{});}finally{authenticated=false;erase();}status('Вы вышли. Локальная копия черновика очищена.');});
$('load-sources').onclick=()=>work(()=>sources());$('more-sources').onclick=()=>work(()=>sources(true));$('open-draft').onclick=()=>work(openDraft);
$('new-draft').onclick=()=>work(async()=>{revision=0;opened=null;$('draft-id').value=crypto.randomUUID();$('target-kind').value='device';$('target-id').value='';$('base-revision').value='0';$('base-hash').value='';$('plan').value='';$('draft-version').textContent='Новый черновик';status('Новый личный черновик. Выберите адресата и заполните план.');});
$('draft-form').onsubmit=event=>{event.preventDefault();work(save);};$('retry-save').onclick=()=>work(retry);
$('discard-save').onclick=()=>work(async()=>{pending=null;await openDraft();});
controls();work(async()=>{await request('/session',{});authenticated=true;status('Вы вошли. Выберите пользователя или откройте личный черновик.');});
