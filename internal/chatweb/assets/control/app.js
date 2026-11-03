const $=id=>document.getElementById(id);
let authenticated=false,busy=false,pending=null,revision=0,opened=null,next='',listedOwner='';
let pendingKind='draft',sourceRevision=0,sourceIdentity=null,sourceJob='';
const sourceFields=['source-id','source-owner','source-name','source-mode','source-format','source-resource','source-external','source-until','source-refresh','source-stale','source-modes','source-enabled','source-secret-operation','source-secret'];
const formFields=['draft-id','target-kind','target-id','base-revision','base-hash','plan'];
function status(message){$('status').textContent=message;}
function controls(){
 $('login').disabled=busy||authenticated;$('logout').disabled=busy||!authenticated;
 for(const id of ['load-sources','load-inventory','open-draft','save-draft','new-draft','new-source','save-source'])$(id).disabled=busy||!authenticated||!!pending;
 for(const id of sourceFields)$(id).disabled=busy||!authenticated||!!pending||sourceIdentity&&['source-id','source-owner'].includes(id);
 $('sync-source').disabled=busy||!authenticated||!!pending||!sourceIdentity;$('source-job').disabled=busy||!authenticated||!!pending||!sourceJob;
 $('more-sources').disabled=busy||!authenticated||!next||!!pending;
 for(const id of ['owner','inventory-device',...formFields])$(id).disabled=busy||!authenticated||!!pending;
 $('pending').hidden=!pending;for(const id of ['retry-save','discard-save'])$(id).disabled=busy||!authenticated;
 for(const button of $('sources').querySelectorAll('button'))button.disabled=busy||!authenticated||!!pending;
 $('source-secret').disabled=busy||!authenticated||!!pending||$('source-secret-operation').value!=='replace';
 if(!['server','resource'].includes($('source-mode').value))$('sync-source').disabled=true;
}
function erase(){pending=null;revision=0;opened=null;next='';listedOwner='';clearSource();for(const id of ['owner','inventory-device','draft-id','target-id','base-hash','plan'])$(id).value='';$('target-kind').value='device';$('base-revision').value='0';$('draft-version').textContent='Новый черновик';for(const id of ['sources','profiles','source-details','inventory-meta','inventory-layers','inventory-effective','inventory-fields','inventory-restrictions'])$(id).replaceChildren();$('inventory-state').textContent='';$('inventory-view').hidden=true;}
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
function inventoryPair(list,name,value){const term=document.createElement('dt');term.textContent=name;const detail=document.createElement('dd');detail.textContent=value;list.append(term,detail);}
function inventoryOrigin(origin){return origin&&typeof origin==='object'&&!Array.isArray(origin)&&typeof origin.layerId==='string'&&typeof origin.kind==='string'&&Number.isSafeInteger(origin.revision)&&origin.revision>=0;}
function inventoryDate(milliseconds){const date=new Date(milliseconds);if(!Number.isFinite(date.getTime()))throw Error('invalid');return date.toISOString();}
function showInventory(view){
 if(!view||typeof view!=='object'||Array.isArray(view))throw Error('invalid');
 const {device,owner,state,revision,hash,policyRevision,layers,effective}=view;
 if(typeof device!=='string'||!device||device.length>64||typeof owner!=='string'||!['assigned','unassigned','expired'].includes(state)||!Number.isSafeInteger(revision)||revision<0||typeof hash!=='string'||hash.length>64||!Number.isSafeInteger(policyRevision)||policyRevision<0||!Array.isArray(layers)||effective!==undefined&&effective!==null&&(typeof effective!=='object'||Array.isArray(effective)))throw Error('invalid');
 const assigned=state==='assigned'||state==='expired';
 if(!assigned&&(revision!==0||hash!==''||layers.length||effective))throw Error('invalid');
 if(assigned&&(revision<1||!/^[0-9a-f]{64}$/.test(hash)||!effective||typeof view.mode!=='string'||!view.mode||!Number.isSafeInteger(view.approvalUntilMs)||view.approvalUntilMs<1))throw Error('invalid');
 $('inventory-state').textContent=`Состояние назначения: ${{assigned:'Назначена',unassigned:'Не назначена',expired:'Истекла'}[state]}`;
 const meta=$('inventory-meta');meta.replaceChildren();
 inventoryPair(meta,'Устройство',device);inventoryPair(meta,'Владелец',owner);
 inventoryPair(meta,'Желаемая версия',String(revision));inventoryPair(meta,'Хэш желаемой конфигурации',hash||'-');
 inventoryPair(meta,'Версия выданной политики',String(policyRevision));
 if(assigned){inventoryPair(meta,'Режим сети',view.mode);if(view.approvalUntilMs>0)inventoryPair(meta,'Подтверждение действительно до',inventoryDate(view.approvalUntilMs));}
 const layerList=$('inventory-layers');layerList.replaceChildren();
 for(const layer of layers){
  if(!layer||typeof layer!=='object'||Array.isArray(layer)||typeof layer.id!=='string'||typeof layer.kind!=='string'||!Number.isSafeInteger(layer.priority)||!Number.isSafeInteger(layer.revision)||layer.revision<1||layer.changes!=null&&!Array.isArray(layer.changes)||layer.permissions!=null&&!Array.isArray(layer.permissions))throw Error('invalid');
  textItem(layerList,`${layer.kind} · ${layer.id} · приоритет ${layer.priority} · версия ${layer.revision} · изменений ${layer.changes?.length||0} · разрешений ${layer.permissions?.length||0}`);
 }
 if(!layerList.children.length)textItem(layerList,'Наследованные слои отсутствуют.');
 const documentNode=$('inventory-effective');
 if(effective){if(effective.document===undefined)throw Error('invalid');documentNode.textContent=JSON.stringify(effective.document,null,2);}else documentNode.textContent='Нет действующих настроек.';
 const fieldList=$('inventory-fields');fieldList.replaceChildren();
 const origins=effective&&effective.fields;
 if(origins!==undefined&&origins!==null&&(typeof origins!=='object'||Array.isArray(origins)))throw Error('invalid');
 if(origins)for(const path of Object.keys(origins)){
  const origin=origins[path];if(!inventoryOrigin(origin))throw Error('invalid');
  textItem(fieldList,`${path} ← ${origin.kind} · ${origin.layerId} · версия ${origin.revision}`);
 }
 if(!fieldList.children.length)textItem(fieldList,'Источники полей не возвращены.');
 const restrictionList=$('inventory-restrictions');restrictionList.replaceChildren();
 const restrictions=effective&&effective.restrictions;
 if(restrictions!==undefined&&restrictions!==null&&!Array.isArray(restrictions))throw Error('invalid');
 for(const restriction of restrictions||[]){
  const permission=restriction&&restriction.permission,origin=restriction&&restriction.origin;
  if(!permission||typeof permission!=='object'||Array.isArray(permission)||typeof permission.path!=='string'||typeof permission.mode!=='string'||!inventoryOrigin(origin))throw Error('invalid');
  let text=`${permission.path} · режим ${permission.mode}`;
  if(Array.isArray(permission.choices))text+=` · вариантов ${permission.choices.length}`;
  if(Number.isSafeInteger(permission.minimum))text+=` · минимум ${permission.minimum}`;
  if(Number.isSafeInteger(permission.maximum))text+=` · максимум ${permission.maximum}`;
  text+=` · источник ${origin.kind} · ${origin.layerId} · версия ${origin.revision}`;
  textItem(restrictionList,text);
 }
 if(!restrictionList.children.length)textItem(restrictionList,'Ограничения не возвращены.');
 $('inventory-view').hidden=false;
}
async function loadInventory(){
 const device=$('inventory-device').value.trim();
 if(!/^[A-Za-z0-9_-]{1,64}$/.test(device))throw Error('invalid');
 $('inventory-view').hidden=true;
 const view=await action('configuration.inventory.get',{id:device});
 if(view.device!==device)throw Error('invalid');
 showInventory(view);
 status('Желаемая конфигурация загружена. Это не проверка связи и не подтверждение активации Android.');
}
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
  });const edit=document.createElement('button');edit.textContent='Настроить источник';edit.onclick=()=>work(async()=>{showSource(await action('source.get',{id:source.id}));status('Параметры загружены. Прежний секрет не возвращается.');});li.append(document.createElement('br'),button,edit);
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
 pendingKind='draft';pending=raw;await retry();
}
async function retry(){if(!pending)throw Error('invalid');let result;try{result=await request('/control/action',pending);}catch(error){if(error.message==='invalid')pending=null;throw error;}if(pendingKind==='source'){showSource(result);status('Источник сохранён. Активные политики меняются отдельной публикацией.');}else if(pendingKind==='sync'){if(typeof result.id!=='string')throw Error('invalid');sourceJob=result.id;$('job-status').textContent=JSON.stringify(result,null,2);status('Задание обновления поставлено в очередь.');}else{showDraft(result);status('Черновик сохранён. Политики устройств не изменены.');}pending=null;}
function clearSource(){sourceRevision=0;sourceIdentity=null;sourceJob='';for(const id of ['source-id','source-owner','source-name','source-resource','source-external','source-until','source-secret'])$(id).value='';$('source-mode').value='server';$('source-format').value='uri';$('source-refresh').value='3600';$('source-stale').value='86400';$('source-enabled').checked=true;$('source-secret-operation').value='keep';for(const option of $('source-modes').options)option.selected=option.value==='wifi';$('source-version').textContent='Источник не выбран';$('job-status').replaceChildren();}
function localDate(seconds){const d=new Date(seconds*1000);if(!Number.isFinite(d.getTime()))throw Error('invalid');return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}
function showSource(s){if(!Number.isSafeInteger(s.revision)||s.revision<1||!Array.isArray(s.networkModes))throw Error('invalid');sourceIdentity={id:s.id,owner:s.owner};sourceRevision=s.revision;sourceJob='';$('source-id').value=s.id;$('source-owner').value=s.owner;$('source-name').value=s.name;$('source-mode').value=s.mode;$('source-format').value=s.format;$('source-resource').value=s.resourceId||'';$('source-external').value=s.externalUserId||'';$('source-until').value=localDate(s.validUntil);$('source-refresh').value=String(s.refreshSeconds);$('source-stale').value=String(s.maxStaleSeconds);$('source-enabled').checked=s.enabled;for(const option of $('source-modes').options)option.selected=s.networkModes.includes(option.value);$('source-secret-operation').value='keep';$('source-secret').value='';$('source-version').textContent=`Версия источника: ${s.revision} · ${s.state}`;$('job-status').replaceChildren();}
async function saveSource(){
 if(pending)throw Error('invalid');const mode=$('source-mode').value,id=$('source-id').value.trim(),owner=$('source-owner').value.trim();
 if(sourceIdentity&&(id!==sourceIdentity.id||owner!==sourceIdentity.owner))throw Error('invalid');
 const source={id,owner,name:$('source-name').value.trim(),mode,format:$('source-format').value,resourceId:mode==='resource'?$('source-resource').value.trim():'',externalUserId:mode==='resource'?$('source-external').value.trim():'',enabled:$('source-enabled').checked,revision:sourceRevision,validUntil:Math.floor(new Date($('source-until').value).getTime()/1000),refreshSeconds:Number($('source-refresh').value),maxStaleSeconds:Number($('source-stale').value),networkModes:[...$('source-modes').selectedOptions].map(o=>o.value)};
 if(!id||!owner||!source.name||!['server','manual','resource'].includes(mode)||!Number.isSafeInteger(source.validUntil)||!source.networkModes.length)throw Error('invalid');
 const operation=$('source-secret-operation').value;let secret=JSON.stringify({operation});
 if(operation==='replace'){try{JSON.parse($('source-secret').value);}catch{throw Error('invalid');}secret='{"operation":"replace","value":'+$('source-secret').value+'}';}
 pendingKind='source';pending=JSON.stringify({version:1,action:'source.put',requestId:crypto.randomUUID()}).slice(0,-1)+',"payload":{"source":'+JSON.stringify(source)+',"secret":'+secret+'}}';await retry();
}
$('login').onclick=()=>work(async()=>{const result=await request('/login',{});const target=new URL(result.url);if(target.protocol!=='https:'&&!(location.hostname==='127.0.0.1'&&target.protocol==='http:'&&target.hostname==='127.0.0.1'))throw Error('invalid');location.assign(target.href);});
$('logout').onclick=()=>work(async()=>{try{await request('/logout',{});}finally{authenticated=false;erase();}status('Вы вышли. Локальная копия черновика очищена.');});
$('load-sources').onclick=()=>work(()=>sources());$('more-sources').onclick=()=>work(()=>sources(true));$('load-inventory').onclick=()=>work(loadInventory);$('open-draft').onclick=()=>work(openDraft);
$('new-draft').onclick=()=>work(async()=>{revision=0;opened=null;$('draft-id').value=crypto.randomUUID();$('target-kind').value='device';$('target-id').value='';$('base-revision').value='0';$('base-hash').value='';$('plan').value='';$('draft-version').textContent='Новый черновик';status('Новый личный черновик. Выберите адресата и заполните план.');});
$('draft-form').onsubmit=event=>{event.preventDefault();work(save);};$('retry-save').onclick=()=>work(retry);
$('discard-save').onclick=()=>work(async()=>{const kind=pendingKind,sourceId=$('source-id').value.trim();pending=null;if(kind==='draft')await openDraft();else if(sourceId)showSource(await action('source.get',{id:sourceId}));});
$('new-source').onclick=()=>work(async()=>{const owner=$('owner').value.trim();clearSource();$('source-id').value=crypto.randomUUID();$('source-owner').value=owner;$('source-until').value=localDate(Math.floor(Date.now()/1000)+30*86400);$('source-version').textContent='Новый источник';status('Заполните параметры. Для нового HTTPS источника укажите новые учётные данные.');});
$('source-form').onsubmit=event=>{event.preventDefault();work(saveSource);};
$('source-secret-operation').onchange=controls;$('source-mode').onchange=controls;
$('sync-source').onclick=()=>work(async()=>{if(pending||!sourceIdentity)throw Error('invalid');pendingKind='sync';pending=envelope('source.sync',{id:sourceIdentity.id,revision:sourceRevision});await retry();});
$('source-job').onclick=()=>work(async()=>{if(!sourceJob)throw Error('invalid');$('job-status').textContent=JSON.stringify(await action('job.get',{id:sourceJob}),null,2);status('Состояние задания обновлено.');});
controls();work(async()=>{await request('/session',{});authenticated=true;status('Вы вошли. Выберите пользователя или откройте личный черновик.');});
