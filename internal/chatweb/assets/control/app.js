import {mergeDeviceProposal} from './layer-merge.js';
const $=id=>document.getElementById(id);
const sourceImportPath='/control/source/import';
const sourceImportBytes=10*1024*1024;
const jobStates={queued:'В очереди',running:'Выполняется',succeeded:'Завершено',failed:'Ошибка',cancelled:'Отменено',dead_letter:'Истёк срок или лимит повторов'};
const recipientKinds={user:'Пользователь',device:'Устройство',group:'Группа'};
let authenticated=false,busy=false,pending=null,revision=0,opened=null,next='',listedOwner='';
let pendingKind='draft',sourceRevision=0,sourceIdentity=null,sourceJob='',sourceHistoryNext='';
let layerInventory=null,layerRevision=0,layerOpened=null,layerSaved=null,layerJob=null,layerPreview=null;
let layerComparison=null;
let layerDraftInventory=null;
let sourceShares=null;
let providerContext=null,providerEpoch=0;
let devicesNext='',deviceIds=new Set();
let reauthenticationAvailable=false,reauthenticationNeeded=false,reauthenticationIssuer='',reauthenticationFocus=false;
let runtimeReport=null,runtimeDeadline=0,runtimeTimer=null,runtimeEpoch=0;
let runtimeRefreshTimer=null,runtimeRequest=null,runtimePolling=false,runtimeLastStarted=0;
let boundsDraft=null,boundsEpoch=0;
let routeProfileEdit=null;
const runtimeRefreshMs=60000;
const sourceFields=['source-id','source-owner','source-name','source-mode','source-device','source-format','source-resource','source-external','source-until','source-refresh','source-stale','source-modes','source-enabled','source-secret-operation','source-secret'];
const formFields=['draft-id','target-kind','target-id','base-revision','base-hash','plan'];
function status(message,tone='info'){
 const banner=$('status');
 banner.textContent=message;
 banner.dataset.tone=tone;
}
function setNavExpanded(expanded){
 $('console-nav-toggle').setAttribute('aria-expanded',String(expanded));
 $('console-shell').classList.toggle('mobile-nav-expanded',expanded);
}
function setDesktopNavExpanded(expanded){
 $('desktop-nav-toggle').setAttribute('aria-expanded',String(expanded));
 $('console-shell').classList.toggle('desktop-nav-collapsed',!expanded);
}
function updateSectionNav(focus=false){
 const links=Array.from($('console-nav').querySelectorAll('a'));
 const current=links.find(link=>link.hash===location.hash)||links[0];
 const heading=$(current.hash.slice(1));
 $('console-nav-current').textContent=current.textContent.trim();
 $('section-context').textContent=current.textContent.trim();
 for(const section of $('workspace').querySelectorAll('.workspace-page')){
  section.hidden=section.getAttribute('aria-labelledby')!==heading.id;
 }
 if(focus&&authenticated){
  if(location.hash==='#workspace')$('workspace').focus({preventScroll:true});
  else heading.focus({preventScroll:true});
  window.scrollTo(0,0);
 }
 syncRuntimeVisibility();
}
function actionButton(){
 const button=document.createElement('button');
 button.className='pf-v6-c-button pf-m-secondary';
 return button;
}
function inventoryBadge(id,text,tone='neutral'){
 const badge=$(id);
 badge.textContent=text;
 badge.dataset.tone=tone;
}
const deviceID=/^[A-Za-z0-9_-]{1,64}$/;
function linkedDevice(){
 const prefix='#device=';
 const id=location.hash.startsWith(prefix)?location.hash.slice(prefix.length):'';
 return deviceID.test(id)?id:'';
}
const confirmedDecision='m4-confirmed-v1';
const routeCheckMethods={tcp:'TCP',tls:'TLS',https_204:'HTTPS 204',https_status:'Код ответа HTTPS',ssh_banner:'SSH banner',https_exit_ip:'IP выхода по HTTPS',https_exit_country:'Страна выхода по HTTPS'};
const exitCountryLabels={RU:'Россия',NON_RU:'За пределами России'};
function sameRouteCheck(a,b){
 return a?.method===b.method&&a.target===b.target&&a.expected_ip===b.expected_ip&&
  a.expected_exit_class===b.expected_exit_class&&a.http_method===b.http_method&&a.expected_status===b.expected_status;
}
function validProbeHTTPS(target){
 if(!/^https:\/\/(?:\[[0-9a-fA-F:.]+\]|[a-z0-9.-]+)(?::[0-9]{1,5})?(?:[/?]|$)/.test(target)||
    /[\\#]|%(?![0-9a-f]{2})/i.test(target))return false;
 try{
  const url=new URL(target);
  return url.port!=='0'&&!url.hostname.endsWith('.');
 }catch{return false;}
}
function routeDraft(){
 const value=JSON.parse($('plan').value),graph=value.graph,network=value.network;
 if(!graph||!network||Array.isArray(graph)||Array.isArray(network)||typeof graph!=='object'||typeof network!=='object')throw Error('invalid');
 const tags=new Set();
 for(const kind of ['profiles','chains','balancers'])for(const tag of Object.keys(graph[kind]||{}))if(/^[A-Za-z0-9_-]{1,64}$/.test(tag))tags.add(tag);
 if(typeof graph.netbird?.tag==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(graph.netbird.tag))tags.add(graph.netbird.tag);
 if(value.adaptive){
  const a=value.adaptive;
  if(typeof a!=='object'||Array.isArray(a)||Object.keys(a).sort().join(',')!=='bindingsB64,groups,metadataB64'||
    typeof a.metadataB64!=='string'||typeof a.bindingsB64!=='string'||!a.groups||typeof a.groups!=='object'||Array.isArray(a.groups))throw Error('invalid');
  const managed=Object.values(a.groups);
  if(managed.length<1||managed.length>16||new Set(managed).size!==managed.length||managed.some(tag=>typeof tag!=='string'||
    !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(tag)||tag==='direct'||tag.startsWith('syn443_')||tags.has(tag)))throw Error('invalid');
  for(const tag of managed)tags.add(tag);
 }
 tags.add('direct');
 const checks=network.routeChecks??[];
 if(!Array.isArray(checks)||checks.length>16||checks.some(row=>{
  if(!row||typeof row.outbound!=='string')return true;
  if(Object.hasOwn(row,'profile'))return Object.hasOwn(row,'checks')||row.profile?.schemaVersion!==2||typeof row.profile.id!=='string';
  return !Array.isArray(row.checks)||row.checks.length>4;
 }))throw Error('invalid');
 return {value,network,tags,checks};
}
function drawRouteChecks(){
 const draft=authenticated?$('plan').value:null;
 if(boundsDraft!==draft){boundsDraft=draft;boundsEpoch++;$('route-bounds-result').replaceChildren();closeRouteProfile();}
 $('route-profile-open').disabled=true;
 $('route-bounds').hidden=true;$('route-bounds-preview').disabled=true;
 const editor=$('route-check-editor'),select=$('route-check-path'),list=$('route-check-list');
 $('route-check-exit').hidden=$('route-check-method').value!=='https_exit_ip';
 $('route-check-http').hidden=$('route-check-method').value!=='https_status';
 $('route-check-country').hidden=$('route-check-method').value!=='https_exit_country';
 $('route-profile-note').hidden=true;
 $('route-check-add').disabled=true;
 const cooldown=$('route-reserve-cooldown');cooldown.checked=false;cooldown.disabled=true;
 const rollout=$('route-cooldown-rollout');rollout.hidden=true;
 drawDeviceRollout('route-rollout',null);
 const decision=$('route-decision');decision.value='';decision.disabled=true;
 $('route-decision-rollout').hidden=true;
 drawDeviceRollout('route-decision',null);
 const prior=select.value;select.replaceChildren();list.replaceChildren();editor.disabled=true;
 if(!authenticated)return;
 let state;
 try{state=routeDraft();}catch{return;}
 if(state.value.adaptive){$('route-bounds').hidden=false;$('route-bounds-preview').disabled=busy||!!pending;}
 for(const tag of [...state.tags].sort()){const option=document.createElement('option');option.value=tag;option.textContent=tag;select.append(option);}
 if(state.tags.has(prior))select.value=prior;
 else if(state.tags.has(state.value.graph.final))select.value=state.value.graph.final;
 const selected=state.checks.find(row=>row.outbound===select.value);
 if(routeProfileEdit&&routeProfileEdit.path!==select.value)closeRouteProfile();
 $('route-profile-open').disabled=busy||!!pending||!(selected?.profile||selected?.checks?.length);
 $('route-check-required').checked=selected?.required===true;
 $('route-profile-note').hidden=!selected?.profile;
 for(const id of ['route-check-method','route-check-target','route-check-ip','route-check-verb','route-check-status','route-check-country-class','route-check-add']){
  $(id).disabled=!!selected?.profile;
 }
 editor.disabled=busy||!!pending||!state.tags.size;
 const failover=internalFailoverPlan(state);
 if(failover){
  cooldown.disabled=editor.disabled;cooldown.checked=failover.probeCooldown===true;rollout.hidden=!cooldown.checked;
  drawDeviceRollout('route-rollout',failover.probeCooldownRollout);
  decision.disabled=editor.disabled;
  decision.value=failover.decisionRevision===confirmedDecision?confirmedDecision:'';
  $('route-decision-rollout').hidden=!decision.value;
  if(decision.value)drawDeviceRollout('route-decision',failover.decisionRollout);
 }
 for(const row of state.checks){
  if(row.profile){
   const li=document.createElement('li');
   li.textContent=`${row.outbound} · Профиль ${row.profile.id}${row.required===true?' · обязательная':''}`;
   list.append(li);
   continue;
  }
  for(const item of row.checks){
   if(!item||typeof item.method!=='string'||typeof item.target!=='string')continue;
   const li=document.createElement('li'),remove=actionButton();
   const method=Object.hasOwn(routeCheckMethods,item.method)?routeCheckMethods[item.method]:item.method;
   let expected='';
   if(item.method==='https_exit_ip'&&typeof item.expected_ip==='string')expected=` · ${item.expected_ip}`;
   if(item.method==='https_status')expected=` · ${item.http_method} · ${item.expected_status}`;
   if(item.method==='https_exit_country'&&Object.hasOwn(exitCountryLabels,item.expected_exit_class))expected=` · ${exitCountryLabels[item.expected_exit_class]}`;
   li.textContent=`${row.outbound} · ${method} · ${item.target}${expected}${row.required===true?' · обязательная':''} `;
   remove.type='button';remove.textContent='Удалить проверку';
   remove.onclick=()=>work(async()=>{
    const current=routeDraft(),group=current.checks.find(r=>r.outbound===row.outbound);
    const index=group?.checks.findIndex(c=>sameRouteCheck(c,item));
    if(!group||index===undefined||index<0)throw Error('invalid');
    group.checks.splice(index,1);
    if(!group.checks.length)current.checks.splice(current.checks.indexOf(group),1);
    applyRouteChecks(current);
   });
   li.append(remove);list.append(li);
  }
 }
}
function drawDeviceRollout(prefix,existing){
 const valid=typeof existing?.id==='string'&&Number.isSafeInteger(existing.basisPoints)&&existing.basisPoints>=0&&existing.basisPoints<=10000;
 $(prefix+'-id').value=valid?existing.id:'';
 $(prefix+'-share').value=valid?String(existing.basisPoints/100):'';
}
function readDeviceRollout(id,share){
 if(!id&&!share)return null;
 if(!/^[a-z0-9][a-z0-9._-]{0,47}$/.test(id)||!/^\d{1,3}(\.\d{1,2})?$/.test(share)||Number(share)>100)throw Error('invalid');
 return {id,basisPoints:Math.round(Number(share)*100)};
}
function internalFailoverPlan(state){
 const failover=state.network.routeFailover;
 return failover?.networkMode==='wifi'&&failover.intent==='INTERNAL'&&state.tags.has(failover.selector)?failover:null;
}
function applyRouteChecks(state){
 if(state.checks.length)state.network.routeChecks=state.checks;
 else delete state.network.routeChecks;
 const serialized=JSON.stringify(state.value,null,2);
 if(new TextEncoder().encode(serialized).length>262144)throw Error('size');
 $('plan').value=serialized;
 status('Проверки изменены в черновике. Сохраните его, чтобы не потерять правки.');
}
function closeRouteProfile(){
 routeProfileEdit=null;
 $('route-profile-editor').hidden=true;
 $('route-profile-json').value='';
}
function flatProfile(profile){
 const {stages}=profile;
 const leafRefs=value=>Array.isArray(value)&&value.every(v=>v&&Object.keys(v).length===1&&typeof v.leaf==='string');
 if(leafRefs(stages))return {mode:'sequence',refs:stages};
 if(!Array.isArray(stages)||stages.length!==1||!stages[0]||Object.keys(stages[0]).length!==1)return null;
 const operator=Object.keys(stages[0])[0];
 if(!['all','any','quorum'].includes(operator))return null;
 const expr=stages[0][operator],refs=operator==='quorum'?expr?.of:expr;
 return leafRefs(refs)?{mode:operator,refs,minimum:operator==='quorum'?expr.k:1}:null;
}
function profileView(){
 const mode=$('route-profile-mode').value;
 $('route-profile-threshold').hidden=mode!=='quorum';
 $('route-profile-timing').hidden=mode==='custom';
 $('route-profile-advanced').hidden=mode!=='custom';
}
function profileCandidate(edit,mode=$('route-profile-mode').value){
 if(mode==='custom')return $('route-profile-json').value;
 if(!edit.flat)throw Error('invalid');
 const deadline=$('route-profile-deadline').valueAsNumber,refs=edit.flat.refs;
 if(!Number.isInteger(deadline)||deadline<1||deadline>12000)throw Error('invalid');
 let stages=refs;
 if(mode!=='sequence'){
  if(refs.length<2)throw Error('invalid');
  if(mode==='quorum'){
   const k=$('route-profile-count').valueAsNumber;
   if(!Number.isInteger(k)||k<1||k>refs.length)throw Error('invalid');
   stages=[{quorum:{k,of:refs}}];
  }else if(mode==='all'||mode==='any')stages=[{[mode]:refs}];
  else throw Error('invalid');
 }
 return JSON.stringify({...edit.profile,deadlineMs:deadline,stages});
}
function profileSubject(){
 return JSON.stringify(['draft-id','target-kind','target-id'].map(id=>$(id).value));
}
function openRouteProfile(){
 const current=routeDraft(),path=$('route-check-path').value;
 const row=current.checks.find(r=>r.outbound===path);
 if(!authenticated||busy||pending||!row)return;
 let profile;
 if(row.profile){
  profile={...row.profile,revision:row.profile.revision+1};
 }else{
  const leaves=row.checks.map((check,index)=>({id:'check-'+(index+1),check}));
  const gates=leaves.filter(l=>['tls','https_exit_ip','https_exit_country'].includes(l.check.method)).map(l=>l.id);
  const stages=leaves.filter(l=>!gates.includes(l.id)).map(l=>({leaf:l.id}));
  profile={schemaVersion:2,id:('health-'+path.toLowerCase()).slice(0,64),revision:1,deadlineMs:12000,leaves,gates,stages};
 }
 const flat=flatProfile(profile);
 routeProfileEdit={path,profile,flat,epoch:boundsEpoch,subject:profileSubject(),mode:flat?.mode||'custom'};
 const mode=$('route-profile-mode');
 for(const option of mode.options)option.disabled=option.value!=='custom'&&(!flat||(option.value!=='sequence'&&flat.refs.length<2));
 mode.value=flat?.mode||'custom';
 $('route-profile-count').value=String(flat?.minimum||1);
 $('route-profile-deadline').value=String(profile.deadlineMs);
 $('route-profile-json').value=JSON.stringify(profile,null,2);
 $('route-profile-editor').hidden=false;
 profileView();mode.focus();
}
$('route-profile-open').onclick=openRouteProfile;
$('route-profile-cancel').onclick=()=>{closeRouteProfile();$('route-profile-open').focus();};
$('route-profile-mode').onchange=()=>{
 const edit=routeProfileEdit,select=$('route-profile-mode');
 if(!edit)return;
 if(select.value==='custom'&&edit.mode!=='custom'){
  try{$('route-profile-json').value=JSON.stringify(JSON.parse(profileCandidate(edit,edit.mode)),null,2);}
  catch{select.value=edit.mode;status('Проверьте тайм-аут и минимальное число успешных проверок.','danger');return;}
 }
 edit.mode=select.value;profileView();
};
$('route-profile-json').oninput=()=>{
 for(const option of $('route-profile-mode').options)option.disabled=option.value!=='custom';
};
$('route-profile-apply').onclick=()=>work(async()=>{
 const edit=routeProfileEdit;
 if(!edit||edit.subject!==profileSubject())return;
 const raw=profileCandidate(edit);
 if(!raw||new TextEncoder().encode(raw).length>24000)throw Error('invalid');
 const report=await request('/control/route-check-profile',raw);
 if(!authenticated||routeProfileEdit!==edit||edit.epoch!==boundsEpoch||
    edit.subject!==profileSubject()||$('route-check-path').value!==edit.path)return;
 if(report?.valid!==true)throw Error('invalid');
 const profile=JSON.parse(raw),current=routeDraft(),row=current.checks.find(r=>r.outbound===edit.path);
 if(!row||profile.revision!==edit.profile.revision||(row.profile&&profile.id!==row.profile.id))throw Error('invalid');
 delete row.checks;row.profile=profile;
 applyRouteChecks(current);closeRouteProfile();
});
function controls(){
 $('refresh-runtime').disabled=busy||!!runtimeRequest||!authenticated||!layerInventory;
 $('reauthentication').hidden=!authenticated||!reauthenticationNeeded;
 $('reauthentication-unavailable').hidden=reauthenticationAvailable;
 $('reauthentication-start').disabled=busy||!authenticated||!reauthenticationAvailable;
 $('reauthentication-check').disabled=busy||!authenticated;
 for(const id of ['refresh-devices','more-devices'])$(id).disabled=busy||!authenticated||!!pending||(id==='more-devices'&&!devicesNext);
 for(const button of $('device-rows').querySelectorAll('button'))button.disabled=busy||!authenticated||!!pending;
 $('login').disabled=busy||authenticated;$('logout').disabled=busy||!authenticated;
 $('login').hidden=authenticated;$('logout').hidden=!authenticated;
 for(const id of ['workspace','console-navigation','skip-workspace','desktop-nav-toggle','console-nav-toggle'])$(id).hidden=!authenticated;
 $('signin').hidden=authenticated;
 if(!authenticated){
  setNavExpanded(false);
  setDesktopNavExpanded(true);
 }
 $('console-shell').classList.toggle('signed-in',authenticated);
 for(const id of ['load-sources','load-inventory','open-draft','save-draft','new-draft','new-source','save-source'])$(id).disabled=busy||!authenticated||!!pending;
 for(const id of ['telemetry-hour','load-telemetry'])$(id).disabled=busy||!authenticated;
 for(const id of sourceFields)$(id).disabled=busy||!authenticated||!!pending||sourceIdentity&&['source-id','source-owner','source-mode'].includes(id);
 const deviceSource=$('source-mode').value==='device';
 $('source-device-settings').hidden=!deviceSource;
 $('source-device').disabled=$('source-device').disabled||!deviceSource||!!sourceIdentity?.fetchDeviceId;
 $('source-device').required=deviceSource;
 updateProviderControls();
 $('sync-source').disabled=busy||!authenticated||!!pending||!sourceIdentity;$('source-job').disabled=busy||!authenticated||!!pending||!sourceJob;
 $('source-history').disabled=busy||!authenticated||!!pending||!sourceIdentity;
 $('source-history-more').disabled=$('source-history').disabled||!sourceHistoryNext;
 $('source-import-file').disabled=busy||!authenticated||!!pending||sourceIdentity?.mode!=='manual';
 $('source-import').disabled=$('source-import-file').disabled||!$('source-import-file').files.length;
 $('source-shares-load').disabled=$('source-history').disabled;
 const sharesBlocked=$('source-shares-load').disabled||!sourceShares;
 for(const id of ['source-shares-kind','source-shares-id','source-shares-add','source-shares-confirm'])$(id).disabled=sharesBlocked;
 $('source-shares-save').disabled=sharesBlocked||!$('source-shares-confirm').checked||!sharesChanged();
 for(const button of $('source-shares-list').querySelectorAll('button'))button.disabled=sharesBlocked;
 $('more-sources').disabled=busy||!authenticated||!next||!!pending;
 for(const id of ['owner','inventory-device',...formFields])$(id).disabled=busy||!authenticated||!!pending;
 $('pending').hidden=!pending;for(const id of ['retry-save','discard-save'])$(id).disabled=busy||!authenticated;
 if(pending&&['layer-preview','layer-publish','layer-discard'].includes(pendingKind))$('discard-save').disabled=true;
 for(const button of $('sources').querySelectorAll('button'))button.disabled=busy||!authenticated||!!pending;
 $('source-secret').disabled=busy||!authenticated||!!pending||$('source-secret-operation').value!=='replace';
 if(!['server','resource','device'].includes($('source-mode').value)||deviceSource&&!sourceIdentity?.fetchDeviceId)$('sync-source').disabled=true;
 layerControls();
 drawRouteChecks();
}
function clearInventory(){
 clearRuntime();
 layerInventory=null;
 for(const id of ['inventory-meta','inventory-layers','inventory-effective','inventory-fields','inventory-restrictions','inventory-issued-config','inventory-state','inventory-issued','inventory-issued-algorithm','inventory-report','inventory-report-time'])$(id).replaceChildren();
 for(const id of ['inventory-state','inventory-issued','inventory-report'])delete $(id).dataset.tone;
 $('inventory-issued-algorithm').hidden=true;
 $('inventory-report-time').removeAttribute('datetime');$('inventory-report-time').hidden=true;
 $('inventory-details').open=false;$('inventory-view').hidden=true;$('inventory-issued-settings').hidden=true;$('inventory-issued-settings').open=false;
}
function erase(){
 reauthenticationAvailable=false;reauthenticationNeeded=false;reauthenticationIssuer='';reauthenticationFocus=false;
 clearDevices();clearInventory();clearLayers();clearTelemetry();pending=null;revision=0;opened=null;next='';listedOwner='';clearSource();
 for(const id of ['owner','inventory-device','draft-id','target-id','base-hash','plan','route-check-target','route-check-ip','route-check-country-class'])$(id).value='';
 $('target-kind').value='device';$('base-revision').value='0';$('draft-version').textContent='Новый черновик';
 for(const id of ['sources','profiles','source-details','inventory-status'])$(id).replaceChildren();
}
async function request(path,body,signal){
 const raw=typeof body==='string'?body:JSON.stringify(body);
 if(path===sourceImportPath?raw.length>14*1024*1024+65536:new TextEncoder().encode(raw).length>278528)throw Error('size');
 const controller=new AbortController(),abort=()=>controller.abort();
 if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
 let timedOut=false;
 const deadline=setTimeout(()=>{timedOut=true;abort();},15000);
 try{
 const response=await fetch(path,{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',headers:{'Content-Type':'application/json','X-Syn443-CSRF':'1'},body:raw,signal:controller.signal});
 if(response.status===401&&path==='/session'&&!authenticated)throw Error('anonymous');
 if(response.status===403&&(path==='/control/action'||path===sourceImportPath)){
  let challenge;
  try{const text=await response.text();if(text.length<=128)challenge=JSON.parse(text);}catch{}
  if(challenge&&typeof challenge==='object'&&Object.keys(challenge).length===1&&challenge.code==='catalog_reauthentication_required'){
   reauthenticationNeeded=true;reauthenticationFocus=true;throw Error('reauth');
  }
 }
 if(response.status===401||response.status===403){authenticated=false;erase();throw Error(response.status===401?'login':'denied');}
 if(response.status===413)throw Error(path===sourceImportPath?'importSize':'size');
 if(!response.ok)throw Error(response.status===409?'conflict':response.status===400?'invalid':response.status===404?'not_found':'network');
 return await response.json();
 }catch(error){if(timedOut)throw Error('timeout');throw error;}
 finally{clearTimeout(deadline);signal?.removeEventListener('abort',abort);}
}
const envelope=(action,payload)=>JSON.stringify({version:1,action,requestId:crypto.randomUUID(),payload});
const action=(name,payload,signal)=>request('/control/action',envelope(name,payload),signal);
function clearTelemetry(){
 $('telemetry-status').textContent='';$('telemetry-rows').replaceChildren();$('telemetry-view').hidden=true;
}
$('telemetry-hour').value=new Date(Math.floor(Date.now()/3600000-2)*3600000).toISOString().slice(0,16);
$('telemetry-hour').onchange=clearTelemetry;
$('telemetry-form').onsubmit=event=>{
 event.preventDefault();
 if(!authenticated||busy)return;
 clearTelemetry();
 const hour=$('telemetry-hour').value+'Z';
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:00Z$/.test(hour)){$('telemetry-status').textContent='Укажите начало часа без минут.';return;}
 void work(async()=>{
  try{
   const report=await action('telemetry.summary.get',{hour});
   if(report?.schemaVersion!==1||report.hourStartMs!==Date.parse(hour)||!Array.isArray(report.rows)||report.rows.length>256||report.available!==(report.rows.length>0))throw Error('network');
   if(!report.available){$('telemetry-status').textContent='За этот час нет готовой сводки.';return;}
   const rows=document.createDocumentFragment();
   for(const row of report.rows){
    if(!row||![row.kind,row.code,row.mode].every(s=>typeof s==='string'&&/^[a-z0-9_]{1,48}$/.test(s))||![row.events,row.timed,row.duration].every(Number.isSafeInteger)||row.events<=0||row.timed<0||row.timed>row.events||row.duration<0||row.duration>row.timed*600000)throw Error('network');
    const baseline=row.baselineReselections??0,conservative=row.conservativeReselections??0;
    if(![baseline,conservative].every(Number.isSafeInteger)||baseline<0||conservative<0||baseline>row.events||conservative>row.events-baseline||
      ((baseline||conservative)&&(row.kind!=='route'||row.code!=='reselected')))throw Error('network');
    const counts=(baseline||conservative)?`Базовый: ${baseline}, консервативный: ${conservative}`:'—';
    const tr=document.createElement('tr');
    for(const value of [row.kind,row.code,row.mode,row.events,row.timed?`${Math.round(row.duration/row.timed)} мс`:'—',counts]){
     const cell=document.createElement('td');cell.textContent=value;tr.append(cell);
    }
    rows.append(tr);
   }
   $('telemetry-rows').append(rows);$('telemetry-view').hidden=false;
   $('telemetry-status').textContent='Сводка за '+hour;
  }catch(error){
   $('telemetry-status').textContent=({not_found:'Нет доступа к сводкам или просмотр выключен.',denied:'Доступ к панели отозван или недостаточно прав.',login:'Сессия завершена. Войдите снова.',invalid:'Час недоступен. Выберите завершившийся час за последние 180 суток.'})[error.message]||'Не удалось загрузить сводку.';
  }
 });
};
async function work(fn){if(busy)return;busy=true;controls();try{await fn();}catch(error){status(({timeout:'Сервер не ответил вовремя. Повторите действие.',anonymous:'Войдите с административной учётной записью.',login:'Сессия завершена. Войдите снова.',denied:'Доступ отозван или недостаточно прав.',reauth:'Для операции нужно подтвердить вход. Правки и подготовленный запрос остаются в этой вкладке.',popup:'Разрешите новую вкладку для Keycloak и повторите подтверждение входа.',conflict:'Версия изменилась. Откройте текущий черновик перед новой правкой.',invalid:'Проверьте поля и структуру данных.',size:'Данные превышают допустимый размер.',importSize:'Файл подписки или запрос превышает допустимый размер.'})[error.message]||'Сервер недоступен. Правка остаётся только в памяти этой вкладки.',error.message==='anonymous'?'info':'danger');}finally{busy=false;controls();if(reauthenticationFocus&&authenticated){reauthenticationFocus=false;$('reauthentication-title').focus();}}}

function sessionCapabilities(value){
 if(!value||value.authenticated!==true)throw Error('invalid');
 const available=value.reauthenticationAvailable===true;
 if(available&&(typeof value.reauthenticationFresh!=='boolean'||typeof value.reauthenticationIssuer!=='string'))throw Error('invalid');
 if(available){
  const issuer=new URL(value.reauthenticationIssuer);
  if(issuer.username||issuer.password||issuer.search||issuer.hash||issuer.protocol!=='https:'&&!(issuer.protocol==='http:'&&issuer.hostname==='127.0.0.1'))throw Error('invalid');
 }
 reauthenticationAvailable=available;reauthenticationIssuer=available?value.reauthenticationIssuer:'';
 return available&&value.reauthenticationFresh===true;
}
async function beginReauthentication(){
 if(!reauthenticationAvailable||!reauthenticationNeeded)throw Error('invalid');
 const popup=window.open('about:blank','_blank');if(!popup){reauthenticationFocus=true;throw Error('popup');}
 popup.opener=null;
 try{
  const device=$('inventory-device').value.trim();
  const value=await request('/reauth',deviceID.test(device)?{device}:{});
  const url=new URL(value.url),expected=new URL(reauthenticationIssuer+'/protocol/openid-connect/auth');
  if(url.origin!==expected.origin||url.pathname!==expected.pathname||url.username||url.password||url.hash||url.searchParams.get('prompt')!=='login'||url.searchParams.get('max_age')!=='0'||url.searchParams.get('redirect_uri')!==location.origin+'/callback')throw Error('invalid');
  popup.location.replace(url.href);
  $('reauthentication-status').textContent='Подтвердите вход в новой вкладке. Затем вернитесь сюда и нажмите «Проверить вход». Изменение не отправляется повторно автоматически.';
 }catch(error){popup.close();reauthenticationFocus=true;throw error;}
}
async function checkReauthentication(){
 const fresh=sessionCapabilities(await request('/session',{}));
 if(fresh){reauthenticationNeeded=false;status('Вход подтверждён. Проверьте правки и повторите выбранную операцию.');}
 else $('reauthentication-status').textContent='Свежий вход с подтверждением ещё не получен. Завершите вход в новой вкладке или повторите его.';
}
function textItem(list,text){const item=document.createElement('li');item.textContent=text;list.append(item);return item;}
function inventoryPair(list,name,value){const term=document.createElement('dt');term.textContent=name;const detail=document.createElement('dd');detail.textContent=value;list.append(term,detail);}
function updateProviderControls(){
 const visible=authenticated&&$('source-mode').value==='resource';
 const id=$('source-resource').value.trim();
 const context=visible?JSON.stringify([$('source-id').value,$('source-owner').value,id]):null;
 if(context!==providerContext){
  providerContext=context;providerEpoch++;$('provider-details').replaceChildren();
 }
 $('provider-settings').hidden=!visible;
 $('inspect-provider').disabled=!visible||busy||!!pending||!/^[A-Za-z0-9_-]{1,48}$/.test(id);
}
async function inspectProvider(){
 const id=$('source-resource').value.trim(),epoch=providerEpoch;
 const details=$('provider-details');details.replaceChildren();
 const {resource,impact}=await action('resource.get',{id});
 if(!authenticated||providerEpoch!==epoch)return;
 const names={'panel.remnawave':'Remnawave','panel.x-ui':'x-ui','panel.3x-ui':'3x-ui','overlay.tailscale':'Tailscale','overlay.zerotier':'ZeroTier'};
 if(!resource||resource.id!==id||typeof resource.name!=='string'||!resource.name||resource.name.length>256||
  !Object.hasOwn(names,resource.providerType)||typeof resource.apiVersion!=='string'||resource.apiVersion.length>64||
  typeof resource.enabled!=='boolean'||!Number.isSafeInteger(resource.revision)||resource.revision<1||
  !Number.isSafeInteger(resource.lastSync)||resource.lastSync<0||resource.lastSync>8640000000000||
  !impact||!Number.isSafeInteger(impact.sources)||impact.sources<0)throw Error('invalid');
 const planned=resource.providerType!=='panel.remnawave';
 const expected=planned?'not_implemented':resource.enabled?'unknown':'disabled';
 if(resource.state!==expected||planned&&resource.enabled||!planned&&resource.apiVersion!=='3.4')throw Error('invalid');
 const rows=document.createDocumentFragment();
 inventoryPair(rows,'Название',resource.name);
 inventoryPair(rows,'Провайдер',names[resource.providerType]);
 if(resource.apiVersion)inventoryPair(rows,'Версия API',resource.apiVersion);
 inventoryPair(rows,'Состояние',planned?'Поддержка запланирована':resource.enabled?'Включён':'Отключён');
 inventoryPair(rows,'Ревизия ресурса',resource.revision);
 inventoryPair(rows,'Связанные источники',impact.sources);
 if(!planned)inventoryPair(rows,'Последняя попытка синхронизации',resource.lastSync?inventoryDate(resource.lastSync*1000):'Нет данных');
 details.append(rows);
}
function inventoryOrigin(origin){return origin&&typeof origin==='object'&&!Array.isArray(origin)&&typeof origin.layerId==='string'&&typeof origin.kind==='string'&&Number.isSafeInteger(origin.revision)&&origin.revision>=0;}
function inventoryDate(milliseconds){const date=new Date(milliseconds);if(!Number.isFinite(date.getTime()))throw Error('invalid');return date.toISOString();}
function showInventory(view){
 if(!view||typeof view!=='object'||Array.isArray(view)||view.historical)throw Error('invalid');
 const {device,owner,state,revision,hash,policyRevision,layers,effective}=view;
 if(typeof device!=='string'||!device||device.length>64||typeof owner!=='string'||!['assigned','unassigned','expired'].includes(state)||!Number.isSafeInteger(revision)||revision<0||typeof hash!=='string'||hash.length>64||!Number.isSafeInteger(policyRevision)||policyRevision<0||!Array.isArray(layers)||effective!==undefined&&effective!==null&&(typeof effective!=='object'||Array.isArray(effective)))throw Error('invalid');
 const assigned=state==='assigned'||state==='expired';
 if(!assigned&&(revision!==0||hash!==''||layers.length||effective))throw Error('invalid');
 if(assigned&&(revision<1||!/^[0-9a-f]{64}$/.test(hash)||!effective||typeof view.mode!=='string'||!view.mode||!Number.isSafeInteger(view.approvalUntilMs)||view.approvalUntilMs<1))throw Error('invalid');
 const stateLabel={assigned:`Назначена · версия ${revision}`,unassigned:'Не назначена',expired:`Истекла · версия ${revision}`};
 inventoryBadge('inventory-state',stateLabel[state],{assigned:'success',unassigned:'neutral',expired:'warning'}[state]);
 inventoryBadge('inventory-issued',policyRevision?`Версия ${policyRevision}`:'Ещё не выдана',policyRevision?'info':'neutral');
 inventoryBadge('inventory-report','Отчёт ещё не получен');
 const meta=$('inventory-meta');meta.replaceChildren();
 inventoryPair(meta,'Устройство',device);inventoryPair(meta,'Владелец',owner);
 inventoryPair(meta,'Желаемая версия',String(revision));inventoryPair(meta,'Хэш желаемой конфигурации',hash||'-');
 inventoryPair(meta,'Версия выданной политики',String(policyRevision));
 if(view.publicationSource!==undefined){
  const labels={not_issued:'Политика ещё не выдана',unlinked:'Источник не зафиксирован',matches_desired:'Соответствует желаемой',different_revision:'Выдана из другой ревизии'};
  if(typeof view.publicationSource!=='string'||!Object.hasOwn(labels,view.publicationSource))throw Error('invalid');
  inventoryPair(meta,'Источник выданной политики',labels[view.publicationSource]);
 }
 const report=view.activation;
 if(report){
  if(!['not_issued','awaiting_report','reported','historical'].includes(report.state))throw Error('invalid');
  if(['reported','historical'].includes(report.state)){
   const outcomes={committed:'Применена',degraded:'Применена с ограничениями',rolled_back:'Откат'};
   if(!Object.hasOwn(outcomes,report.outcome)||!Number.isSafeInteger(report.policyRevision)||report.policyRevision<1||!Number.isSafeInteger(report.activePolicyRevision)||report.activePolicyRevision<0||!Number.isSafeInteger(report.receivedAtMs)||report.receivedAtMs<1)throw Error('invalid');
   const historical=report.state==='historical'?' · предыдущая или истёкшая выдача':'';
   const summary=`${outcomes[report.outcome]} · политика ${report.policyRevision}${historical}`;
   const tone=report.state==='historical'?'warning':{committed:'success',degraded:'warning',rolled_back:'danger'}[report.outcome];
   inventoryBadge('inventory-report',summary,tone);
   const time=$('inventory-report-time');
   time.dateTime=inventoryDate(report.receivedAtMs);
   time.textContent=new Intl.DateTimeFormat('ru',{
    year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short',
   }).format(report.receivedAtMs);
   time.hidden=false;
   inventoryPair(meta,'Отчёт устройства',summary);
   inventoryPair(meta,'Версия по отчёту',report.activePolicyRevision?String(report.activePolicyRevision):'Нет');
   inventoryPair(meta,'Получен',inventoryDate(report.receivedAtMs));
  }else{
   const label=report.state==='not_issued'?'Политика ещё не выдана':'Ожидаем результат применения';
   inventoryBadge('inventory-report',label,report.state==='not_issued'?'neutral':'info');
   inventoryPair(meta,'Отчёт устройства',label);
  }
 }
 if(assigned){inventoryPair(meta,'Режим сети',view.mode);if(view.approvalUntilMs>0)inventoryPair(meta,'Подтверждение действительно до',inventoryDate(view.approvalUntilMs));}
 const layerList=$('inventory-layers');layerList.replaceChildren();
 for(const layer of layers){
  if(!layer||typeof layer!=='object'||Array.isArray(layer)||typeof layer.id!=='string'||typeof layer.kind!=='string'||!Number.isSafeInteger(layer.priority)||!Number.isSafeInteger(layer.revision)||layer.revision<1||layer.changes!=null&&!Array.isArray(layer.changes)||layer.permissions!=null&&!Array.isArray(layer.permissions))throw Error('invalid');
  textItem(layerList,`${layer.kind} · ${layer.id} · приоритет ${layer.priority} · версия ${layer.revision} · изменений ${layer.changes?.length||0} · разрешений ${layer.permissions?.length||0}`);
 }
 if(!layerList.children.length)textItem(layerList,'Наследованные слои отсутствуют.');
 const documentNode=$('inventory-effective');
 if(effective){if(effective.document===undefined)throw Error('invalid');documentNode.textContent=JSON.stringify(effective.document,null,2);}else documentNode.textContent='Управляемая конфигурация не назначена.';
 const issued=view.issuedSettings;
 if(issued!=null){
  if(typeof issued!=='object'||Array.isArray(issued)||issued.revision!==policyRevision||!Array.isArray(issued.outbounds)||!issued.outbounds.length)throw Error('invalid');
  if(['m1-local-v1',confirmedDecision].includes(issued.algorithmRevision)){
   const algorithm=$('inventory-issued-algorithm');
   algorithm.textContent='Алгоритм '+issued.algorithmRevision;
   algorithm.hidden=false;
  }
  $('inventory-issued-config').textContent=JSON.stringify(issued,null,2);
  $('inventory-issued-settings').hidden=false;
 }
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
function clearDevices(){
 devicesNext='';deviceIds=new Set();$('device-rows').replaceChildren();$('devices-status').textContent='';$('devices-region').hidden=true;$('more-devices').hidden=true;
}
const deviceReportStates={not_issued:'Политика не выдана',awaiting_report:'Ожидается отчёт',historical:'Архивный отчёт',reported:'Отчёт о выданной политике'};
const deviceOutcomes={committed:'Применена',degraded:'Применена частично',rolled_back:'Откат'};
const closedObject=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>keys.includes(k));
const safeRevision=v=>Number.isSafeInteger(v)&&v>=0;
async function loadDevices(more=false){
 const after=more?devicesNext:'';
 if(more&&!after)throw Error('invalid');
 if(!more)clearDevices();
 $('devices-disclosure').open=true;
 $('devices-status').textContent='Загружаем устройства…';
 try{
  const page=await action('configuration.devices.list',{after});
  if(!closedObject(page,['devices','next','observedAtMs'])||!Array.isArray(page.devices)||page.devices.length>32||typeof page.next!=='string'||page.next&&!deviceID.test(page.next)||!Number.isSafeInteger(page.observedAtMs)||page.observedAtMs<1)throw Error('invalid');
  const seen=more?new Set(deviceIds):new Set();let previous=after;
  for(const row of page.devices){
   if(!closedObject(row,['device','policyRevision','desiredRevision','report'])||typeof row.device!=='string'||!deviceID.test(row.device)||row.device<=previous||seen.has(row.device)||!safeRevision(row.policyRevision)||!safeRevision(row.desiredRevision))throw Error('invalid');
   const report=row.report;
   if(!closedObject(report,['state','policyRevision','outcome','activePolicyRevision','receivedAtMs'])||!Object.hasOwn(deviceReportStates,report.state)||!safeRevision(report.activePolicyRevision)||!safeRevision(report.policyRevision??0)||!safeRevision(report.receivedAtMs??0))throw Error('invalid');
   if(['historical','reported'].includes(report.state)){
    if(!Object.hasOwn(deviceOutcomes,report.outcome)||!report.policyRevision||!report.receivedAtMs||report.state==='reported'&&report.policyRevision!==row.policyRevision)throw Error('invalid');
   }else if(report.policyRevision||report.outcome||report.receivedAtMs||report.activePolicyRevision||report.state==='not_issued'&&row.policyRevision!==0||report.state==='awaiting_report'&&row.policyRevision===0)throw Error('invalid');
   previous=row.device;seen.add(row.device);
  }
  if(page.next&&(page.devices.length!==32||page.next!==previous))throw Error('invalid');
  // Validate the complete page before exposing any row or attaching actions.
  const fragment=document.createDocumentFragment();
  for(const row of page.devices){
   const tr=document.createElement('tr'),cell=document.createElement('td'),open=actionButton();
   open.type='button';open.textContent=row.device;open.setAttribute('aria-label',`Открыть устройство ${row.device}`);
   open.onclick=()=>work(async()=>{$('inventory-device').value=row.device;await loadInventory();});cell.append(open);tr.append(cell);
   const report=row.report;const label=report.outcome?`${deviceReportStates[report.state]} · ${deviceOutcomes[report.outcome]}`:deviceReportStates[report.state];
   for(const value of [row.desiredRevision?String(row.desiredRevision):'Не назначена',row.policyRevision?String(row.policyRevision):'Не выдана',label,report.receivedAtMs?inventoryDate(report.receivedAtMs):'—']){const td=document.createElement('td');td.textContent=value;tr.append(td);}
   fragment.append(tr);
  }
  if(!more)$('device-rows').replaceChildren();$('device-rows').append(fragment);
  deviceIds=seen;devicesNext=page.next;$('devices-region').hidden=!deviceIds.size;$('more-devices').hidden=!devicesNext;
  $('devices-status').textContent=deviceIds.size?`Загружено устройств: ${deviceIds.size}.`:'Доступных устройств нет. Проверьте назначение и срок доступа.';
 }catch(error){
  clearDevices();
  $('devices-status').textContent=error.message==='invalid'?'Сервер вернул некорректный список. Устройства скрыты.':'Список устройств недоступен. Можно открыть карточку по ID.';
  if(['login','denied'].includes(error.message))throw error;
 }
}
async function loadInventory(){
 const device=$('inventory-device').value.trim();
 if(!deviceID.test(device))throw Error('invalid');
 clearInventory();
 $('inventory-status').textContent='Загружаем конфигурацию…';
 try{
  const view=await action('configuration.inventory.get',{id:device});
  if(view?.device!==device)throw Error('invalid');
  showInventory(view);
  $('devices-disclosure').open=false;
  $('inventory-view').focus({preventScroll:true});
  layerInventory=structuredClone(view);
  await loadRuntime();
  $('inventory-status').textContent='Конфигурация загружена.';
 }catch(error){
  clearInventory();
  $('inventory-status').textContent=error.message==='invalid'?'Карточка не соответствует выбранному устройству.':
   error.message==='denied'?'Проверьте права доступа и повторите вход.':
   error.message==='login'?'Сессия завершена. Войдите снова.':'Не удалось загрузить карточку. Повторите попытку.';
  throw error;
 }
}
function clearRuntime(){
 runtimePolling=false;clearTimeout(runtimeRefreshTimer);runtimeRefreshTimer=null;
 const prior=runtimeRequest;runtimeRequest=null;prior?.controller.abort();
 runtimeEpoch++;runtimeReport=null;runtimeDeadline=0;clearTimeout(runtimeTimer);runtimeTimer=null;
 for(const id of ['inventory-runtime','inventory-runtime-detail','inventory-runtime-time'])$(id).replaceChildren();
 $('inventory-runtime-time').hidden=true;$('inventory-runtime-time').removeAttribute('datetime');delete $('inventory-runtime').dataset.tone;
}
function checkedRuntime(view,device){
 const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join('|')===[...keys].sort().join('|');
 const integer=(n,min=0,max=Number.MAX_SAFE_INTEGER)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
 if(!view||!['none','recent','stale'].includes(view.state)||!exact(view,view.state==='none'?['device','observedAtMs','state']:['device','observedAtMs','state','report'])||view.device!==device||!integer(view.observedAtMs,1))throw Error('invalid');
 if(view.state==='none')return null;
 const r=view.report;
 if(!exact(r,['version','sequence','build','phase','policyRevision','engineKnown','engineActive','network','sampledAtMs','receivedAtMs'])||r.version!==1||!integer(r.sequence,1)||!integer(r.build,1,2100000000)||!integer(r.policyRevision)||typeof r.engineKnown!=='boolean'||typeof r.engineActive!=='boolean'||!integer(r.sampledAtMs,1)||!integer(r.receivedAtMs,1)||r.receivedAtMs>view.observedAtMs||r.sampledAtMs<r.receivedAtMs-120000||r.sampledAtMs>r.receivedAtMs+30000)throw Error('invalid');
 if(!['off','starting','online','recovering','no_network','blocked','unknown'].includes(r.phase)||!['none','wifi','cellular','unknown'].includes(r.network)||!r.engineKnown&&r.engineActive||r.phase==='online'&&(!r.engineKnown||!r.engineActive||r.policyRevision===0)||r.phase==='off'&&(!r.engineKnown||r.engineActive))throw Error('invalid');
 const remaining=Math.min(r.sampledAtMs,r.receivedAtMs)+180000-view.observedAtMs;
 if((remaining>0)!==(view.state==='recent'))throw Error('invalid');
 inventoryDate(r.receivedAtMs);
 return {report:r,remaining:Math.max(0,Math.min(180000,remaining))};
}
function renderRuntime(){
 clearTimeout(runtimeTimer);runtimeTimer=null;
 if(!runtimeReport){$('inventory-runtime').textContent='Нет отчёта';$('inventory-runtime-detail').textContent='Клиент ещё не присылал состояние.';return;}
 const r=runtimeReport,recent=performance.now()<runtimeDeadline;
 const phase={off:'VPN выключен',starting:'Запуск VPN',online:'VPN включён',recovering:'Восстановление VPN',no_network:'Нет сети',blocked:'VPN заблокирован политикой',unknown:'Состояние неизвестно'}[r.phase];
 $('inventory-runtime').textContent=recent?`Сообщено: ${phase}`:'Отчёт устарел';
 $('inventory-runtime').dataset.tone=recent?'info':'warning';
 $('inventory-runtime-detail').textContent=`${recent?'По данным клиента':'Последнее сообщение: '+phase} · ${ {none:'Без сети',wifi:'Wi-Fi',cellular:'Мобильная сеть',unknown:'Сеть неизвестна'}[r.network]} · сборка ${r.build} · политика ${r.policyRevision}`;
 const time=$('inventory-runtime-time');time.dateTime=inventoryDate(r.receivedAtMs);time.textContent='Получен сервером: '+new Date(r.receivedAtMs).toLocaleString('ru-RU');time.hidden=false;
 if(recent&&!document.hidden&&$('inventory-view').getClientRects().length)runtimeTimer=setTimeout(renderRuntime,Math.max(1,runtimeDeadline-performance.now()));
}
function runtimeVisible(){return authenticated&&!!layerInventory&&!document.hidden&&$('inventory-view').getClientRects().length>0;}
function scheduleRuntimeRefresh(){
 clearTimeout(runtimeRefreshTimer);runtimeRefreshTimer=null;
 if(!runtimePolling||!runtimeVisible()||runtimeRequest)return;
 runtimeRefreshTimer=setTimeout(()=>{
  runtimeRefreshTimer=null;
  if(!runtimePolling||!runtimeVisible())return;
  if(busy){runtimeRefreshTimer=setTimeout(scheduleRuntimeRefresh,1000);return;}
  void loadRuntime(true).catch(error=>{
   if(['login','denied'].includes(error.message))status(error.message==='login'?'Сессия завершена. Войдите снова.':'Доступ отозван или недостаточно прав.','danger');
  });
 },Math.max(1,runtimeLastStarted+runtimeRefreshMs-performance.now()));
}
function syncRuntimeVisibility(){
 if(runtimeReport)renderRuntime();
 if(runtimeVisible())scheduleRuntimeRefresh();
 else{
  clearTimeout(runtimeRefreshTimer);runtimeRefreshTimer=null;
  if(runtimeRequest?.background){const old=runtimeRequest;runtimeRequest=null;runtimeEpoch++;old.controller.abort();controls();}
 }
}
function loadRuntime(background=false){
 const device=layerInventory?.device;if(!deviceID.test(device||''))throw Error('invalid');
 if(runtimeRequest?.device===device)return runtimeRequest.promise;
 if(!background)clearRuntime();
 const epoch=runtimeEpoch,started=performance.now();runtimeLastStarted=started;runtimePolling=true;
 const owner={device,background,controller:new AbortController(),timedOut:false,promise:null,timeout:null};runtimeRequest=owner;
 owner.timeout=setTimeout(()=>{owner.timedOut=true;owner.controller.abort();},15000);
 if(!background)$('inventory-runtime').textContent='Загружаем состояние…';
 controls();
 owner.promise=(async()=>{try{
   const value=await action('configuration.runtime.get',{id:device},owner.controller.signal);
   if(epoch!==runtimeEpoch||!authenticated||layerInventory?.device!==device)return;
   const checked=checkedRuntime(value,device);runtimeReport=checked?.report||null;runtimeDeadline=started+(checked?.remaining||0);renderRuntime();
  }catch(error){
   if(['login','denied'].includes(error.message))throw error;
   if(epoch!==runtimeEpoch||owner.controller.signal.aborted&&!owner.timedOut)return;
   clearRuntime();$('inventory-runtime').textContent='Состояние недоступно';
   $('inventory-runtime-detail').textContent=error.message==='invalid'?'Сервер вернул некорректный отчёт.':'Повторите обновление состояния. Карточка конфигурации сохранена.';
   runtimePolling=authenticated&&layerInventory?.device===device;scheduleRuntimeRefresh();
  }finally{
   clearTimeout(owner.timeout);
   if(runtimeRequest===owner){runtimeRequest=null;scheduleRuntimeRefresh();}
   controls();
  }})();
 return owner.promise;
}
function openLinkedDevice(){
 const device=linkedDevice();
 if(!device||!authenticated)return;
 $('inventory-device').value=device;
 return loadInventory();
}
function showDraft(draft){
 if(!Number.isSafeInteger(draft.revision)||draft.revision<1)throw Error('invalid');
 opened={id:draft.id,kind:draft.targetKind,target:draft.targetId};revision=draft.revision;
 $('draft-id').value=draft.id;$('target-kind').value=draft.targetKind;$('target-id').value=draft.targetId;
 $('base-revision').value=String(draft.baseRevision);$('base-hash').value=draft.baseHash;$('plan').value=JSON.stringify(draft.plan,null,2);$('route-check-target').value='';$('route-check-ip').value='';$('route-check-country-class').value='';
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
  const button=actionButton();button.textContent='Показать профили';button.onclick=()=>work(async()=>{
   const view=await action('source.snapshot',{id:source.id,snapshot:source.activeSnapshot||''});
   if(!Array.isArray(view.profiles))throw Error('invalid');$('profiles').replaceChildren();
   for(const profile of view.profiles)textItem($('profiles'),`${profile.name} · ${profile.kind} · ${profile.id}`);
   $('source-details').textContent=JSON.stringify({sourceId:source.id,revision:source.revision,networkModes:source.networkModes,snapshot:view.snapshot.id,observedAt:view.snapshot.observedAt,validUntil:view.snapshot.validUntil},null,2);
   status('Метаданные профилей загружены. Учётные данные прокси не выводятся.');
  });const edit=actionButton();edit.textContent='Настроить источник';edit.onclick=()=>work(async()=>{showSource(await action('source.get',{id:source.id}));status('Параметры загружены. Прежний секрет не возвращается.');});li.append(document.createElement('br'),button,edit);
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
async function retry(){
 if(!pending)throw Error('invalid');
 let result;
 try{result=await request(pendingKind==='import'?sourceImportPath:'/control/action',pending);}
 catch(error){if(['invalid','size','importSize'].includes(error.message))pending=null;throw error;}
 if(pendingKind==='source'){
  showSource(result);status('Источник сохранён. Активные политики меняются отдельной публикацией.');
 }else if(pendingKind==='shares'){
  const attempted=JSON.parse(pending).payload;
  const view=validateShares(result);
  if(attempted.id!==sourceIdentity?.id||attempted.revision!==sourceRevision
     ||view.revision!==attempted.shares.revision+1||recipientKey(view.recipients)!==recipientKey(attempted.shares.recipients))throw Error('invalid');
  showSourceShares(view);status('Получатели источника сохранены.');
 }else if(['sync','import'].includes(pendingKind)){
  if(result.sourceId!==sourceIdentity?.id||typeof result.id!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(result.id)
      ||typeof result.phase!=='string'||!Object.hasOwn(jobStates,result.phase))throw Error('invalid');
  sourceJob=result.id;
  $('job-status').textContent=JSON.stringify({id:result.id,sourceId:result.sourceId,phase:result.phase},null,2);
  status('Задание принято. Проверьте результат в истории источника.');
 }else if(pendingKind.startsWith('layer-')){
  acceptLayerMutation(pendingKind,result);
 }else{
  showDraft(result);status('Черновик сохранён. Политики устройств не изменены.');
 }
 pending=null;
}
function clearSource(){sourceRevision=0;sourceIdentity=null;sourceJob='';clearSourceHistory();clearSourceShares();for(const id of ['source-id','source-owner','source-name','source-device','source-resource','source-external','source-until','source-secret','source-import-file'])$(id).value='';$('source-mode').value='server';$('source-format').value='uri';$('source-refresh').value='3600';$('source-stale').value='86400';$('source-enabled').checked=true;$('source-secret-operation').value='keep';for(const option of $('source-modes').options)option.selected=option.value==='wifi';$('source-version').textContent='Источник не выбран';$('job-status').replaceChildren();}
function localDate(seconds){const d=new Date(seconds*1000);if(!Number.isFinite(d.getTime()))throw Error('invalid');return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}
function showSource(s){if(!Number.isSafeInteger(s.revision)||s.revision<1||!Array.isArray(s.networkModes))throw Error('invalid');sourceIdentity={id:s.id,owner:s.owner,mode:s.mode,fetchDeviceId:s.fetchDeviceId||''};sourceRevision=s.revision;sourceJob='';clearSourceHistory();clearSourceShares();$('source-import-file').value='';$('source-id').value=s.id;$('source-owner').value=s.owner;$('source-name').value=s.name;$('source-mode').value=s.mode;$('source-device').value=sourceIdentity.fetchDeviceId;$('source-format').value=s.format;$('source-resource').value=s.resourceId||'';$('source-external').value=s.externalUserId||'';$('source-until').value=localDate(s.validUntil);$('source-refresh').value=String(s.refreshSeconds);$('source-stale').value=String(s.maxStaleSeconds);$('source-enabled').checked=s.enabled;for(const option of $('source-modes').options)option.selected=s.networkModes.includes(option.value);$('source-secret-operation').value='keep';$('source-secret').value='';$('source-version').textContent=`Версия источника: ${s.revision} · ${s.state}`;$('job-status').replaceChildren();}
async function importSource(){
 const field=$('source-import-file'),file=field.files[0];
 if(pending||sourceIdentity?.mode!=='manual'||!file||file.size<1)throw Error('invalid');
 if(file.size>sourceImportBytes)throw Error('importSize');
 const bytes=new Uint8Array(await file.arrayBuffer());
 try{
  if(bytes.length!==file.size||bytes.length>sourceImportBytes)throw Error('invalid');
  const chunks=[],chunkSize=3*8192;
  for(let offset=0;offset<bytes.length;offset+=chunkSize)chunks.push(btoa(String.fromCharCode(...bytes.subarray(offset,offset+chunkSize))));
  pendingKind='import';
  pending=envelope('source.import',{id:sourceIdentity.id,revision:sourceRevision,data:chunks.join('')});
  field.value='';
 }finally{bytes.fill(0);}
 await retry();
}
function clearSourceHistory(){
 sourceHistoryNext='';$('source-history-status').textContent='';$('source-history-list').replaceChildren();
}
function clearSourceShares(){
 sourceShares=null;$('source-shares-kind').value='user';$('source-shares-id').value='';$('source-shares-confirm').checked=false;
 $('source-shares-revision').textContent='';$('source-shares-list').replaceChildren();
}
function recipientKey(recipients){return recipients.map(r=>r.kind+':'+r.id).sort().join('\n');}
function sharesChanged(){return !!sourceShares&&sourceShares.initial!==recipientKey(sourceShares.recipients);}
function validRecipient(item){
 return item&&typeof item.kind==='string'&&Object.hasOwn(recipientKinds,item.kind)
     &&typeof item.id==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(item.id);
}
function validateShares(view){
 if(!view||!Number.isSafeInteger(view.revision)||view.revision<0||!Array.isArray(view.recipients)||view.recipients.length>256
    ||!view.recipients.every(validRecipient))throw Error('invalid');
 const recipients=view.recipients.map(({kind,id})=>({kind,id}));
 if(new Set(recipients.map(r=>r.kind+':'+r.id)).size!==recipients.length)throw Error('invalid');
 return {revision:view.revision,recipients};
}
function renderSourceShares(){
 const list=$('source-shares-list');list.replaceChildren();
 $('source-shares-revision').textContent=`Версия списка: ${sourceShares.revision}`+(sharesChanged()?' · есть правки':'');
 for(const [index,r] of sourceShares.recipients.entries()){
  const item=textItem(list,`${recipientKinds[r.kind]} · ${r.id} `);
  const remove=actionButton();remove.textContent='Удалить';
  remove.onclick=()=>{if(busy||pending||!sourceShares)return;sourceShares.recipients.splice(index,1);$('source-shares-confirm').checked=false;renderSourceShares();controls();};
  item.append(remove);
 }
}
function showSourceShares(view){
 sourceShares={...view,initial:recipientKey(view.recipients)};
 $('source-shares-id').value='';$('source-shares-confirm').checked=false;renderSourceShares();
}
async function loadSourceShares(){
 if(!sourceIdentity)throw Error('invalid');
 showSourceShares(validateShares(await action('source.shares.get',{id:sourceIdentity.id})));
 status('Список получателей загружен.');
}
function addSourceRecipient(){
 const r={kind:$('source-shares-kind').value,id:$('source-shares-id').value.trim()};
 if(!sourceShares||sourceShares.recipients.length>=256||!validRecipient(r)
    ||sourceShares.recipients.some(old=>old.kind===r.kind&&old.id===r.id))throw Error('invalid');
 if(sourceIdentity.mode==='device'&&(r.kind!=='user'||r.id!==sourceIdentity.owner))throw Error('invalid');
 sourceShares.recipients.push(r);$('source-shares-id').value='';$('source-shares-confirm').checked=false;renderSourceShares();
}
async function saveSourceShares(){
 if(!sourceIdentity||!sourceShares||!sharesChanged()||!$('source-shares-confirm').checked||pending)throw Error('invalid');
 const shares={revision:sourceShares.revision,recipients:sourceShares.recipients};
 pendingKind='shares';pending=envelope('source.shares.put',{id:sourceIdentity.id,revision:sourceRevision,shares});
 await retry();
}
async function sourceHistory(more=false){
 const sourceId=sourceIdentity?.id;
 if(!sourceId||more&&!sourceHistoryNext)throw Error('invalid');
 const after=more?sourceHistoryNext:'';
 const page=await action('job.list',{sourceId,after});
 if(page.sourceId!==sourceId||!Array.isArray(page.jobs)||page.jobs.length>20||typeof page.next!=='string'||!/^[A-Za-z0-9_-]{0,128}$/.test(page.next))throw Error('invalid');
 if(page.next&&(page.jobs.length!==20||page.next!==page.jobs[19]?.job?.id||page.next===after))throw Error('invalid');
 const summaries=page.jobs.map(item=>{
  const {job,updatedAt,nextAttemptAt}=item||{};
  if(!job||job.sourceId!==sourceId||typeof job.id!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(job.id)
      ||typeof job.phase!=='string'||!Object.hasOwn(jobStates,job.phase)||!['fetch','resource','manual','device'].includes(job.kind)
      ||!Number.isSafeInteger(job.sourceRevision)||job.sourceRevision<1||!Number.isInteger(job.attempts)||job.attempts<0||job.attempts>8
      ||typeof job.reason!=='string'||!/^[a-z_]{0,64}$/.test(job.reason)||!Number.isSafeInteger(updatedAt)||updatedAt<1
      ||!Number.isSafeInteger(nextAttemptAt)||nextAttemptAt<0)throw Error('invalid');
  const retry=nextAttemptAt? ` · не ранее ${inventoryDate(nextAttemptAt*1000)}`:'';
  const reason=job.reason? ` · ${job.reason}`:'';
  return `${jobStates[job.phase]} · ${job.kind} · v${job.sourceRevision} · попыток ${job.attempts} · ${inventoryDate(updatedAt*1000)}${retry}${reason}`;
 });
 if(!more)clearSourceHistory();
 sourceHistoryNext=page.next;
 for(const summary of summaries)textItem($('source-history-list'),summary);
 $('source-history-status').textContent=summaries.length?'История обновлена.':'Других заданий нет.';
}
async function saveSource(){
 if(pending)throw Error('invalid');const mode=$('source-mode').value,id=$('source-id').value.trim(),owner=$('source-owner').value.trim();
 if(sourceIdentity&&(id!==sourceIdentity.id||owner!==sourceIdentity.owner||mode!==sourceIdentity.mode))throw Error('invalid');
 const source={id,owner,name:$('source-name').value.trim(),mode,format:$('source-format').value,resourceId:mode==='resource'?$('source-resource').value.trim():'',externalUserId:mode==='resource'?$('source-external').value.trim():'',enabled:$('source-enabled').checked,revision:sourceRevision,validUntil:Math.floor(new Date($('source-until').value).getTime()/1000),refreshSeconds:Number($('source-refresh').value),maxStaleSeconds:Number($('source-stale').value),networkModes:[...$('source-modes').selectedOptions].map(o=>o.value)};
 if(!id||!owner||!source.name||!['server','device','manual','resource'].includes(mode)||!Number.isSafeInteger(source.validUntil)||!source.networkModes.length)throw Error('invalid');
 if(mode==='device'){
  const bound=$('source-device').value.trim();
  if(!bound||sourceIdentity?.fetchDeviceId&&sourceIdentity.fetchDeviceId!==bound||!source.networkModes.includes('wifi'))throw Error('invalid');
  source.fetchDeviceId=bound;
 }
 const operation=$('source-secret-operation').value;let secret=JSON.stringify({operation});
 if(operation==='replace'){try{JSON.parse($('source-secret').value);}catch{throw Error('invalid');}secret='{"operation":"replace","value":'+$('source-secret').value+'}';}
 pendingKind='source';pending=JSON.stringify({version:1,action:'source.put',requestId:crypto.randomUUID()}).slice(0,-1)+',"payload":{"source":'+JSON.stringify(source)+',"secret":'+secret+'}}';await retry();
}
$('login').onclick=()=>work(async()=>{const device=linkedDevice();const result=await request('/login',device?{device}:{});const target=new URL(result.url);if(target.protocol!=='https:'&&!(location.hostname==='127.0.0.1'&&target.protocol==='http:'&&target.hostname==='127.0.0.1'))throw Error('invalid');location.assign(target.href);});
$('logout').onclick=()=>work(async()=>{try{await request('/logout',{});}finally{authenticated=false;erase();if(linkedDevice())history.replaceState(null,'','/#inventory-title');}status('Вы вышли. Локальная копия черновика очищена.');});
$('refresh-devices').onclick=()=>work(()=>loadDevices());
$('reauthentication-start').onclick=()=>work(beginReauthentication);
$('reauthentication-check').onclick=()=>work(checkReauthentication);
$('refresh-runtime').onclick=()=>work(loadRuntime);
document.addEventListener('visibilitychange',syncRuntimeVisibility);
$('more-devices').onclick=()=>work(()=>loadDevices(true));
$('load-sources').onclick=()=>work(()=>sources());$('more-sources').onclick=()=>work(()=>sources(true));$('inventory-form').onsubmit=event=>{event.preventDefault();if(authenticated&&!pending)void work(loadInventory);};
$('inventory-device').oninput=()=>{
 clearInventory();clearDraftInventory();$('inventory-status').textContent='';
 if(linkedDevice())history.replaceState(null,'','/#inventory-title');
 layerControls();
};
const desktopNavToggle=$('desktop-nav-toggle');
desktopNavToggle.onclick=()=>setDesktopNavExpanded(desktopNavToggle.getAttribute('aria-expanded')!=='true');
const navToggle=$('console-nav-toggle');
navToggle.onclick=()=>setNavExpanded(navToggle.getAttribute('aria-expanded')!=='true');
document.addEventListener('keydown',event=>{
 if(event.key==='Escape'&&navToggle.getAttribute('aria-expanded')==='true'){
  setNavExpanded(false);
  navToggle.focus();
 }
});
document.addEventListener('pointerdown',event=>{
 if(navToggle.getAttribute('aria-expanded')==='true'&&!event.target.closest('#console-navigation, #console-nav-toggle')){
  setNavExpanded(false);
 }
});
$('console-nav').addEventListener('click',event=>{
 const link=event.target.closest('a');
 if(link&&link.hash===location.hash&&event.button===0&&!event.ctrlKey&&!event.metaKey&&!event.shiftKey&&!event.altKey){
  setNavExpanded(false);
  $(link.hash.slice(1)).focus({preventScroll:true});
 }
});
addEventListener('hashchange',()=>{
 updateSectionNav(true);
 setNavExpanded(false);
 if(authenticated&&!pending&&linkedDevice())void work(openLinkedDevice);
});$('open-draft').onclick=()=>work(openDraft);
$('new-draft').onclick=()=>work(async()=>{revision=0;opened=null;$('draft-id').value=crypto.randomUUID();$('target-kind').value='device';$('target-id').value='';$('base-revision').value='0';$('base-hash').value='';$('plan').value='';$('route-check-target').value='';$('route-check-ip').value='';$('route-check-country-class').value='';$('draft-version').textContent='Новый черновик';status('Новый личный черновик. Выберите адресата и заполните план.');});
$('draft-form').onsubmit=event=>{event.preventDefault();work(save);};$('retry-save').onclick=()=>work(retry);
$('plan').oninput=drawRouteChecks;
$('route-bounds-preview').onclick=()=>work(async()=>{
 const epoch=boundsEpoch,plan=routeDraft().value.adaptive;
 if(!plan||!authenticated)throw Error('invalid');
 const target=$('route-bounds-result');target.replaceChildren();
 const report=await request('/control/route-bounds',plan);
 if(!authenticated||boundsEpoch!==epoch||boundsDraft!==$('plan').value)return;
 if(report.limit!==4096)throw Error('invalid');
 if(report.status==='over_limit'){
  target.textContent='Превышен предел 4096 цепочек на одно назначение. Сузьте список узлов в переходе или уберите часть шаблонов.';
  return;
 }
 const names={RU:'Российский интернет',NON_RU:'Зарубежный интернет',INTERNAL:'Внутренняя сеть'};
 const count=n=>Number.isInteger(n)&&n>0&&n<=report.limit;
 if(report.status!=='ready'||!report.intents||!Array.isArray(report.groups)||!report.groups.length||report.groups.length>16)throw Error('invalid');
 const intents=Object.entries(report.intents);
 if(!intents.length||intents.length>3||intents.some(([id,n])=>!Object.hasOwn(names,id)||!count(n)))throw Error('invalid');
 const groups=report.groups;
 if(groups.some(g=>!g||!Object.hasOwn(report.intents,g.intent)||typeof g.group!=='string'||!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(g.group)||
   !count(g.upperBound)||g.upperBound>report.intents[g.intent]||!Number.isInteger(g.maxHops)||g.maxHops<1||g.maxHops>4))throw Error('invalid');
 const limit=document.createElement('p');
 limit.textContent='Верхняя граница до проверки доступности. Лимит на назначение - 4096.';
 const list=document.createElement('ul');
 for(const [intent,n] of intents){
  const row=document.createElement('li');row.textContent=names[intent]+' - до '+n;
  const children=document.createElement('ul');
  for(const group of groups.filter(g=>g.intent===intent)){
   const child=document.createElement('li');child.textContent=group.group+' - до '+group.upperBound+' цепочек, переходов до '+group.maxHops;children.append(child);
  }
  if(!children.childElementCount)throw Error('invalid');
  row.append(children);list.append(row);
 }
 target.replaceChildren(limit,list);
});
$('route-reserve-cooldown').onchange=()=>{
 const enabled=$('route-reserve-cooldown').checked;
 work(async()=>{
  const state=routeDraft(),failover=internalFailoverPlan(state);
  if(!failover)throw Error('invalid');
  if(enabled)failover.probeCooldown=true;else{delete failover.probeCooldown;delete failover.probeCooldownRollout;}
  applyRouteChecks(state);
 });
};
$('route-rollout-save').onclick=()=>{
 const id=$('route-rollout-id').value.trim(),share=$('route-rollout-share').value;
 work(async()=>{
  const state=routeDraft(),failover=internalFailoverPlan(state);
  if(failover?.probeCooldown!==true)throw Error('invalid');
  const value=readDeviceRollout(id,share);
  if(value)failover.probeCooldownRollout=value;else delete failover.probeCooldownRollout;
  applyRouteChecks(state);
 });
};
$('route-decision').onchange=()=>{
 const selected=$('route-decision').value;
 work(async()=>{
  const state=routeDraft(),failover=internalFailoverPlan(state);
  if(!failover)throw Error('invalid');
  if(selected===confirmedDecision)failover.decisionRevision=selected;
  else{delete failover.decisionRevision;delete failover.decisionRollout;}
  applyRouteChecks(state);
 });
};
$('route-decision-save').onclick=()=>{
 const id=$('route-decision-id').value.trim(),share=$('route-decision-share').value;
 work(async()=>{
  const state=routeDraft(),failover=internalFailoverPlan(state);
  if(failover?.decisionRevision!==confirmedDecision)throw Error('invalid');
  const value=readDeviceRollout(id,share);
  if(value)failover.decisionRollout=value;else delete failover.decisionRollout;
  applyRouteChecks(state);
 });
};
$('route-check-path').onchange=drawRouteChecks;
$('route-check-required').onchange=()=>{
 const selected=$('route-check-path').value,value=$('route-check-required').checked;
 try{if(!routeDraft().checks.some(row=>row.outbound===selected))return;}catch{return;}
 work(async()=>{
  const current=routeDraft(),row=current.checks.find(r=>r.outbound===selected);
  if(!row)throw Error('invalid');
  row.required=value;applyRouteChecks(current);
 });
};
$('route-check-method').onchange=()=>{$('route-check-ip').value='';$('route-check-country-class').value='';drawRouteChecks();};
$('route-check-add').onclick=()=>{
 const path=$('route-check-path').value,method=$('route-check-method').value,target=$('route-check-target').value.trim();
 const expectedIP=$('route-check-ip').value.trim();
 const required=$('route-check-required').checked;
 work(async()=>{
  const current=routeDraft();
  if(!current.tags.has(path)||!Object.hasOwn(routeCheckMethods,method)||!target||target.length>2048||/[^!-~]/.test(target))throw Error('invalid');
  const check={method,target};
  if(method==='https_exit_country'){
   const country=$('route-check-country-class').value;
   if(!Object.hasOwn(exitCountryLabels,country)||!validProbeHTTPS(target)||!/^https:\/\/[^/?#]+\/?$/.test(target))throw Error('invalid');
   check.expected_exit_class=country;
  }
  if(method==='https_exit_ip'){
   if(!/^[0-9a-fA-F:.]{2,45}$/.test(expectedIP)||!validProbeHTTPS(target))throw Error('invalid');
   check.expected_ip=expectedIP;
  }
  if(method==='https_status'){
   const verb=$('route-check-verb').value,code=$('route-check-status').value;
   if(!validProbeHTTPS(target)||!['HEAD','GET'].includes(verb)||!/^[2-5][0-9]{2}$/.test(code))throw Error('invalid');
   check.http_method=verb;check.expected_status=Number(code);
  }
  let group=current.checks.find(row=>row.outbound===path);
  if(!group){if(current.checks.length>=16)throw Error('invalid');group={outbound:path,required,checks:[]};current.checks.push(group);}
  if(group.profile||group.checks.length>=4||group.checks.some(row=>sameRouteCheck(row,check)))throw Error('invalid');
  group.required=required;group.checks.push(check);applyRouteChecks(current);$('route-check-target').value='';$('route-check-ip').value='';
 });
};
$('discard-save').onclick=()=>work(async()=>{const kind=pendingKind,sourceId=$('source-id').value.trim();pending=null;if(kind.startsWith('layer-')){layerPreview=null;layerJob=null;await loadLayerDraft();}else if(kind==='draft')await openDraft();else if(sourceId)showSource(await action('source.get',{id:sourceId}));});
$('new-source').onclick=()=>work(async()=>{const owner=$('owner').value.trim();clearSource();$('source-id').value=crypto.randomUUID();$('source-owner').value=owner;$('source-until').value=localDate(Math.floor(Date.now()/1000)+30*86400);$('source-version').textContent='Новый источник';status('Заполните параметры. Для нового HTTPS источника укажите новые учётные данные.');});
$('source-form').onsubmit=event=>{event.preventDefault();work(saveSource);};
$('source-secret-operation').onchange=controls;$('source-mode').onchange=controls;
$('inspect-provider').onclick=()=>work(inspectProvider);
for(const id of ['source-id','source-owner','source-resource'])$(id).addEventListener('input',updateProviderControls);
$('sync-source').onclick=()=>work(async()=>{if(pending||!sourceIdentity)throw Error('invalid');pendingKind='sync';pending=envelope('source.sync',{id:sourceIdentity.id,revision:sourceRevision});await retry();});
$('source-job').onclick=()=>work(async()=>{if(!sourceJob)throw Error('invalid');$('job-status').textContent=JSON.stringify(await action('job.get',{id:sourceJob}),null,2);status('Состояние задания обновлено.');});
$('source-history').onclick=()=>work(()=>sourceHistory());
$('source-history-more').onclick=()=>work(()=>sourceHistory(true));
$('source-import-file').onchange=controls;
$('source-import').onclick=()=>work(importSource);
$('source-shares-load').onclick=()=>work(loadSourceShares);
$('source-shares-add').onclick=()=>work(addSourceRecipient);
$('source-shares-confirm').onchange=controls;
$('source-shares-save').onclick=()=>work(saveSourceShares);
updateSectionNav();
controls();
void work(async()=>{
 sessionCapabilities(await request('/session',{}));authenticated=true;status('');
 await loadDevices();
 await openLinkedDevice();
});

function clearLayerReview(){layerPreview=null;$('layer-confirm').checked=false;$('layer-review').hidden=true;$('layer-impact').textContent='';}
function clearLayerComparison(){layerComparison=null;$('layer-comparison').hidden=true;$('layer-diff').textContent='';$('layer-conflicts').replaceChildren();}
function clearDraftInventory(){layerDraftInventory=null;$('layer-saved').replaceChildren();$('layer-list-status').textContent='';}
function clearLayers(){$('layer-discard-confirm').checked=false;layerInventory=null;layerRevision=0;layerOpened=null;layerSaved=null;layerJob=null;clearDraftInventory();clearLayerReview();clearLayerComparison();for(const id of ['layer-id','layer-proposal'])$(id).value='';$('layer-job').textContent='';$('layer-version').textContent='Черновик слоёв не открыт';$('layer-result').textContent='Результат публикации не является подтверждением активации Android.';}
function layerUnchanged(){return !!layerSaved&&$('layer-id').value.trim()===layerSaved.id&&$('layer-proposal').value===layerSaved.text;}
function layerControls(){
 const disabled=busy||!authenticated||!!pending;
 for(const id of ['layer-id','layer-proposal','layer-load','layer-save','layer-confirm'])$(id).disabled=disabled||!!layerJob;
 $('layer-from-device').disabled=disabled||!!layerJob||!layerInventory||layerInventory.state==='unassigned';
 const first=layerInventory?.state==='unassigned';
 $('layer-first-device').hidden=!first;
 $('layer-first-mode').disabled=disabled||!!layerJob;
 $('layer-first-from-plan').disabled=disabled||!!layerJob||!first||
  !!$('layer-proposal').value.trim()&&!layerUnchanged();
 $('layer-preview').disabled=disabled||!layerUnchanged()||!!layerJob;
 $('layer-poll').disabled=disabled||!layerJob;
 $('layer-publish').disabled=disabled||!!layerJob||!layerUnchanged()||!layerPreview||!$('layer-confirm').checked||layerPreview.preview.expiresAtMs<=Date.now();
 $('layer-compare').disabled=disabled||!!layerJob;
 $('layer-merge').disabled=disabled||!!layerJob||!layerComparison?.result?.ready;
 $('layer-list').disabled=disabled||!!layerJob;$('layer-saved').disabled=disabled||!!layerJob||!layerDraftInventory?.drafts.length;
 $('layer-open-saved').disabled=disabled||!!layerJob||!layerDraftInventory?.drafts.length;
 $('layer-discard-confirm').disabled=disabled||!!layerJob||!layerSaved;
 $('layer-discard').disabled=disabled||!!layerJob||!layerSaved||!$('layer-discard-confirm').checked;
 for(const button of $('layer-conflicts').querySelectorAll('button'))button.disabled=disabled||!!layerJob;
}
function layerProposal(){
 let proposal;try{proposal=JSON.parse($('layer-proposal').value);}catch{throw Error('invalid');}
 const id=$('layer-id').value.trim();
 if(!/^[A-Za-z0-9_-]{1,64}$/.test(id)||!proposal||Array.isArray(proposal)||proposal.draftId!==id||proposal.draftRevision!==layerRevision+1||!Array.isArray(proposal.bundles)||!proposal.bundles.length||proposal.bundles.length>64||layerOpened&&(id!==layerOpened.id||proposal.targetKind!==layerOpened.kind||proposal.targetId!==layerOpened.target))throw Error('invalid');
 return proposal;
}
function showLayerDraft(draft){
 const p=draft&&draft.proposal;
 if(!draft||typeof draft.id!=='string'||!Number.isSafeInteger(draft.revision)||draft.revision<1||!Number.isSafeInteger(draft.savedAtMs)||draft.savedAtMs<1||!p||p.draftId!==draft.id||p.draftRevision!==draft.revision||!Array.isArray(p.bundles))throw Error('invalid');
 $('layer-discard-confirm').checked=false;layerRevision=draft.revision;layerOpened={id:draft.id,kind:p.targetKind,target:p.targetId};
 $('layer-id').value=draft.id;$('layer-proposal').value=JSON.stringify(p,null,2);
 layerSaved={id:draft.id,proposal:structuredClone(p),text:$('layer-proposal').value};
 layerJob=null;clearLayerReview();clearLayerComparison();$('layer-job').textContent='';$('layer-version').textContent=`Сохранённая версия слоёв: ${draft.revision}`;
}
async function loadLayerDraft(){
 const id=$('layer-id').value.trim();if(!/^[A-Za-z0-9_-]{1,64}$/.test(id))throw Error('invalid');
 const saved=await action('configuration.layers.draft.get',{id});if(saved.id!==id)throw Error('invalid');showLayerDraft(saved);
 status('Черновик слоёв загружен. Для новой правки версия предложения увеличивается при сохранении.');
}
function draftInventoryTarget(){
 let targetKind='device',targetId=$('inventory-device').value.trim();
 if($('layer-proposal').value.trim()){
  let proposal;try{proposal=JSON.parse($('layer-proposal').value);}catch{throw Error('invalid');}
  targetKind=proposal?.targetKind;targetId=proposal?.targetId;
 }
 if(!['template','group','user','device'].includes(targetKind)||typeof targetId!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(targetId))throw Error('invalid');
 return {targetKind,targetId};
}
async function listLayerDrafts(){
 const scope=draftInventoryTarget();clearDraftInventory();
 const result=await action('configuration.layers.drafts.list',scope);
 if(!result||Object.keys(result).sort().join(',')!=='drafts,targetId,targetKind'||result.targetKind!==scope.targetKind||result.targetId!==scope.targetId||!Array.isArray(result.drafts)||result.drafts.length>64)throw Error('invalid');
 const ids=new Set();
 for(const row of result.drafts){
  if(!row||Object.keys(row).sort().join(',')!=='id,revision,savedAtMs'||typeof row.id!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(row.id)||ids.has(row.id)||!Number.isSafeInteger(row.revision)||row.revision<1||!Number.isSafeInteger(row.savedAtMs)||row.savedAtMs<1)throw Error('invalid');
  ids.add(row.id);
 }
 layerDraftInventory=structuredClone(result);
 for(const row of result.drafts){const option=document.createElement('option');option.value=row.id;option.textContent=`${row.id} - версия ${row.revision}`;$('layer-saved').append(option);}
 $('layer-list-status').textContent=result.drafts.length?`Сохранённых копий: ${result.drafts.length}`:'Для этого адресата нет сохранённых черновиков.';
 status('Список загружен. Открытие копии выполняется отдельной кнопкой.');
}
$('layer-list').onclick=()=>work(listLayerDrafts);
$('layer-open-saved').onclick=()=>work(async()=>{
 const inventory=layerDraftInventory,id=$('layer-saved').value,row=inventory?.drafts.find(x=>x.id===id);if(!row)throw Error('invalid');
 const saved=await action('configuration.layers.draft.get',{id});
 if(!saved||saved.id!==id||saved.revision<row.revision||saved.proposal?.targetKind!==inventory.targetKind||saved.proposal?.targetId!==inventory.targetId)throw Error('invalid');
 showLayerDraft(saved);status('Сохранённая копия открыта. Проверьте правку перед сохранением и публикацией.');
});
function editDeviceLayer(){
 if(!layerInventory||layerInventory.state==='unassigned')throw Error('invalid');
 const v=structuredClone(layerInventory),layers=v.layers;
 let own=layers.find(layer=>layer.kind==='device'&&layer.id===v.device);
 if(own){if(own.revision>=Number.MAX_SAFE_INTEGER)throw Error('invalid');own.revision++;}
 else{own={id:v.device,kind:'device',priority:0,revision:1,changes:[],permissions:[]};layers.push(own);}
 setNewLayerDraft(v,v.mode,layers,Math.max(v.approvalUntilMs,Date.now()+3600000));
 status('Наследованные слои сохранены. Внесите изменения в changes слоя device и сохраните черновик.');
}
function firstDeviceLayer(){
 const v=layerInventory,mode=$('layer-first-mode').value;
 if(v?.state!=='unassigned'||!['home_wifi','wifi','cellular_restricted','cellular'].includes(mode)||
   $('layer-proposal').value.trim()&&!layerUnchanged())throw Error('invalid');
 let plan;
 try{plan=routeDraft().value;}catch{throw Error('invalid');}
 if(plan.schemaVersion!==1||!['activation,graph,network,schemaVersion','activation,adaptive,graph,network,schemaVersion'].includes(Object.keys(plan).sort().join(','))||
    !plan.activation||typeof plan.activation!=='object'||Array.isArray(plan.activation))throw Error('invalid');
 const changes=Object.entries(plan).map(([key,value])=>({path:'/'+key,operation:'set',value}));
 const template={id:crypto.randomUUID(),kind:'template',priority:0,revision:1,changes,permissions:[]};
 setNewLayerDraft(v,mode,[template],Date.now()+3600000);
 status('Первый черновик создан в редакторе. Сохраните его и запросите предварительную проверку.');
}
function setNewLayerDraft(device,mode,layers,approvalUntilMs){
 layerRevision=0;layerOpened=null;layerSaved=null;layerJob=null;clearLayerReview();clearLayerComparison();
 const id=crypto.randomUUID();$('layer-id').value=id;
 $('layer-proposal').value=JSON.stringify({draftId:id,draftRevision:1,targetKind:'device',targetId:device.device,mode,approvalUntilMs,bundles:[{device:device.device,baseRevision:device.revision,baseHash:device.hash,layers}]},null,2);
 $('layer-version').textContent='Новый черновик слоёв';$('layer-job').textContent='';
}
function acceptLayerMutation(kind,result){
 if(kind==='layer-discard'){
  const submitted=JSON.parse(pending).payload;
  if(!result||Object.keys(result).sort().join(',')!=='discarded,id,revision'||result.discarded!==true||result.id!==submitted.id||result.revision!==submitted.revision)throw Error('invalid');
  layerSaved=null;layerOpened=null;layerRevision=0;clearLayerReview();clearLayerComparison();clearDraftInventory();$('layer-discard-confirm').checked=false;
  // Retain unsaved text. A future save requires the user to start/open a new
  // draft; the discarded ID is never silently reused or rewritten.
  $('layer-version').textContent='Сохранённый черновик удалён';
  status('Сохранённая копия удалена. Текст остался в редакторе; для сохранения создайте новый черновик. Желаемая конфигурация не изменена.');return;
 }

 if(kind==='layer-save'){
  const submitted=JSON.parse(pending).payload.draft;
  if(result.id!==submitted.id||result.revision!==submitted.revision+1||result.proposal?.targetKind!==submitted.proposal.targetKind||result.proposal?.targetId!==submitted.proposal.targetId)throw Error('invalid');
  showLayerDraft(result);status('Личный черновик слоёв сохранён. Желаемые конфигурации не изменены.');return;
 }
 if(!result||typeof result.id!=='string'||!['queued','running','ready','published','rejected','expired','cancelled'].includes(result.state))throw Error('invalid');
 layerJob={id:result.id,kind};clearLayerReview();$('layer-job').textContent=JSON.stringify(result,null,2);
 status(kind==='layer-preview'?'Предварительная проверка поставлена в очередь.':'Публикация поставлена в очередь. Проверьте результат задания.');
}
async function saveLayerDraft(){
 if(pending||layerJob)throw Error('invalid');
 let proposal;try{proposal=JSON.parse($('layer-proposal').value);}catch{throw Error('invalid');}
 // The displayed saved proposal retains its saved revision. A new edit always
 // advances it explicitly in the transmitted draft, never in inherited layers.
 if(proposal?.draftRevision===layerRevision&&layerRevision>0)proposal.draftRevision++;
 const prior=$('layer-proposal').value;$('layer-proposal').value=JSON.stringify(proposal,null,2);
 try{proposal=layerProposal();}catch(error){$('layer-proposal').value=prior;throw error;}
 clearLayerReview();pendingKind='layer-save';pending=envelope('configuration.layers.draft.put',{draft:{id:$('layer-id').value.trim(),revision:layerRevision,proposal,savedAtMs:0}});await retry();
}
function checkedLayerPreview(result){
 const p=result&&result.preview,saved=layerSaved?.proposal;
 if(!saved||!result||typeof result.previewId!=='string'||typeof result.ticket!=='string'||result.ticket.length<24||!p||p.schemaVersion!==1||p.draftId!==saved.draftId||p.draftRevision!==saved.draftRevision||p.targetKind!==saved.targetKind||p.targetId!==saved.targetId||p.mode!==saved.mode||!Number.isSafeInteger(p.expiresAtMs)||p.expiresAtMs<=Date.now()||p.expiresAtMs>Date.now()+180000||!Array.isArray(p.recipients)||p.recipients.length!==saved.bundles.length||!/^([0-9a-f]{64})$/.test(p.effectiveHash)||!/^([0-9a-f]{64})$/.test(p.dependencyHash))throw Error('invalid');
 const seen=new Set();for(const r of p.recipients){const bundle=saved.bundles.find(b=>b.device===r.device);if(!bundle||seen.has(r.device)||r.baseRevision!==bundle.baseRevision||r.baseHash!==bundle.baseHash)throw Error('invalid');seen.add(r.device);}
 return result;
}
async function pollLayerJob(){
 if(!layerJob)throw Error('invalid');const job=layerJob,view=await action('configuration.request.get',{id:job.id});
 if(view.id!==job.id||!['queued','running','ready','published','rejected','expired','cancelled'].includes(view.state))throw Error('invalid');
 $('layer-job').textContent=JSON.stringify({id:view.id,state:view.state,error:view.error||''},null,2);
 if(['queued','running'].includes(view.state)){status('Задание ещё выполняется.');return;}
 layerJob=null;clearLayerReview();
 if(view.state==='ready'&&job.kind==='layer-preview'){
  if(!layerUnchanged())throw Error('invalid');layerPreview=checkedLayerPreview(view.result);
  const p=layerPreview.preview;$('layer-impact').textContent=JSON.stringify({targetKind:p.targetKind,targetId:p.targetId,mode:p.mode,recipients:p.recipients.map(r=>({device:r.device,owner:r.owner,baseRevision:r.baseRevision,baseHash:r.baseHash})),effectiveHash:p.effectiveHash,dependencyHash:p.dependencyHash,expiresAt:inventoryDate(p.expiresAtMs),proposal:layerSaved.proposal},null,2);
  $('layer-review').hidden=false;status('Проверка сервера завершена. Просмотрите предложение и адресатов, затем подтвердите публикацию.');return;
 }
 if(view.state==='published'&&job.kind==='layer-publish'){
  layerInventory=null;layerSaved=null;$('layer-result').textContent='Желаемая конфигурация опубликована. Активация Android ещё не подтверждена. Перед следующей правкой загрузите актуальную конфигурацию устройства.';status('Желаемые версии опубликованы атомарно. Подтверждение активации устройства проверяется отдельно.');return;
 }
 status(view.error==='configuration_conflict'?'Конфликт исходной версии. Сохранённый черновик сохранён; загрузите актуальную конфигурацию и сравните изменения.':'Задание отклонено или истекло. Изменения не подтверждены; проверьте права, источники и исходные версии.');
}
$('layer-from-device').onclick=()=>work(async()=>editDeviceLayer());
$('layer-first-from-plan').onclick=()=>work(async()=>firstDeviceLayer());
$('layer-load').onclick=()=>work(loadLayerDraft);$('layer-save').onclick=()=>work(saveLayerDraft);
$('layer-id').oninput=$('layer-proposal').oninput=()=>{clearLayerReview();clearLayerComparison();layerControls();};
$('layer-confirm').onchange=$('layer-discard-confirm').onchange=layerControls;
$('layer-discard').onclick=()=>work(async()=>{
 if(pending||layerJob||!layerSaved||!$('layer-discard-confirm').checked)throw Error('invalid');
 const p=layerSaved.proposal;clearLayerReview();pendingKind='layer-discard';
 pending=envelope('configuration.layers.draft.discard',{id:layerSaved.id,revision:layerRevision,targetKind:p.targetKind,targetId:p.targetId});await retry();
});
$('layer-preview').onclick=()=>work(async()=>{if(pending||layerJob||!layerUnchanged())throw Error('invalid');clearLayerReview();pendingKind='layer-preview';pending=envelope('configuration.preview.request',{proposal:layerSaved.proposal});await retry();});
$('layer-poll').onclick=()=>work(pollLayerJob);
$('layer-publish').onclick=()=>work(async()=>{if(pending||layerJob||!layerUnchanged()||!$('layer-confirm').checked)throw Error('invalid');const result=checkedLayerPreview(layerPreview);pendingKind='layer-publish';pending=envelope('configuration.publish',{previewId:result.previewId,ticket:result.ticket});await retry();});

function renderLayerComparison(){
 const s=layerComparison;s.result=mergeDeviceProposal(s.base,s.current,s['local'],s.choices);
 $('layer-diff').textContent=JSON.stringify({base:s.base,local:s['local'],current:s.current,merged:s.result.proposal},null,2);
 const list=$('layer-conflicts');list.replaceChildren();
 for(const conflict of s.result.conflicts){
  const item=textItem(list,`${conflict.path} · исходное: ${JSON.stringify(conflict.base)??'отсутствует'} · локальное: ${JSON.stringify(conflict['local'])??'отсутствует'} · серверное: ${JSON.stringify(conflict.remote)??'отсутствует'} · выбор: ${conflict.choice||'не выбран'}`);
  for(const [choice,label] of [['local','Оставить локальное'],['remote','Оставить серверное']]){const button=actionButton();button.textContent=label;button.onclick=()=>{s.choices[conflict.path]=choice;renderLayerComparison();layerControls();};item.append(document.createElement('br'),button);}
 }
 if(!s.result.conflicts.length)textItem(list,'Конфликтов значений нет. Проверьте обновлённые родительские слои и результат.');
 $('layer-comparison').hidden=false;
}
$('layer-compare').onclick=()=>work(async()=>{
 if(layerJob||pending)throw Error('invalid');clearLayerReview();clearLayerComparison();
 let local;try{local=JSON.parse($('layer-proposal').value);}catch{throw Error('invalid');}
 if(local?.targetKind!=='device'||local.bundles?.length!==1)throw Error('invalid');const bundle=local.bundles[0];
 const current=await action('configuration.inventory.get',{id:local.targetId});
 const base=bundle.baseRevision===0?{device:local.targetId,owner:current.owner,revision:0,hash:'',layers:[],mode:local.mode,approvalUntilMs:local.approvalUntilMs}:await action('configuration.history.get',{id:local.targetId,revision:bundle.baseRevision,hash:bundle.baseHash});
 layerComparison={base,current,local,choices:Object.create(null),result:null};renderLayerComparison();status('Сравните исходную, локальную и текущую версии. Разрешите каждый конфликт перед переносом в черновик.');
});
$('layer-merge').onclick=()=>work(async()=>{
 const s=layerComparison;if(!s?.result.ready||pending||layerJob)throw Error('invalid');
 const result=mergeDeviceProposal(s.base,s.current,s['local'],s.choices);if(!result.ready)throw Error('invalid');result.proposal.draftRevision=layerRevision+1;
 $('layer-proposal').value=JSON.stringify(result.proposal,null,2);clearLayerReview();clearLayerComparison();status('Результат сравнения перенесён только в редактор. Сохраните, повторно проверьте и явно опубликуйте.');
});
