import {mergeDeviceProposal} from './layer-merge.js';
const $=id=>document.getElementById(id);
const sourceImportPath='/control/source/import';
const sourceImportBytes=10*1024*1024;
const jobStates={queued:'В очереди',running:'Выполняется',succeeded:'Завершено',failed:'Ошибка',cancelled:'Отменено',dead_letter:'Истёк срок или лимит повторов'};
const recipientKinds={user:'Пользователь',device:'Устройство',group:'Группа'};
let authenticated=false,busy=false,pending=null,revision=0,opened=null,next='',listedOwner='';
let pendingKind='draft',sourceRevision=0,sourceIdentity=null,sourceJob='',sourceHistoryNext='';
let reviewEpoch=0,reviewAvailable=false,sourceReview=null,reviewChanges=[],reviewOffset=0;
let sourceSnapshotEpoch=0,sourceDetailLoading=false;
let layerInventory=null,layerRevision=0,layerOpened=null,layerSaved=null,layerJob=null,layerPreview=null;
let layerComparison=null;
let layerDraftInventory=null;
let inventoryEpoch=0;
let sourceShares=null;
let providerContext=null,providerEpoch=0;
let providerEdit=null;
let devicesNext='',devicePrefix='',deviceIds=new Set(),devicesEpoch=0;
const deviceFavorites=new Set();
let reauthenticationAvailable=false,reauthenticationNeeded=false,reauthenticationIssuer='',reauthenticationFocus=false;
let runtimeReport=null,runtimeDeadline=0,runtimeTimer=null,runtimeEpoch=0;
let runtimeRefreshTimer=null,runtimeRequest=null,runtimePolling=false,runtimeLastStarted=0;
let boundsDraft=null,boundsEpoch=0;
let cohortRequest=null,cohortInputs=null;
let explanationEpoch=0,explanationContext='';
let replayEpoch=0;
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
const supportedPolicyAlgorithms=new Set(['m1-local-v1',confirmedDecision,'m4-graph-tcp-v1']);
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
const homeFields = ['address','hostname','port','pin'];
let homeDocument, homeSubject;
function showHomeProof(current, changed) {
 const form=$('home-proof'), enabled=!!current?.value.adaptive;
 form.hidden=!enabled;
 form.disabled=!enabled||busy||!!pending;
 const proof=current?.network.homeProof;
 $('home-remove').disabled=!enabled||!Object.hasOwn(current.network,'homeProof');
 if(!changed)return;
 const values=enabled&&proof&&typeof proof==='object'?proof:{};
 for(const key of homeFields) {
  const value=key==='pin'?values.spkiSha256:values[key];
  $('home-'+key).value=typeof value==='string'||key==='port'&&Number.isInteger(value)?String(value):'';
 }
 $('home-feedback').textContent='';
}
const supportedModes=['HOME_WIFI','WIFI','CELLULAR_RESTRICTED','CELLULAR'];
function updateDurationControl() {
 const permitted=supportedModes.some(mode=>$('mode-allow-'+mode).checked);
 $('mode-minutes').disabled=!permitted;
}
function showModeSelection(current,changed) {
 const form=$('mode-selection'), enabled=!!current?.value.adaptive;
 form.hidden=!enabled;
 form.disabled=!enabled||busy||!!pending;
 const rule=current?.network.modeSelection;
 $('mode-remove').disabled=!enabled||!rule;
 if(!changed)return;
 $('mode-preferred').value=rule?.preferredMode??'AUTO';
 for(const mode of supportedModes)$('mode-allow-'+mode).checked=Array.isArray(rule?.userModes)&&rule.userModes.includes(mode);
 $('mode-minutes').value=rule?.maxOverrideMinutes>0?String(rule.maxOverrideMinutes):'60';
 $('mode-feedback').textContent='';
 updateDurationControl();
}
for(const mode of supportedModes)$('mode-allow-'+mode).onchange=updateDurationControl;
function changeModeSelection(remove) {
 if(!authenticated||busy||pending||homeDocument!==$('plan').value||homeSubject!==profileSubject())return;
 const state=routeDraft();
 if(!state.value.adaptive)return;
 const notice=$('mode-feedback');
 if(remove) delete state.network.modeSelection;
 else {
  const preferredMode=$('mode-preferred').value;
  const userModes=supportedModes.filter(mode=>$('mode-allow-'+mode).checked);
  const minutes=$('mode-minutes').value.trim();
  if(!state.network.homeProof&&(preferredMode==='HOME_WIFI'||userModes.includes('HOME_WIFI'))){
   notice.textContent='Сначала укажите узел для проверки домашнего Wi-Fi.';
   (preferredMode==='HOME_WIFI'?$('mode-preferred'):$('mode-allow-HOME_WIFI')).focus();return;
  }
  if(userModes.length&&(!/^[1-9][0-9]{0,3}$/.test(minutes)||Number(minutes)>1440)){
   notice.textContent='Выберите срок от 1 до 1440 минут.';$('mode-minutes').focus();return;
  }
  state.network.modeSelection={preferredMode,userModes,maxOverrideMinutes:userModes.length?Number(minutes):0};
 }
 const next=JSON.stringify(state.value,null,2);
 if(new TextEncoder().encode(next).length>262144){notice.textContent='План превышает допустимый размер.';return;}
 $('plan').value=next;drawRouteChecks();
 notice.textContent=remove?'Назначение режима удалено из черновика.':'Назначение режима записано в черновик.';
}
$('mode-apply').onclick=()=>changeModeSelection(false);
$('mode-remove').onclick=()=>changeModeSelection(true);
function privateHomeAddress(raw) {
 if(raw.includes(':')) {
  if(!/^f[cd][0-9a-f]{2}:[0-9a-f:]+$/i.test(raw))return false;
  try {return !!new URL('https://['+raw+']/').hostname;}catch{return false;}
 }
 if(!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(raw))return false;
 const [first,second,...rest]=raw.split('.').map(Number);
 return [first,second,...rest].every(n=>n<=255)&&(first===10||first===172&&second>=16&&second<=31||first===192&&second===168);
}
function updateHomeProof(remove) {
 if(!authenticated||busy||pending)return;
 const state=routeDraft();
 if(!state.value.adaptive||homeDocument!==$('plan').value||homeSubject!==profileSubject())return;
 const notice=$('home-feedback');
 if(remove) {
  const mode=state.network.modeSelection;
  if(mode?.preferredMode==='HOME_WIFI'||Array.isArray(mode?.userModes)&&mode.userModes.includes('HOME_WIFI')){
   notice.textContent='Сначала уберите домашний режим из настроек выбора сети.';return;
  }
  delete state.network.homeProof;
 }
 else {
  const [address,hostname,port,pin]=homeFields.map(key=>$('home-'+key).value.trim());
  const labels=hostname.split('.');
  let field,message;
  if(!privateHomeAddress(address)){field='address';message='Введите частный IPv4-адрес или IPv6 ULA.';}
  else if(hostname.length>253||labels.length<2||labels.some(label=>!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))||
    /^\d+$/.test(labels.at(-1))||hostname.endsWith('.localhost')){field='hostname';message='Введите DNS-имя из сертификата в нижнем регистре.';}
  else if(!/^[1-9]\d{0,4}$/.test(port)||Number(port)>65535){field='port';message='Укажите порт от 1 до 65535.';}
  else if(!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(pin)){field='pin';message='Нужен SHA-256 от открытого ключа в формате base64url без дополнения.';}
  if(field){notice.textContent=message;$('home-'+field).focus();return;}
  state.network.homeProof={hostname,address,port:Number(port),spkiSha256:pin};
 }
 const next=JSON.stringify(state.value,null,2);
 if(new TextEncoder().encode(next).length>262144){notice.textContent='План превышает допустимый размер.';return;}
 $('plan').value=next;
 drawRouteChecks();
 notice.textContent=remove?'Узел удалён из черновика.':'Узел записан в черновик.';
}
$('home-apply').onclick=()=>updateHomeProof(false);
$('home-remove').onclick=()=>updateHomeProof(true);
// Unsubmitted parameters belong to one route in the current private draft.
const probeEntryDefaults={
 'route-check-method':'tcp','route-check-target':'','route-check-ip':'',
 'route-check-verb':'HEAD','route-check-status':'200','route-check-country-class':'',
};
const probeEntries=new Map();
let probeEntrySubject=null,probeEntryPath='';
function selectProbeEntry(subject,path,tags){
 const newSubject=path?subject:null;
 if(newSubject===probeEntrySubject&&path===probeEntryPath)return;
 if(newSubject!==probeEntrySubject){
  probeEntries.clear();
 }else if(probeEntryPath&&tags.has(probeEntryPath)){
  const entry={required:$('route-check-required').checked};
  for(const id of Object.keys(probeEntryDefaults))entry[id]=$(id).value;
  probeEntries.set(probeEntryPath,entry);
 }
 for(const tag of probeEntries.keys())if(!tags?.has(tag))probeEntries.delete(tag);
 probeEntrySubject=newSubject;probeEntryPath=path;
 const entry=probeEntries.get(path);
 for(const [id,initial] of Object.entries(probeEntryDefaults))$(id).value=entry?.[id]??initial;
 $('route-check-required').checked=entry?.required===true;
}
function drawRouteChecks(){
 const draft=authenticated?$('plan').value:null;
 const subject=profileSubject(), changed=homeDocument!==draft||homeSubject!==subject;
 homeDocument=draft;homeSubject=subject;
 const context=JSON.stringify([authenticated,$('draft-id').value,$('target-kind').value,$('target-id').value]);
 if(explanationContext!==context)$('cohort-device').value='';
 if(explanationContext!==context||boundsDraft!==draft){explanationContext=context;resetExplanation(true);clearCohortPreview();}
 $('cohort-preview').hidden=true;
 $('route-explanation').hidden=true;
 $('explain-run').disabled=true;
 if(boundsDraft!==draft){boundsDraft=draft;boundsEpoch++;$('route-bounds-result').replaceChildren();closeRouteProfile();}
 $('route-profile-open').disabled=true;
 $('route-bounds').hidden=true;$('route-bounds-preview').disabled=true;
 const editor=$('route-check-editor'),select=$('route-check-path'),list=$('route-check-list');
 $('route-profile-note').hidden=true;
 $('route-check-add').disabled=true;
 const cooldown=$('route-reserve-cooldown');cooldown.checked=false;cooldown.disabled=true;
 const rollout=$('route-cooldown-rollout');rollout.hidden=true;
 drawDeviceRollout('route-rollout',null);
 const decision=$('route-decision');decision.value='';decision.disabled=true;
 $('route-decision-rollout').hidden=true;
 drawDeviceRollout('route-decision',null);
 const prior=select.value;select.replaceChildren();list.replaceChildren();editor.disabled=true;
 let state;
 if(authenticated){try{state=routeDraft();}catch{ /* An incomplete raw draft has no editable fields. */ }}
 showHomeProof(state,changed);
 showModeSelection(state,changed);
 if(!state){selectProbeEntry(null,'',null);return;}
 $('route-explanation').hidden=false;
 $('explain-run').disabled=busy||!!pending||!['domain','address','application'].some(key=>$('explain-'+key).value.trim());
 if(state.value.adaptive){$('route-bounds').hidden=false;$('route-bounds-preview').disabled=busy||!!pending;}
 for(const tag of [...state.tags].sort()){const option=document.createElement('option');option.value=tag;option.textContent=tag;select.append(option);}
 if(state.tags.has(prior))select.value=prior;
 else if(state.tags.has(state.value.graph.final))select.value=state.value.graph.final;
 const selected=state.checks.find(row=>row.outbound===select.value);
 selectProbeEntry(JSON.stringify([subject,revision]),select.value,state.tags);
 $('route-check-exit').hidden=$('route-check-method').value!=='https_exit_ip';
 $('route-check-http').hidden=$('route-check-method').value!=='https_status';
 $('route-check-country').hidden=$('route-check-method').value!=='https_exit_country';
 if(routeProfileEdit&&routeProfileEdit.path!==select.value)closeRouteProfile();
 $('route-profile-open').disabled=busy||!!pending||!(selected?.profile||selected?.checks?.length);
 if(selected)$('route-check-required').checked=selected.required===true;
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
  updateCohortButton();
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
 $(prefix+'-control').value=valid&&Number.isSafeInteger(existing.controlBasisPoints)?String(existing.controlBasisPoints/100):'';
}
function rolloutFields(prefix){
 const share=$(prefix+'-share'),control=$(prefix+'-control');
 return {id:$(prefix+'-id').value.trim(),share:share.value,control:control.value,valid:share.validity.valid&&control.validity.valid};
}
function readDeviceRollout(fields){
 const {id,share,control,valid}=fields;
 if(!valid)throw Error('invalid');
 if(!id&&!share&&!control)return null;
 const percentage=value=>/^\d{1,3}(\.\d{1,2})?$/.test(value)&&Number(value)<=100;
 if(!/^[a-z0-9][a-z0-9._-]{0,47}$/.test(id)||!percentage(share)||(control&&!percentage(control)))throw Error('invalid');
 const result={id,basisPoints:Math.round(Number(share)*100)};
 if(control!=='')result.controlBasisPoints=Math.round(Number(control)*100);
 return result;
}
const cohortFeatures=[
 {key:'decision',prefix:'route-decision',section:'route-decision-rollout',label:'Алгоритм переключения'},
 {key:'probeCooldown',prefix:'route-rollout',section:'route-cooldown-rollout',label:'Пауза проверок резервного маршрута'}
];
function enteredCohorts(){
 return cohortFeatures.filter(({prefix,section})=>!$(section).hidden&&
  ['id','share','control'].some(field=>$(prefix+'-'+field).value!==''));
}
function clearCohortPreview(){
 cohortRequest?.abort();cohortRequest=null;
 $('cohort-result').replaceChildren();
}
function updateCohortButton(){
 const group=$('cohort-preview'),features=enteredCohorts();
 const inputs=JSON.stringify([$('cohort-device').value,...features.map(({key,prefix})=>[key,rolloutFields(prefix)])]);
 if(inputs!==cohortInputs){clearCohortPreview();cohortInputs=inputs;}
 group.hidden=!features.length;
 $('cohort-run').disabled=group.hidden||busy||!!pending||!!cohortRequest||!$('cohort-device').value.trim();
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
 $('route-replay-run').disabled=!authenticated||busy;
 $('refresh-runtime').disabled=busy||!!runtimeRequest||!authenticated||!layerInventory;
 $('reauthentication').hidden=!authenticated||!reauthenticationNeeded;
 $('reauthentication-unavailable').hidden=reauthenticationAvailable;
 $('reauthentication-start').disabled=busy||!authenticated||!reauthenticationAvailable;
 $('invite-reauth').hidden=!authenticated||!reauthenticationAvailable;
 $('invite-reauth').disabled=busy;
 $('reauthentication-check').disabled=busy||!authenticated;
 deviceSearchControls();
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
 for(const id of sourceFields)$(id).disabled=busy||!authenticated||!!pending||sourceIdentity&&['source-id','source-owner','source-mode','source-resource','source-external'].includes(id);
 const deviceSource=$('source-mode').value==='device';
 $('source-device-settings').hidden=!deviceSource;
 $('source-device').disabled=$('source-device').disabled||!deviceSource||!!sourceIdentity?.fetchDeviceId;
 $('source-device').required=deviceSource;
 updateProviderControls();
 const reviewBlocked=busy||!authenticated||!!pending||!reviewAvailable;
 $('source-review-load').disabled=reviewBlocked;
 $('source-review-confirm').disabled=reviewBlocked||!sourceReview;
 for(const id of ['source-review-approve','source-review-reject'])$(id).disabled=reviewBlocked||!sourceReview||!$('source-review-confirm').checked;
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
 for(const id of ['inventory-device',...formFields])$(id).disabled=busy||!authenticated||!!pending;
 $('owner').disabled=!authenticated||!!pending||busy&&!sourceDetailLoading;
 $('pending').hidden=!pending;for(const id of ['retry-save','discard-save'])$(id).disabled=busy||!authenticated;
 if(pending&&['layer-preview','layer-publish','layer-discard'].includes(pendingKind))$('discard-save').disabled=true;
 for(const button of $('sources').querySelectorAll('button'))button.disabled=busy||!authenticated||!!pending;
 $('source-dependencies-refresh').disabled=busy||!authenticated||!!pending||!sourceIdentity;
 $('source-secret').disabled=busy||!authenticated||!!pending||$('source-secret-operation').value!=='replace';
 const withdrawFetch=['server','device'].includes($('source-mode').value)&&$('source-secret-operation').value==='delete';
 $('source-withdraw-hint').hidden=!withdrawFetch;
 if(withdrawFetch&&$('source-enabled').checked)$('save-source').disabled=true;
 if(!['server','resource','device'].includes($('source-mode').value)||deviceSource&&!sourceIdentity?.fetchDeviceId)$('sync-source').disabled=true;
 layerControls();
 drawRouteChecks();
}
function clearInventory(){
 inventoryEpoch++;
 clearRuntime();
 $('issued-path').hidden=true;
 $('issued-path-select').onchange=null;
 for(const id of ['issued-path-select','issued-path-note','issued-path-steps'])$(id).replaceChildren();
 layerInventory=null;
 for(const id of ['inventory-meta','inventory-layers','inventory-effective','inventory-fields','inventory-restrictions','inventory-issued-config','inventory-state','inventory-issued','inventory-issued-algorithm','inventory-report','inventory-report-time'])$(id).replaceChildren();
 for(const id of ['inventory-state','inventory-issued','inventory-report'])delete $(id).dataset.tone;
 $('inventory-issued-algorithm').hidden=true;
 $('inventory-assignment-note').replaceChildren();
 $('inventory-assignment-note').hidden=true;
 $('inventory-report-time').removeAttribute('datetime');$('inventory-report-time').hidden=true;
 $('inventory-details').open=false;$('inventory-view').hidden=true;$('inventory-issued-settings').hidden=true;$('inventory-issued-settings').open=false;
}
function erase(){
 window.dispatchEvent(new Event('syn443-console-session-ended'));
 reauthenticationAvailable=false;reauthenticationNeeded=false;reauthenticationIssuer='';reauthenticationFocus=false;
 clearCohortPreview();$('cohort-device').value='';
 resetReplay();clearDevices(true);clearInventory();clearLayers();clearTelemetry();pending=null;revision=0;opened=null;next='';listedOwner='';clearSource();
 for(const id of ['owner','inventory-device','draft-id','target-id','base-hash','plan','route-check-target','route-check-ip','route-check-country-class'])$(id).value='';
 $('target-kind').value='device';$('base-revision').value='0';$('draft-version').textContent='Новый черновик';
 clearSourceSnapshot();
 for(const id of ['sources','inventory-status'])$(id).replaceChildren();
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
export async function sendInvitation(body,signal){
 if(!authenticated)throw Error('login');
 try{return await request('/control/action',body,signal);}
 finally{controls();}
}
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
    const baseline=row.baselineReselections??0,conservative=row.conservativeReselections??0,adaptive=row.adaptiveReselections===undefined?0:row.adaptiveReselections;
    if(![baseline,conservative,adaptive].every(Number.isSafeInteger)||baseline<0||conservative<0||adaptive<0||
      baseline>row.events||conservative>row.events-baseline||adaptive>row.events-baseline-conservative||
      ((baseline||conservative||adaptive)&&(row.kind!=='route'||row.code!=='reselected')))throw Error('network');
    const legacyCounts=`Базовый: ${baseline}, консервативный: ${conservative}`;
    const counts=adaptive?(baseline||conservative?`${legacyCounts}, адаптивный: ${adaptive}`:`адаптивный: ${adaptive}`):
      (baseline||conservative?legacyCounts:'—');
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
async function work(fn){if(busy)return;busy=true;controls();try{await fn();}catch(error){status(({timeout:'Сервер не ответил вовремя. Повторите действие.',anonymous:'Войдите с административной учётной записью.',login:'Сессия завершена. Войдите снова.',denied:'Доступ отозван или недостаточно прав.',reauth:'Для операции нужно подтвердить вход. Правки и подготовленный запрос остаются в этой вкладке.',popup:'Разрешите новую вкладку для Keycloak и повторите подтверждение входа.',conflict:'Версия изменилась. Откройте текущий черновик перед новой правкой.',controlShare:'Для одного идентификатора раскатки задайте одинаковую долю контрольной группы.',invalid:'Проверьте поля и структуру данных.',size:'Данные превышают допустимый размер.',importSize:'Файл подписки или запрос превышает допустимый размер.'})[error.message]||'Сервер недоступен. Правка остаётся только в памяти этой вкладки.',error.message==='anonymous'?'info':'danger');}finally{busy=false;controls();if(reauthenticationFocus&&authenticated){reauthenticationFocus=false;$('reauthentication-title').focus();}}}

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
function showIssuedPaths(issued){
 const rows=issued.outbounds,byTag=new Map(),validTag=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v);
 const labels={direct:'Прямое соединение',block:'Блокировка',http:'HTTP',socks:'SOCKS',ssh:'SSH',vless:'VLESS',
  netbird:'NetBird',selector:'Селектор',urltest:'Балансер',dns:'DNS','syn443-adaptive':'Адаптивный выбор'};
 if(rows.length>256)return;
 for(const row of rows){
  if(!row||!validTag(row.tag)||!Object.hasOwn(labels,row.type)||byTag.has(row.tag)||
    row.detour!==undefined&&!validTag(row.detour))return;
  byTag.set(row.tag,row);
 }
 const select=$('issued-path-select'),note=$('issued-path-note'),steps=$('issued-path-steps');
 for(const row of rows)select.add(new Option(row.tag===issued.routeFinal?row.tag+' (основной выход)':row.tag,row.tag));
 if(byTag.has(issued.routeFinal))select.value=issued.routeFinal;
 function draw(){
  steps.replaceChildren();
  const route=[],seen=new Set();let tag=select.value;
  while(tag){
   const row=byTag.get(tag);
   if(!row||seen.has(tag)){
    note.textContent='Порядок соединения неизвестен: в описании нет звена или оно повторяется.';return;
   }
   seen.add(tag);route.push(row);tag=row.detour;
  }
  const dynamic=route.some(row=>['selector','urltest','syn443-adaptive'].includes(row.type));
  note.textContent=dynamic?'Конкретный маршрут выбирает устройство.':'Порядок соединения от устройства до выбранного выхода.';
  for(const row of route.reverse()){
   const item=document.createElement('li');item.textContent=row.tag+' · '+labels[row.type];
   if(['selector','urltest','syn443-adaptive'].includes(row.type)&&Array.isArray(row.outbounds)&&row.outbounds.length&&row.outbounds.length<=256&&row.outbounds.every(validTag)){
    const choices=document.createElement('span');choices.textContent=' · варианты: '+row.outbounds.join(', ');item.append(choices);
   }
   if(row.type==='netbird'){
    const overlay=issued.netbird,detail=document.createElement('span');
    const matches=overlay?.tag===row.tag;
    const transport=matches&&overlay.transport==='direct'&&!row.detour?'прямое соединение':
      matches&&overlay.transport==='vless'&&row.detour?'через VLESS ('+row.detour+')':null;
    let text=transport?' · транспорт по политике: '+transport:' · транспорт не указан в сохранённой сводке';
    if(transport&&[overlay.overlayId,overlay.resourceId,overlay.networkId].every(validTag))
     text+=' · сеть: '+overlay.networkId+' · ресурс: '+overlay.resourceId+' · подключение: '+overlay.overlayId;
    detail.textContent=text;item.append(detail);
   }
   steps.append(item);
  }
 }
 $('issued-path').hidden=false;select.onchange=draw;draw();
}
function clearProviderEditor(){
 providerEdit=null;
 $('provider-editor').open=false;
 $('provider-editor').hidden=true;
 $('provider-edit-name').value='';
 $('provider-edit-enabled').checked=false;
 $('provider-impact-confirm').checked=false;
 $('provider-impact-text').textContent='';
 $('provider-impact').hidden=true;
}
function updateProviderControls(){
 const visible=authenticated&&$('source-mode').value==='resource';
 const id=$('source-resource').value.trim();
 const context=visible?JSON.stringify([$('source-id').value,$('source-owner').value,id]):null;
 if(context!==providerContext){
  providerContext=context;providerEpoch++;$('provider-details').replaceChildren();clearProviderEditor();
 }
 $('provider-settings').hidden=!visible;
 $('inspect-provider').disabled=!visible||busy||!!pending||!/^[A-Za-z0-9_-]{1,48}$/.test(id);
 if(!providerEdit)return;
 const name=$('provider-edit-name').value.trim(),enabled=$('provider-edit-enabled').checked;
 const toggled=enabled!==providerEdit.resource.enabled;
 $('provider-impact').hidden=!toggled;
 if(toggled){
  const state=enabled?'будет разрешена':'будет остановлена';
  $('provider-impact-text').textContent=`Синхронизация ${state}. Связанные источники: ${providerEdit.impact.sources}.`;
 }
 const blocked=!visible||busy||!!pending;
 for(const field of ['provider-edit-name','provider-edit-enabled','provider-impact-confirm'])$(field).disabled=blocked;
 $('provider-edit-save').disabled=blocked||!name||new TextEncoder().encode(name).length>256||
  (toggled?!$('provider-impact-confirm').checked:name===providerEdit.resource.name);
}
async function inspectProvider(){
 const id=$('source-resource').value.trim(),epoch=providerEpoch;
 const details=$('provider-details');details.replaceChildren();clearProviderEditor();
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
 if(!planned&&typeof impact.hash==='string'&&/^[A-Za-z0-9_-]{43}$/.test(impact.hash)){
  providerEdit={resource,impact,epoch};
  $('provider-edit-name').value=resource.name;$('provider-edit-enabled').checked=resource.enabled;
  $('provider-editor').hidden=false;
 }
}
async function saveProvider(){
 if(!providerEdit||providerEdit.epoch!==providerEpoch||pending)throw Error('invalid');
 const {resource,impact}=providerEdit,name=$('provider-edit-name').value.trim(),enabled=$('provider-edit-enabled').checked;
 if(!name||new TextEncoder().encode(name).length>256||enabled===resource.enabled&&name===resource.name||
  enabled!==resource.enabled&&!$('provider-impact-confirm').checked)throw Error('invalid');
 const draft={id:resource.id,providerType:resource.providerType,apiVersion:resource.apiVersion,revision:resource.revision,name,enabled};
 pendingKind='resource';pending=envelope('resource.put',{resource:draft,secret:{operation:'keep'},impactHash:impact.hash});
 await retry();
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
 const stateLabel={assigned:`Назначены · версия ${revision}`,unassigned:'Слои не назначены',expired:`Срок назначения истёк · версия ${revision}`};
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
 if(effective){if(effective.document===undefined)throw Error('invalid');documentNode.textContent=JSON.stringify(effective.document,null,2);}else documentNode.textContent='Настройки из управляемых слоёв отсутствуют.';
 const issued=view.issuedSettings;
 if(issued!=null){
  if(typeof issued!=='object'||Array.isArray(issued)||issued.revision!==policyRevision||!Array.isArray(issued.outbounds)||!issued.outbounds.length)throw Error('invalid');
  if(supportedPolicyAlgorithms.has(issued.algorithmRevision)){
   const algorithm=$('inventory-issued-algorithm');
   algorithm.textContent='Алгоритм '+issued.algorithmRevision;
   algorithm.hidden=false;
  }
  $('inventory-issued-config').textContent=JSON.stringify(issued,null,2);
  showIssuedPaths(issued);
  $('inventory-issued-settings').hidden=false;
 }
 if(state==='unassigned'&&policyRevision>0){
  const note=$('inventory-assignment-note');
  note.textContent=`Сервер выдал политику версии ${policyRevision}.`+(issued?' Подробнее в разделе «Настройки выданной политики».':'');
  note.hidden=false;
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
function clearDevices(dropPreferences=false){
 devicesEpoch++;
 devicesNext='';deviceIds=new Set();$('device-rows').replaceChildren();$('devices-status').textContent='';$('devices-region').hidden=true;$('more-devices').hidden=true;
 if(dropPreferences){
  devicePrefix='';
  $('device-filters').hidden=true;
  $('clear-device-prefix').hidden=true;
  deviceFavorites.clear();
  $('device-search').value='';
  $('device-filter').value='all';
 }
}
function deviceSearchControls(){
 const query=$('device-search').value.trim(),blocked=busy||!authenticated||!!pending;
 $('search-all-devices').disabled=blocked||!deviceID.test(query)||query.toLowerCase()===devicePrefix.toLowerCase();
 $('clear-device-prefix').hidden=!devicePrefix;
 $('clear-device-prefix').disabled=blocked;
}
function filterDevices(){
 const query=$('device-search').value.trim().toLowerCase(),mode=$('device-filter').value;
 let visible=0;
 for(const row of $('device-rows').children){
  const id=row.dataset.id;
  const matchesMode=mode==='all'||mode==='attention'&&row.dataset.attention==='true'||mode==='favorites'&&deviceFavorites.has(id);
  row.hidden=!matchesMode||!id.toLowerCase().includes(query);
  if(!row.hidden)visible++;
 }
 $('devices-region').hidden=visible===0;
 $('device-filters').hidden=!deviceIds.size&&!devicePrefix;
 deviceSearchControls();
 if(!deviceIds.size&&devicePrefix){
  $('devices-status').textContent=`Доступных устройств с началом ID «${devicePrefix}» нет.`;
 }else if(!deviceIds.size){
  $('devices-status').textContent='Доступных устройств нет. Проверьте назначение и срок доступа.';
 }else if(!query&&mode==='all'){
  $('devices-status').textContent=`Загружено устройств: ${deviceIds.size}.`;
 }else{
  $('devices-status').textContent=`Найдено среди загруженных: ${visible} из ${deviceIds.size}.`+(devicesNext?' Можно загрузить ещё.':'');
 }
 if(devicePrefix&&deviceIds.size)$('devices-status').textContent+=` В базе выбран префикс «${devicePrefix}».`;
}
function favoriteButton(id){
 const button=actionButton();
 button.type='button';
 button.setAttribute('aria-label',`Избранное для ${id}`);
 const update=()=>{
  const saved=deviceFavorites.has(id);
  button.textContent=saved?'В избранном':'В избранное';
  button.setAttribute('aria-pressed',String(saved));
 };
 button.onclick=()=>{
  if(!authenticated||busy||pending||!deviceIds.has(id))return;
  if(deviceFavorites.has(id))deviceFavorites.delete(id);else deviceFavorites.add(id);
  update();filterDevices();
  if(button.closest('tr')?.hidden)$('device-filter').focus();
 };
 update();
 return button;
}
const deviceReportStates={not_issued:'Политика не выдана',awaiting_report:'Ожидается отчёт',historical:'Архивный отчёт',reported:'Отчёт о выданной политике'};
const deviceOutcomes={committed:'Применена',degraded:'Применена частично',rolled_back:'Откат'};
const closedObject=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).every(k=>keys.includes(k));
const safeRevision=v=>Number.isSafeInteger(v)&&v>=0;
async function loadDevices(more=false,prefix=devicePrefix){
 if(prefix&&!deviceID.test(prefix))throw Error('invalid');
 const after=more?devicesNext:'';
 if(more&&!after)throw Error('invalid');
 if(!more){clearDevices();devicePrefix=prefix;}
 const epoch=devicesEpoch;
 $('devices-disclosure').open=true;
 $('devices-status').textContent='Загружаем устройства…';
 try{
  const page=await action('configuration.devices.list',prefix?{after,prefix}:{after});
  if(epoch!==devicesEpoch||!authenticated)return;
  if(!closedObject(page,['devices','next','observedAtMs'])||!Array.isArray(page.devices)||page.devices.length>32||typeof page.next!=='string'||page.next&&!deviceID.test(page.next)||!Number.isSafeInteger(page.observedAtMs)||page.observedAtMs<1)throw Error('invalid');
  const seen=more?new Set(deviceIds):new Set();let previous=after;
  for(const row of page.devices){
   if(!closedObject(row,['device','policyRevision','desiredRevision','report'])||typeof row.device!=='string'||!deviceID.test(row.device)||row.device<=previous||seen.has(row.device)||!safeRevision(row.policyRevision)||!safeRevision(row.desiredRevision))throw Error('invalid');
   const report=row.report;
   if(!closedObject(report,['state','policyRevision','outcome','activePolicyRevision','receivedAtMs'])||!Object.hasOwn(deviceReportStates,report.state)||!safeRevision(report.activePolicyRevision)||!safeRevision(report.policyRevision??0)||!safeRevision(report.receivedAtMs??0))throw Error('invalid');
   if(['historical','reported'].includes(report.state)){
    if(!Object.hasOwn(deviceOutcomes,report.outcome)||!report.policyRevision||!report.receivedAtMs||report.state==='reported'&&report.policyRevision!==row.policyRevision)throw Error('invalid');
   }else if(report.policyRevision||report.outcome||report.receivedAtMs||report.activePolicyRevision||report.state==='not_issued'&&row.policyRevision!==0||report.state==='awaiting_report'&&row.policyRevision===0)throw Error('invalid');
   if(prefix&&!row.device.toLowerCase().startsWith(prefix.toLowerCase()))throw Error('invalid');
   previous=row.device;seen.add(row.device);
  }
  if(page.next&&(page.devices.length!==32||page.next!==previous))throw Error('invalid');
  // Validate the complete page before exposing any row or attaching actions.
  const fragment=document.createDocumentFragment();
  for(const row of page.devices){
   const tr=document.createElement('tr'),cell=document.createElement('td'),open=actionButton();
   open.type='button';open.textContent=row.device;open.setAttribute('aria-label',`Открыть устройство ${row.device}`);
   open.onclick=()=>work(async()=>{$('inventory-device').value=row.device;await loadInventory();});
   cell.append(open,favoriteButton(row.device));tr.append(cell);
   tr.dataset.id=row.device;tr.dataset.attention=String(row.report.state==='reported'&&['degraded','rolled_back'].includes(row.report.outcome));
   const report=row.report;const label=report.outcome?`${deviceReportStates[report.state]} · ${deviceOutcomes[report.outcome]}`:deviceReportStates[report.state];
   for(const value of [row.desiredRevision?String(row.desiredRevision):'Слои не назначены',row.policyRevision?String(row.policyRevision):'Не выдана',label,report.receivedAtMs?inventoryDate(report.receivedAtMs):'—']){const td=document.createElement('td');td.textContent=value;tr.append(td);}
   fragment.append(tr);
  }
  if(!more)$('device-rows').replaceChildren();$('device-rows').append(fragment);
  deviceIds=seen;devicesNext=page.next;$('more-devices').hidden=!devicesNext;
  if(!devicesNext){
   const searchedPrefix=prefix.toLowerCase();
   for(const id of deviceFavorites){
    if(id.toLowerCase().startsWith(searchedPrefix)&&!seen.has(id))deviceFavorites.delete(id);
   }
  }
  filterDevices();
 }catch(error){
  if(epoch!==devicesEpoch||!authenticated){if(['login','denied'].includes(error.message))throw error;return;}
  clearDevices(true);
  $('devices-status').textContent=error.message==='invalid'?'Сервер вернул некорректный список. Устройства скрыты.':'Список устройств недоступен. Можно открыть карточку по ID.';
  if(['login','denied'].includes(error.message))throw error;
 }
}
async function loadInventory(){
 const device=$('inventory-device').value.trim();
 if(!deviceID.test(device))throw Error('invalid');
 clearInventory();
 const epoch=inventoryEpoch;
 $('inventory-status').textContent='Загружаем конфигурацию…';
 try{
  const view=await action('configuration.inventory.get',{id:device});
  if(epoch!==inventoryEpoch||!authenticated||$('inventory-device').value.trim()!==device)return;
  if(view?.device!==device)throw Error('invalid');
  showInventory(view);
  $('devices-disclosure').open=false;
  $('inventory-view').focus({preventScroll:true});
  layerInventory=structuredClone(view);
  await loadRuntime();
  if(epoch!==inventoryEpoch)return;
  $('inventory-status').textContent='Конфигурация загружена.';
 }catch(error){
  if(epoch!==inventoryEpoch&&authenticated)return;
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
 const phase={off:'VPN выключен',starting:'Запуск VPN',online:'VPN включён',recovering:'Восстановление VPN',no_network:'Нет сети',blocked:'VPN заблокирован',unknown:'Состояние неизвестно'}[r.phase];
 const engine=!r.engineKnown?'состояние движка неизвестно':r.engineActive?'движок активен':'движок остановлен';
 $('inventory-runtime').textContent=recent?`Сообщено: ${phase}`:'Отчёт устарел';
 $('inventory-runtime').dataset.tone=recent?'info':'warning';
 $('inventory-runtime-detail').textContent=`${recent?'По данным клиента':'Последнее сообщение: '+phase} · ${ {none:'Без сети',wifi:'Wi-Fi',cellular:'Мобильная сеть',unknown:'Сеть неизвестна'}[r.network]} · сборка ${r.build} · политика ${r.policyRevision} · ${engine}`;
 const issued=layerInventory?.issuedSettings;
 if(recent&&r.engineKnown&&r.engineActive&&issued?.revision===r.policyRevision&&supportedPolicyAlgorithms.has(issued.algorithmRevision)){
  $('inventory-runtime-detail').append(' · алгоритм политики '+issued.algorithmRevision);
 }
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
 selectProbeEntry(null,'',null);
 $('draft-id').value=draft.id;$('target-kind').value=draft.targetKind;$('target-id').value=draft.targetId;
 $('base-revision').value=String(draft.baseRevision);$('base-hash').value=draft.baseHash;$('plan').value=JSON.stringify(draft.plan,null,2);$('route-check-target').value='';$('route-check-ip').value='';$('route-check-country-class').value='';
 $('draft-version').textContent=`Версия черновика: ${draft.revision}`;
}
function clearSourceSnapshot(){
 sourceSnapshotEpoch++;
 $('source-details').hidden=true;
 for(const node of $('source-details').querySelectorAll('dd span[id], dd time[id]')){
  node.textContent='';node.removeAttribute('datetime');
 }
 $('profiles').replaceChildren();
}
function sourceDate(id,seconds,unknown){
 const field=$(id),date=new Date(seconds*1000);
 if(Number.isSafeInteger(seconds)&&seconds>0&&Number.isFinite(date.getTime())){
  field.dateTime=date.toISOString();
  field.textContent=date.toLocaleString('ru');
 }else{
  field.removeAttribute('datetime');field.textContent=unknown;
 }
}
function byteCount(exact,legacy){
 if(typeof exact==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(exact)){
  const value=BigInt(exact);
  return value<=18446744073709551615n?value:null;
 }
 return exact===undefined&&Number.isSafeInteger(legacy)&&legacy>=0?BigInt(legacy):null;
}
function showSourceSnapshot(source,view){
 const snapshot=view?.snapshot;
 if(!snapshot||!Array.isArray(view.profiles)||typeof snapshot.id!=='string'||
    (snapshot.sourceId!==undefined&&snapshot.sourceId!==source.id)||
    (source.activeSnapshot&&snapshot.id!==source.activeSnapshot))throw Error('conflict');
 const modes={home_wifi:'Домашний Wi-Fi',wifi:'Wi-Fi',cellular_restricted:'Мобильная сеть с ограничениями',cellular:'Мобильная сеть'};
 $('source-snapshot-name').textContent=source.name+' · '+source.id+' · v'+source.revision+' · '+snapshot.id;
 $('source-snapshot-modes').textContent=source.networkModes.map(mode=>modes[mode]||mode).join(', ');
 sourceDate('source-snapshot-time',snapshot.observedAt,'Неизвестно');
 sourceDate('source-snapshot-until',snapshot.validUntil,'Неизвестно');
 const quota=snapshot.quota,known=quota?.known===true;
 const used=known?byteCount(view.trafficBytes?.used,quota.used):null;
 const limit=known?byteCount(view.trafficBytes?.limit,quota.limit):null;
 const bytes=new Intl.NumberFormat('ru');
 const fmt=n=>n===null?'Неизвестно':bytes.format(n)+' Б';
 $('source-traffic-used').textContent=fmt(used);
 $('source-traffic-limit').textContent=limit===0n?'Без ограничения':fmt(limit);
 $('source-traffic-left').textContent=limit===0n?'Без ограничения':fmt(used===null||limit===null?null:(used<limit?limit-used:0n));
 sourceDate('source-traffic-time',known?quota.observedAt:null,'Сведений нет');
 sourceDate('source-traffic-expiry',known?quota.expiresAt:null,'Не указан');
 for(const profile of view.profiles)textItem($('profiles'),profile.name+' · '+profile.kind+' · '+profile.id);
 $('source-details').hidden=false;
}
async function sources(more=false){
 const owner=$('owner').value.trim();if(!owner)throw Error('invalid');
 if(more&&owner!==listedOwner)throw Error('invalid');
 if(!more)clearSourceSnapshot();
 const epoch=sourceSnapshotEpoch;
 const page=await action('source.list',{owner,after:more?next:''});
 if(epoch!==sourceSnapshotEpoch||owner!==$('owner').value.trim())return;
 if(!Array.isArray(page.sources)||typeof page.next!=='string'||page.sources.some(source=>!validSourceBinding(source)||source.owner!==owner))throw Error('invalid');
 if(!more)$('sources').replaceChildren();
 listedOwner=owner;next=page.next;
 for(const source of page.sources){
  const li=textItem($('sources'),`${source.name} (${source.id}) · ${sourceStateLabel(source.state)} · v${source.revision}`);
  const button=actionButton();button.textContent='Показать профили';button.onclick=()=>work(async()=>{
   clearSourceSnapshot();const selection=sourceSnapshotEpoch;
   const view=await action('source.snapshot',{id:source.id,snapshot:source.activeSnapshot||''});
   if(!authenticated||selection!==sourceSnapshotEpoch||owner!==$('owner').value.trim())return;
   showSourceSnapshot(source,view);
   status('Метаданные профилей загружены. Учётные данные прокси не выводятся.');
  });const edit=actionButton();edit.textContent='Настроить источник';edit.onclick=()=>work(async()=>{
    const selection=sourceSnapshotEpoch;
    sourceDetailLoading=true;controls();
    try{
     const details=await action('source.get',{id:source.id});
     if(!authenticated||selection!==sourceSnapshotEpoch||owner!==$('owner').value.trim())return;
     showSource(details,source);status('Параметры загружены. Прежний секрет не возвращается.');
    }finally{sourceDetailLoading=false;}
  });li.append(document.createElement('br'),button,edit);
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
 catch(error){
  if(pendingKind==='review'&&error.message==='conflict'){
   pending=null;resetSourceReview(reviewAvailable);
   status('Версии подписки или её зависимости изменились. Сравните версии заново.','danger');return;
  }
  if(pendingKind==='resource'&&error.message==='conflict'){
   pending=null;clearProviderEditor();$('provider-details').replaceChildren();
   status('Ресурс или его источники изменились. Нажмите «Посмотреть ресурс» и проверьте актуальные настройки.','danger');return;
  }
  if(['invalid','size','importSize'].includes(error.message))pending=null;throw error;
 }
 if(pendingKind==='review'){
  const sent=JSON.parse(pending).payload;
  if(!result||result.id!==sent.candidate||result.sourceId!==sent.sourceId||result.sourceRevision!==sent.sourceRevision||
     result.hash!==sent.hash||result.state!==(sent.approve?'active':'rejected'))throw Error('invalid');
  pending=null;
  if(sourceIdentity?.id===sent.sourceId&&sourceRevision===sent.sourceRevision){
   resetSourceReview(false);
   $('source-version').textContent='Версия источника: '+sourceRevision+' · '+(sent.approve?'обновление принято':'обновление отклонено');
  }
  status(sent.approve?'Версия подписки принята.':'Версия подписки отклонена.');return;
 }else if(pendingKind==='resource'){
  const wanted=JSON.parse(pending).payload.resource;
  if(!result||result.id!==wanted.id||result.revision!==wanted.revision+1||result.enabled!==wanted.enabled||
    result.name!==wanted.name||result.providerType!==wanted.providerType||result.apiVersion!==wanted.apiVersion)throw Error('invalid');
  pending=null;
  if(providerEdit?.epoch===providerEpoch&&$('source-resource').value.trim()===wanted.id)await inspectProvider();
  status('Настройки ресурса сохранены.');return;
 }else if(pendingKind==='source'){
  const wanted=JSON.parse(pending).payload.source;
  if(result?.revision!==wanted.revision+1)throw Error('invalid');
  showSource(result,wanted);status('Источник сохранён. Активные политики меняются отдельной публикацией.');
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
let sourceDependencyProfiles=[];
function appendSourceDependencies(){
 const list=$('source-dependencies-profiles'),start=list.childElementCount;
 for(const id of sourceDependencyProfiles.slice(start,start+32))textItem(list,id);
 $('source-dependencies-more').hidden=list.childElementCount>=sourceDependencyProfiles.length;
}
function showSourceDependencies(value,selected){
 const box=$('source-dependencies'),summary=$('source-dependencies-summary'),list=$('source-dependencies-profiles');
 sourceDependencyProfiles=[];list.replaceChildren();list.hidden=true;box.hidden=!selected;summary.textContent='';
 $('source-dependencies-more').hidden=true;
 if(!selected)return;
 if(!value||!Array.isArray(value.profileIds)||value.profileIds.length>5000||
    typeof value.incomplete!=='boolean'||new Set(value.profileIds).size!==value.profileIds.length||
    value.profileIds.some(id=>typeof id!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(id))){
  summary.textContent='Зависимости пока неизвестны. Обновите сведения перед отключением источника.';return;
 }
 sourceDependencyProfiles=value.profileIds;appendSourceDependencies();
 list.hidden=!value.profileIds.length;
 const detail=value.profileIds.length?('Используемых профилей: '+value.profileIds.length+'. Перед отключением замените эти профили в маршрутах или отключите соответствующие маршруты.'):
  value.incomplete?'':'В опубликованных маршрутах профили этого источника не используются.';
 summary.textContent=[detail,value.incomplete?'Часть конфигураций ещё проверяется. Список зависимостей может измениться.':''].filter(Boolean).join(' ');
}
async function refreshSourceDependencies(){
 const owner=sourceIdentity,revision=sourceRevision;
 if(!owner||!authenticated)return;
 showSourceDependencies(null,true);
 const source=await action('source.get',{id:owner.id});
 if(!authenticated||sourceIdentity!==owner||sourceRevision!==revision)return;
 if(!validSourceBinding(source)||!sameSourceBinding(source,owner)||source.revision!==revision)throw Error('conflict');
 showSourceDependencies(source.routeDependencies,true);
}
function clearSource(){showSourceDependencies(null,false);resetSourceReview(false);sourceRevision=0;sourceIdentity=null;sourceJob='';clearSourceHistory();clearSourceShares();for(const id of ['source-id','source-owner','source-name','source-device','source-resource','source-external','source-until','source-secret','source-import-file'])$(id).value='';$('source-mode').value='server';$('source-format').value='uri';$('source-refresh').value='3600';$('source-stale').value='86400';$('source-enabled').checked=true;$('source-secret-operation').value='keep';for(const option of $('source-modes').options)option.selected=option.value==='wifi';$('source-version').textContent='Источник не выбран';$('job-status').replaceChildren();}
function localDate(seconds){const d=new Date(seconds*1000);if(!Number.isFinite(d.getTime()))throw Error('invalid');return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}
function resetSourceReview(available){
 reviewEpoch++;reviewAvailable=available;sourceReview=null;reviewChanges=[];reviewOffset=0;
 $('source-review').hidden=!available;$('source-review-comparison').hidden=true;
 $('source-review-more').hidden=true;
 $('source-review-confirm').checked=false;$('source-review-summary').textContent='';$('source-review-changes').replaceChildren();
}
function moreReviewChanges(){
 for(const change of reviewChanges.slice(reviewOffset,reviewOffset+40))textItem($('source-review-changes'),change);
 reviewOffset=Math.min(reviewOffset+40,reviewChanges.length);
 $('source-review-more').hidden=reviewOffset>=reviewChanges.length;
}
function reviewProfiles(view,sourceId,id){
 const snapshot=view?.snapshot;
 if(!snapshot||snapshot.id!==id||snapshot.sourceId!==sourceId||!Array.isArray(view.profiles)||
    view.profiles.length>5000||snapshot.count!==view.profiles.length)throw Error('invalid');
 const profiles=new Map();
 for(const item of view.profiles){
  if(!item||typeof item.id!=='string'||!/^[-_A-Za-z0-9]{1,128}$/.test(item.id)||profiles.has(item.id)||
     typeof item.name!=='string'||typeof item.kind!=='string')throw Error('invalid');
  profiles.set(item.id,{name:item.name,kind:item.kind});
 }
 return profiles;
}
async function compareSourceReview(){
 const owner=sourceIdentity;
 if(!owner||pending)return;
 resetSourceReview(true);
 const epoch=reviewEpoch;
 const source=await action('source.get',{id:owner.id});
 if(epoch!==reviewEpoch||sourceIdentity!==owner)return;
 if(source.id!==owner.id||source.owner!==owner.owner||source.revision!==sourceRevision)throw Error('conflict');
 if(!hasReviewCandidate(source)){resetSourceReview(false);status(source.state==='quarantined'?sourceStateDetail(source):'У источника нет версии в карантине.');return;}
 const candidate=source.candidateSnapshot,active=source.activeSnapshot||'';
 const [newView,oldView]=await Promise.all([action('source.snapshot',{id:source.id,snapshot:candidate}),
  active?action('source.snapshot',{id:source.id,snapshot:active}):Promise.resolve(null)]);
 if(epoch!==reviewEpoch||sourceIdentity!==owner)return;
 const next=reviewProfiles(newView,source.id,candidate),previous=oldView?reviewProfiles(oldView,source.id,active):new Map();
 const snapshot=newView.snapshot;
 if(snapshot.state!=='quarantined'||snapshot.sourceRevision!==source.revision||!/^[-_A-Za-z0-9]{43}$/.test(snapshot.hash)||
    !Number.isSafeInteger(snapshot.observedAt)||snapshot.observedAt<=0||active&&oldView.snapshot.state!=='active')throw Error('conflict');
 const changes=[];
 for(const [id,profile] of previous)if(!next.has(id))changes.push('Удалён · '+profile.name+' ('+profile.kind+')');
 for(const [id,profile] of next){
  const prior=previous.get(id);
  if(!prior)changes.push('Добавлен · '+profile.name+' ('+profile.kind+')');
  else if(prior.name!==profile.name||prior.kind!==profile.kind)changes.push('Изменён · '+prior.name+' → '+profile.name);
 }
 const reason={excessive_removal:'исчезла значительная часть профилей',referenced_profile_removed:'удалён профиль, используемый в конфигурации'}[snapshot.reason];
 $('source-review-summary').textContent='Источник '+source.id+'. Профилей было '+previous.size+', стало '+next.size+'. Изменений '+changes.length+
  '. Получено '+new Date(snapshot.observedAt*1000).toLocaleString('ru')+'.'+(reason?' Причина карантина: '+reason+'.':'');
 reviewChanges=changes;moreReviewChanges();
 sourceReview={sourceId:source.id,sourceRevision:source.revision,candidate,hash:snapshot.hash,active};
 $('source-review-comparison').hidden=false;
}
async function decideSourceReview(approve){
 if(pending||!sourceReview||sourceReview.sourceId!==sourceIdentity?.id||sourceReview.sourceRevision!==sourceRevision||
    !$('source-review-confirm').checked)throw Error('invalid');
 pendingKind='review';pending=envelope('source.review',{...sourceReview,approve});await retry();
}
function validSourceBinding(s){
 if(!s||typeof s.id!=='string'||!/^[A-Za-z0-9_-]{1,48}$/.test(s.id)||
    typeof s.owner!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(s.owner))return false;
 if(s.mode==='resource')return typeof s.resourceId==='string'&&/^[A-Za-z0-9_-]{1,48}$/.test(s.resourceId)&&
    typeof s.externalUserId==='string'&&/^[1-9][0-9]{0,14}$/.test(s.externalUserId);
 return ['server','manual','device'].includes(s.mode)&&(s.resourceId??'')===''&&(s.externalUserId??'')==='';
}
function sameSourceBinding(source,expected){
 return source.id===expected.id&&source.owner===expected.owner&&source.mode===expected.mode&&
    (source.resourceId??'')===(expected.resourceId??'')&&(source.externalUserId??'')===(expected.externalUserId??'')&&
    (!expected.fetchDeviceId||expected.fetchDeviceId===source.fetchDeviceId);
}
function showSource(s,expected){if(!validSourceBinding(s)||!sameSourceBinding(s,expected)||!Number.isSafeInteger(s.revision)||s.revision<1||!Array.isArray(s.networkModes))throw Error('invalid');resetSourceReview(hasReviewCandidate(s));sourceIdentity={id:s.id,owner:s.owner,mode:s.mode,resourceId:s.resourceId||'',externalUserId:s.externalUserId||'',fetchDeviceId:s.fetchDeviceId||''};sourceRevision=s.revision;showSourceDependencies(s.routeDependencies,true);sourceJob='';clearSourceHistory();clearSourceShares();$('source-import-file').value='';$('source-id').value=s.id;$('source-owner').value=s.owner;$('source-name').value=s.name;$('source-mode').value=s.mode;$('source-device').value=sourceIdentity.fetchDeviceId;$('source-format').value=s.format;$('source-resource').value=s.resourceId||'';$('source-external').value=s.externalUserId||'';$('source-until').value=localDate(s.validUntil);$('source-refresh').value=String(s.refreshSeconds);$('source-stale').value=String(s.maxStaleSeconds);$('source-enabled').checked=s.enabled;for(const option of $('source-modes').options)option.selected=s.networkModes.includes(option.value);$('source-secret-operation').value='keep';$('source-secret').value='';$('source-version').textContent=`Версия источника: ${s.revision} · ${sourceStateDetail(s)}`;$('job-status').replaceChildren();}
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
function hasReviewCandidate(source){
 return Boolean(source.candidateSnapshot) && source.candidateSnapshot!==source.activeSnapshot;
}
function sourceStateDetail(source){
 if(source.state!=='quarantined'||hasReviewCandidate(source))return sourceStateLabel(source.state);
 return source.activeSnapshot
  ? 'Последнее обновление в карантине. Предыдущая версия профилей сохранена. Причина указана в истории обновлений.'
  : 'Первая загрузка в карантине. Опубликованных профилей пока нет. Причина указана в истории обновлений.';
}
function sourceStateLabel(state){
 const labels={active:'Активен',disabled:'Источник отключён',expired:'Срок подписки истёк',
  pending:'Ожидает загрузки',refresh_pending:'Ожидает обновления',refresh_error:'Ошибка обновления',
  resource_disabled:'Ресурс отключён',revoked:'Доступ отозван',quota_exhausted:'Квота исчерпана',
  quarantined:'Требует проверки',rejected:'Обновление отклонено',stale:'Данные устарели'};
 return Object.hasOwn(labels,state)?labels[state]:'Состояние неизвестно';
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
 if(!validSourceBinding(source)||sourceIdentity&&!sameSourceBinding(source,sourceIdentity))throw Error('invalid');
 const operation=$('source-secret-operation').value;
 if(operation==='delete'&&source.enabled&&['server','device'].includes(mode))throw Error('invalid');
 let secret=JSON.stringify({operation});
 if(operation==='replace'){try{JSON.parse($('source-secret').value);}catch{throw Error('invalid');}secret='{"operation":"replace","value":'+$('source-secret').value+'}';}
 pendingKind='source';pending=JSON.stringify({version:1,action:'source.put',requestId:crypto.randomUUID()}).slice(0,-1)+',"payload":{"source":'+JSON.stringify(source)+',"secret":'+secret+'}}';await retry();
}
$('login').onclick=()=>work(async()=>{const device=linkedDevice();const result=await request('/login',device?{device}:{});const target=new URL(result.url);if(target.protocol!=='https:'&&!(location.hostname==='127.0.0.1'&&target.protocol==='http:'&&target.hostname==='127.0.0.1'))throw Error('invalid');location.assign(target.href);});
$('logout').onclick=()=>work(async()=>{try{await request('/logout',{});}finally{authenticated=false;erase();if(linkedDevice())history.replaceState(null,'','/#inventory-title');}status('Вы вышли. Локальная копия черновика очищена.');});
$('device-search').oninput=filterDevices;
$('search-all-devices').onclick=()=>work(()=>loadDevices(false,$('device-search').value.trim()));
$('device-search').onkeydown=event=>{
 if(event.key==='Enter'&&!$('search-all-devices').disabled){event.preventDefault();$('search-all-devices').click();}
};
$('clear-device-prefix').onclick=()=>work(async()=>{
 $('device-search').value='';await loadDevices(false,'');if(authenticated)$('device-search').focus();
});
$('device-filter').onchange=filterDevices;
$('refresh-devices').onclick=()=>work(()=>loadDevices());
$('invite-reauth').onclick=()=>{
 if(!authenticated||!reauthenticationAvailable||busy)return;
 reauthenticationNeeded=true;controls();$('reauthentication-title').focus();
};
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
 if(location.hash!=='#sources-title')clearSourceSnapshot();
 if(location.hash!=='#sources-title')resetSourceReview(reviewAvailable);
 resetExplanation(true);
 resetReplay();
 updateSectionNav(true);
 setNavExpanded(false);
 if(authenticated&&!pending&&linkedDevice())void work(openLinkedDevice);
});$('open-draft').onclick=()=>work(openDraft);
$('new-draft').onclick=()=>work(async()=>{revision=0;opened=null;$('draft-id').value=crypto.randomUUID();$('target-kind').value='device';$('target-id').value='';$('base-revision').value='0';$('base-hash').value='';$('plan').value='';$('route-check-target').value='';$('route-check-ip').value='';$('route-check-country-class').value='';$('draft-version').textContent='Новый черновик';status('Новый личный черновик. Выберите адресата и заполните план.');});
$('draft-form').onsubmit=event=>{event.preventDefault();work(save);};$('retry-save').onclick=()=>work(retry);
$('plan').oninput=()=>{selectProbeEntry(null,'',null);drawRouteChecks();};
for(const id of ['draft-id','target-id','target-kind'])$(id).addEventListener('input',drawRouteChecks);
const connectionFields=['domain','address','application','network','port','dnsType'];
function resetExplanation(clearInputs){
 explanationEpoch++;
 $('explain-result').replaceChildren();
 if(clearInputs) $('route-explanation-form').reset();
}
function plannedSteps(plan,tag,parents=[]){
 if(!/^[A-Za-z0-9_-]{1,64}$/.test(tag)||parents.length>=8||parents.includes(tag))throw Error('invalid');
 const graph=plan.graph;
 if(tag==='direct')return ['Прямое соединение'];
 if(Object.hasOwn(graph.profiles||{},tag))return [tag];
 if(Object.hasOwn(graph.balancers||{},tag)||Object.values(plan.adaptive?.groups||{}).includes(tag))return [tag+' (вариант выберет устройство)'];
 const path=[...parents,tag];
 if(graph.netbird?.tag===tag){
  if(graph.netbird.mode==='direct')return [tag+' (NetBird)'];
  if(graph.netbird.mode==='vless')return [...plannedSteps(plan,graph.netbird.detour,path),tag+' (NetBird)'];
  throw Error('invalid');
 }
 const chain=Object.hasOwn(graph.chains||{},tag)?graph.chains[tag]?.dialOrder:null;
 if(!Array.isArray(chain)||!chain.length||chain.length>4||new Set(chain).size!==chain.length)throw Error('invalid');
 const hops=[];
 for(const member of chain){
  hops.push(...plannedSteps(plan,member,path));
  if(hops.length>4)throw Error('invalid');
 }
 return hops;
}
function showExplanation(report,plan){
 const list=document.createElement('dl');
 for(const [key,title] of [['route','Маршрут'],['dns','DNS']]){
  const item=report?.[key];
  if(!item||!['matched','default','incomplete','not_applicable'].includes(item.status))throw Error('invalid');
  if(item.rule!==undefined&&(typeof item.rule!=='string'||!/^[A-Za-z0-9_.-]{1,64}$/.test(item.rule)))throw Error('invalid');
  if(item.target!==undefined&&(typeof item.target!=='string'||!/^[A-Za-z0-9_.-]{1,64}$/.test(item.target)))throw Error('invalid');
  if(item.status==='not_applicable'){inventoryPair(list,title,'Не требуется');continue;}
  if(item.status==='incomplete'){inventoryPair(list,title,'Недостаточно данных'+(item.rule?' для правила '+item.rule:'')+'.');continue;}
  if(item.status==='matched'&&!item.rule||!item.target&&(key==='dns'||item.status!=='matched'))throw Error('invalid');
  const policy=item.status==='default'?'По умолчанию':'Правило '+item.rule;
  const choice=key==='route'?(item.target?plannedSteps(plan,item.target).join(' → '):'Блокировка'):item.target;
  inventoryPair(list,title,policy+' · '+choice);
 }
 $('explain-result').replaceChildren(list);
}
$('route-explanation-form').addEventListener('input',()=>{resetExplanation(false);drawRouteChecks();});
$('route-explanation-form').onsubmit=event=>{
 event.preventDefault();
 if($('explain-run').disabled)return;
 void work(async()=>{
  resetExplanation(false);
  const epoch=explanationEpoch,{value,network}=routeDraft(),query={};
  for(const field of connectionFields){
   const text=$('explain-'+field).value.trim();
   if(text)query[field]=field==='port'?Number(text):text;
  }
  const result=await request('/control/route-explanation',{
   query,routeFinal:value.graph.final,dnsFinal:network.dnsFinal,rules:network.rules||[],dnsRules:network.dnsRules||[]
  });
  if(authenticated&&explanationEpoch===epoch)showExplanation(result,value);
 });
};
function resetReplay(clearInputs=true){
 replayEpoch++;
 $('route-replay-result').replaceChildren();
 if(clearInputs){$('route-replay-file').value='';$('route-replay-ttl').value='60000';}
}
$('route-replay-file').onchange=()=>resetReplay(false);
$('route-replay-ttl').oninput=()=>resetReplay(false);
$('route-replay-run').onclick=()=>work(async()=>{
 resetReplay(false);
 const epoch=replayEpoch,ttl=Number($('route-replay-ttl').value);
 const file=$('route-replay-file').files[0];
 if(!Number.isSafeInteger(ttl)||ttl<1||ttl>600000)throw Error('invalid');
 let body={source:'reference',trialTtlMs:ttl};
 if(file){
  if(file.size>255*1024)throw Error('size');
  const raw=await file.text();
  if(replayEpoch!==epoch||!authenticated)return;
  let frames;try{frames=JSON.parse(raw);}catch{throw Error('invalid');}
  if(!Array.isArray(frames)||!frames.length||frames.length>64)throw Error('invalid');
  // Preserve the original JSON bytes as text so server-side duplicate-key
  // validation still sees the submitted fields after local structural checks.
  body='{"source":"trace","trialTtlMs":'+ttl+',"frames":'+raw+'}';
 }
 const report=await request('/control/route-replay',body);
 if(!authenticated||replayEpoch!==epoch)return;
 const labels={samePath:'Тот же маршрут',changedPath:'Выбран другой маршрут',lostPath:'Потерян доступный маршрут',gainedPath:'Появился доступный маршрут',neither:'В обоих случаях пути нет'};
 const keys=Object.keys(labels);
 if(!Number.isSafeInteger(report.frames)||report.frames<1||report.frames>64||
  keys.some(k=>!Number.isSafeInteger(report[k])||report[k]<0)||keys.reduce((sum,k)=>sum+report[k],0)!==report.frames)throw Error('invalid');
 const list=document.createElement('ul');
 for(const key of keys){const row=document.createElement('li');row.textContent=labels[key]+' - '+report[key];list.append(row);}
 $('route-replay-result').replaceChildren('Проверено кадров - '+report.frames,list);
});
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
for(const id of ['cohort-device',...cohortFeatures.flatMap(({prefix})=>['id','share','control'].map(field=>prefix+'-'+field))]){
 $(id).addEventListener('input',()=>{clearCohortPreview();updateCohortButton();});
}
$('cohort-run').onclick=async()=>{
 clearCohortPreview();
 const job=new AbortController();
 cohortRequest=job;updateCohortButton();
 const target=$('cohort-result');
 try{
  const device=$('cohort-device').value.trim(),features=enteredCohorts(),body={device};
  if(!/^[A-Za-z0-9_-]{8,128}$/.test(device)||!features.length)throw Error('invalid');
  for(const {key,prefix} of features)body[key]=readDeviceRollout(rolloutFields(prefix));
  target.textContent='Проверяем группу…';
  const assignments=await request('/control/rollout-preview',body,job.signal);
  if(cohortRequest!==job)return;
  const names={control:'постоянная контрольная группа',baseline:'базовая версия вне контрольной группы',treatment:'тестовая версия'};
  if(!assignments||Object.keys(assignments).length!==features.length||
    features.some(({key})=>!Object.hasOwn(assignments,key)||!Object.hasOwn(names,assignments[key])))throw Error('invalidResult');
  const list=document.createElement('ul');
  for(const {key,label} of features){
   const row=document.createElement('li');row.textContent=label+' - '+names[assignments[key]];list.append(row);
  }
  target.replaceChildren(list);
 }catch(error){
  if(cohortRequest===job)target.textContent=error.message==='invalid'?'Проверьте ID устройства, идентификаторы и доли групп.':'Не удалось проверить группу. Повторите запрос.';
 }finally{
  if(cohortRequest===job){cohortRequest=null;updateCohortButton();}
  if(!authenticated)controls();
 }
};
$('route-rollout-save').onclick=()=>{
 const fields=rolloutFields('route-rollout');
 work(async()=>{
  const state=routeDraft(),failover=internalFailoverPlan(state);
  if(failover?.probeCooldown!==true)throw Error('invalid');
  const value=readDeviceRollout(fields),other=failover.decisionRollout;
  if(value&&other?.id===value.id&&(other.controlBasisPoints??0)!==(value.controlBasisPoints??0))throw Error('controlShare');
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
 const fields=rolloutFields('route-decision');
 work(async()=>{
  const state=routeDraft(),failover=internalFailoverPlan(state);
  if(failover?.decisionRevision!==confirmedDecision)throw Error('invalid');
  const value=readDeviceRollout(fields),other=failover.probeCooldownRollout;
  if(value&&other?.id===value.id&&(other.controlBasisPoints??0)!==(value.controlBasisPoints??0))throw Error('controlShare');
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
$('discard-save').onclick=()=>work(async()=>{const kind=pendingKind,expected=kind==='source'?JSON.parse(pending).payload.source:sourceIdentity;pending=null;if(kind==='resource')await inspectProvider();else if(kind.startsWith('layer-')){layerPreview=null;layerJob=null;await loadLayerDraft();}else if(kind==='draft')await openDraft();else if(expected)showSource(await action('source.get',{id:expected.id}),expected);});
$('source-dependencies-more').onclick=appendSourceDependencies;
$('source-dependencies-refresh').onclick=()=>work(refreshSourceDependencies);
$('new-source').onclick=()=>work(async()=>{const owner=$('owner').value.trim();clearSource();$('source-id').value=crypto.randomUUID();$('source-owner').value=owner;$('source-until').value=localDate(Math.floor(Date.now()/1000)+30*86400);$('source-version').textContent='Новый источник';status('Заполните параметры. Для нового HTTPS источника укажите новые учётные данные.');});
$('source-form').onsubmit=event=>{event.preventDefault();work(saveSource);};
$('source-secret-operation').onchange=()=>{
 if($('source-secret-operation').value!=='replace')$('source-secret').value='';
 controls();
};
$('source-enabled').onchange=controls;$('source-mode').onchange=controls;
$('inspect-provider').onclick=()=>work(inspectProvider);
$('provider-edit-name').oninput=updateProviderControls;
$('provider-edit-name').onkeydown=event=>{
 if(event.key==='Enter'&&!event.isComposing){event.preventDefault();if(!$('provider-edit-save').disabled)$('provider-edit-save').click();}
};
$('provider-edit-enabled').onchange=()=>{$('provider-impact-confirm').checked=false;updateProviderControls();};
$('provider-impact-confirm').onchange=updateProviderControls;
$('provider-edit-save').onclick=()=>work(saveProvider);
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
$('owner').addEventListener('input',()=>{
 if(listedOwner&&$('owner').value.trim()!==listedOwner){
  clearSourceSnapshot();$('sources').replaceChildren();next='';listedOwner='';controls();
 }
});
$('source-review-load').onclick=()=>work(compareSourceReview);
$('source-review-more').onclick=moreReviewChanges;
$('source-review-confirm').onchange=controls;
$('source-review-approve').onclick=()=>work(()=>decideSourceReview(true));
$('source-review-reject').onclick=()=>work(()=>decideSourceReview(false));
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
