// Synthetic UI fixture. Actual SQL/CAS, OAuth/DPoP and scope are Go-tested.
import http from 'node:http';import fs from 'node:fs';
let auth=true,denied=false,failSave=false,drafts=new Map(),operations=new Map(),calls=[];
const originalSource=()=>({id:'source-a',owner:'synthetic-user',name:'<img src=x onerror="window.injected=true">',mode:'server',format:'uri',enabled:true,state:'active',revision:1,networkModes:['wifi'],activeSnapshot:'snapshot-a',validUntil:1800003600,refreshSeconds:3600,maxStaleSeconds:86400});
let sources=new Map([['source-a',originalSource()]]),jobs=new Map();
let layerDrafts=new Map(),discardedDrafts=new Set(),configurationJobs=new Map(),options={};
const server=http.createServer(async(req,res)=>{
 const send=(status,data)=>{const headers={'Content-Type':'application/json','Cache-Control':'no-store'};if(req.url.startsWith('/fixture/'))headers.Connection='close';res.writeHead(status,headers);res.end(JSON.stringify(data));};
 if(req.method==='GET'&&['/','/app.js','/style.css','/layer-merge.js'].includes(req.url)){
  const name=req.url==='/'?'index.html':req.url.slice(1);res.writeHead(200,{'Content-Type':name.endsWith('js')?'text/javascript':name.endsWith('css')?'text/css':'text/html','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});res.end(fs.readFileSync(new URL('../internal/chatweb/assets/control/'+name,import.meta.url)));return;
 }
 let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>278528){send(413,{});return;}}
 let body;try{body=JSON.parse(raw||'{}');}catch{send(400,{});return;}
 if(req.url==='/fixture/reset'){auth=true;denied=false;failSave=!!body.failSave;drafts=new Map();operations=new Map();calls=[];sources=new Map([['source-a',originalSource()]]);jobs=new Map();layerDrafts=new Map();discardedDrafts=new Set();configurationJobs=new Map();options={...body};send(200,{});return;}
 if(req.url==='/fixture/state'){send(200,{drafts:[...drafts.values()],layerDrafts:[...layerDrafts.values()],sources:[...sources.values()],operations:operations.size,calls});return;}
 if(req.url==='/fixture/revoke'){denied=true;send(200,{});return;}
 if(req.url==='/fixture/expire'){auth=false;send(200,{});return;}
 if(req.url==='/fixture/advance'){options.remoteChanged=true;send(200,{});return;}
 if(req.headers['x-syn443-csrf']!=='1'||req.headers.origin!=='http://127.0.0.1:17851'){send(403,{});return;}
 if(!auth){send(401,{});return;}
 if(req.url==='/session'){send(200,{authenticated:true});return;}
 if(req.url==='/logout'){auth=false;send(200,{ok:true});return;}
 if(denied){send(403,{});return;}
 if(req.url!=='/control/action'||body.version!==1){send(404,{});return;}
 calls.push(body.action);
 const p=body.payload;
 switch(body.action){
 case 'configuration.history.get':{
  if(p.id!=='device-a'||p.revision!==7||p.hash!=='a'.repeat(64)){send(403,{});break;}
  send(200,{device:p.id,owner:'synthetic-user',state:'assigned',revision:7,hash:'a'.repeat(64),currentRevision:options.remoteChanged?8:7,historical:true,mode:'wifi',approvalUntilMs:1800003600000,layers:[{id:'template-a',kind:'template',priority:0,revision:2,changes:[],permissions:null}]});break;
 }
 case 'configuration.layers.drafts.list':{
  let rows=[...layerDrafts.values()].filter(d=>d.proposal.targetKind===p.targetKind&&d.proposal.targetId===p.targetId).map(d=>({id:d.id,revision:d.revision,savedAtMs:d.savedAtMs})).sort((a,b)=>b.savedAtMs-a.savedAtMs||a.id.localeCompare(b.id));
  if(options.draftListDuplicate&&rows.length)rows.push({...rows[0]});
  if(options.draftListExcess&&rows.length)rows=Array.from({length:65},(_,i)=>({...rows[0],id:'overflow-'+i}));
  if(options.draftListExtra&&rows.length)rows[0].body='<img src=x onerror="window.injected=true">';
  send(200,{targetKind:p.targetKind,targetId:options.draftListMismatch?'another-device':p.targetId,drafts:rows});break;
 }
 case 'configuration.layers.draft.discard':{
  const old=operations.get(body.requestId);if(old){send(old.raw===raw?200:409,old.value);break;}
  const draft=layerDrafts.get(p.id);if(!draft||draft.revision!==p.revision||draft.proposal.targetKind!==p.targetKind||draft.proposal.targetId!==p.targetId){send(409,{});break;}
  if(options.discardConflict){send(409,{});break;}
  const value={id:p.id,revision:p.revision,discarded:true};layerDrafts.delete(p.id);discardedDrafts.add(p.id);operations.set(body.requestId,{raw,value});
  if(options.discardFailOnce){options.discardFailOnce=false;send(503,{});}else send(200,options.discardMismatch?{...value,id:'wrong-draft'}:value);break;
 }
 case 'configuration.layers.draft.get':{const draft=layerDrafts.get(p.id);send(draft?200:403,draft||{});break;}
 case 'configuration.layers.draft.put':{
  if(discardedDrafts.has(p.draft.id)){send(409,{});break;}
  const old=operations.get(body.requestId);if(old){send(old.raw===raw?200:409,old.value);break;}
  const d=p.draft,current=layerDrafts.get(d.id);
  if((current?.revision||0)!==d.revision){send(409,{});break;}
  if(d.savedAtMs!==0||d.proposal?.draftId!==d.id||d.proposal.draftRevision!==d.revision+1||!d.proposal.bundles?.length){send(400,{});break;}
  const value={...d,revision:d.revision+1,savedAtMs:Date.now()};layerDrafts.set(d.id,value);operations.set(body.requestId,{raw,value});
  if(failSave){failSave=false;send(503,{});}else send(200,value);break;
 }
 case 'configuration.preview.request':{
  const old=operations.get(body.requestId);if(old){send(old.raw===raw?200:409,old.value);break;}
  const id=body.requestId,value={id,state:'queued'},proposal=p.proposal;
  const result={previewId:'synthetic-preview-'+id,ticket:'synthetic-ticket-for-browser-fixture',preview:{schemaVersion:1,draftId:options.previewMismatch?'different-draft':proposal.draftId,draftRevision:proposal.draftRevision,targetKind:proposal.targetKind,targetId:proposal.targetId,mode:proposal.mode,expiresAtMs:Date.now()+(options.previewExpired?-1000:120000),recipients:proposal.bundles.map(b=>({device:b.device,owner:'synthetic-user',baseRevision:b.baseRevision,baseHash:b.baseHash})),effectiveHash:'b'.repeat(64),dependencyHash:'c'.repeat(64)}};
  configurationJobs.set(id,{id,state:options.previewConflict?'rejected':'ready',error:options.previewConflict?'configuration_conflict':'',result});operations.set(id,{raw,value});send(200,value);break;
 }
 case 'configuration.publish':{
  const old=operations.get(body.requestId);if(old){send(old.raw===raw?200:409,old.value);break;}
  const ready=[...configurationJobs.values()].find(j=>j.result?.previewId===p.previewId&&j.result.ticket===p.ticket);
  if(!ready||ready.state!=='ready'||ready.result.preview.expiresAtMs<=Date.now()){send(403,{});break;}
  const id=body.requestId,value={id,state:options.failPublish?'published':'queued'};
  configurationJobs.set(id,{id,state:'published'});operations.set(id,{raw,value});
  if(options.failPublish){options.failPublish=false;send(503,{});}else send(200,value);break;
 }
 case 'configuration.request.get':{const job=configurationJobs.get(p.id);send(job?200:403,job||{});break;}
 case 'configuration.inventory.get':{
  if(p.id==='device-unassigned'){send(200,{device:p.id,owner:'synthetic-user',state:'unassigned',revision:0,hash:'',policyRevision:3,publicationSource:'unlinked',mode:'',approvalUntilMs:0,layers:[],activation:{state:'awaiting_report',activePolicyRevision:0}});break;}
  if(!['device-a','device-expired','device-mismatch'].includes(p.id)){send(403,{});break;}
  const origin={kind:'template',layerId:'template-a',revision:2};
  send(200,{device:p.id==='device-mismatch'?'other-device':p.id,owner:'synthetic-user',state:p.id==='device-expired'?'expired':'assigned',revision:7,hash:'a'.repeat(64),policyRevision:23,publicationSource:p.id==='device-expired'||options.remoteChanged?'different_revision':'matches_desired',mode:'wifi',approvalUntilMs:1800003600000,
   activation:{state:p.id==='device-expired'?'historical':'reported',policyRevision:p.id==='device-expired'?22:23,outcome:'rolled_back',activePolicyRevision:21,receivedAtMs:1800000000000},
   ...(options.remoteChanged?{revision:8,hash:'d'.repeat(64)}:{}),
   layers:[{id:'template-a',kind:'template',priority:0,revision:2,changes:[],permissions:null},...(options.remoteChanged?[{id:p.id,kind:'device',priority:0,revision:1,changes:[{path:'/network/dnsStrategy',operation:'set',value:'ipv6_only'}],permissions:[]}]:[])],
   effective:{document:{note:'<img src=x onerror="window.injected=true">'},fields:{'/network/dnsStrategy':origin},restrictions:[{permission:{path:'/network/dnsStrategy',mode:'choice',choices:['prefer_ipv4','ipv4_only']},origin}]}});break;
 }
 case 'source.list':send(200,{sources:[...sources.values()],next:p.after?'':'source-a'});break;
 case 'source.get':{const source=sources.get(p.id);send(source?200:403,source||{});break;}
 case 'source.put':{
  const old=operations.get(body.requestId);if(old){send(old.raw===raw?200:409,old.value);break;}
  const source=p.source,current=sources.get(source.id);
  if((current?.revision||0)!==source.revision){send(409,{});break;}
  if(!source.name||!source.owner||!source.networkModes.length||!['keep','replace','delete'].includes(p.secret.operation)||p.secret.operation==='replace'&&!p.secret.value?.url){send(400,{});break;}
  const value={...source,revision:source.revision+1,state:source.enabled?'pending':'disabled'};sources.set(value.id,value);operations.set(body.requestId,{raw,value});
  if(failSave){failSave=false;send(503,{});}else send(200,value);break;
 }
 case 'source.sync':{const old=operations.get(body.requestId);if(old){send(old.raw===raw?200:409,old.value);break;}const source=sources.get(p.id);if(!source||source.revision!==p.revision){send(409,{});break;}const value={id:'job-a',phase:'queued',sourceId:p.id};jobs.set(value.id,value);operations.set(body.requestId,{raw,value});send(200,value);break;}
 case 'job.get':{const job=jobs.get(p.id);send(job?200:403,job?{...job,phase:'succeeded'}:{});break;}
 case 'job.list':{
  if(!sources.has(p.sourceId)||!['','job-19'].includes(p.after)){send(403,{});break;}
  const rows=Array.from({length:p.after?1:20},(_,i)=>({job:{
   id:p.after?'job-20':`job-${i}`,sourceId:p.sourceId,sourceRevision:1,kind:'fetch',phase:p.after?'dead_letter':i===0?'queued':'succeeded',
   attempts:1,reason:p.after?'deadline_or_retry_limit':i===0?'subscription_fetch_unavailable':'',
   ignored:'synthetic-untrusted-data'
  },createdAt:1800000000,updatedAt:1800000020,nextAttemptAt:!p.after&&i===0?1800000060:0}));
  send(200,{sourceId:p.sourceId,jobs:rows,next:p.after?'':'job-19',observedAt:1800000020});break;
 }
 case 'source.snapshot':send(200,{snapshot:{id:'snapshot-a',observedAt:1800000000,validUntil:1800003600},profiles:[{id:'profile-a',name:'Synthetic proxy',kind:'http'}]});break;
 case 'configuration.draft.get':{const d=drafts.get(p.id);send(d?200:403,d||{});break;}
 case 'configuration.draft.put':{
  const old=operations.get(body.requestId);
  if(old){send(old.raw===raw?200:409,old.value);break;}
  const current=drafts.get(p.draft.id),draft=p.draft;
  if((current?.revision||0)!==draft.revision){send(409,{});break;}
  if(draft.savedAt!==0||draft.plan?.schemaVersion!==1||!draft.plan?.graph||!draft.plan?.network||!draft.plan?.activation){send(400,{});break;}
  const value={...draft,revision:draft.revision+1,savedAt:1800000000};drafts.set(value.id,value);operations.set(body.requestId,{raw,value});
  if(failSave){failSave=false;send(503,{});}else send(200,value);break;
 }
 default:send(400,{});
 }
});server.listen(17851,'127.0.0.1');
