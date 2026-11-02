// Synthetic UI fixture. Actual SQL/CAS, OAuth/DPoP and scope are Go-tested.
import http from 'node:http';import fs from 'node:fs';
let auth=true,denied=false,failSave=false,drafts=new Map(),operations=new Map(),calls=[];
const server=http.createServer(async(req,res)=>{
 const send=(status,data)=>{const headers={'Content-Type':'application/json','Cache-Control':'no-store'};if(req.url.startsWith('/fixture/'))headers.Connection='close';res.writeHead(status,headers);res.end(JSON.stringify(data));};
 if(req.method==='GET'&&['/','/app.js','/style.css'].includes(req.url)){
  const name=req.url==='/'?'index.html':req.url.slice(1);res.writeHead(200,{'Content-Type':name.endsWith('js')?'text/javascript':name.endsWith('css')?'text/css':'text/html','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});res.end(fs.readFileSync(new URL('../internal/chatweb/assets/control/'+name,import.meta.url)));return;
 }
 let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>278528){send(413,{});return;}}
 let body;try{body=JSON.parse(raw||'{}');}catch{send(400,{});return;}
 if(req.url==='/fixture/reset'){auth=true;denied=false;failSave=!!body.failSave;drafts=new Map();operations=new Map();calls=[];send(200,{});return;}
 if(req.url==='/fixture/state'){send(200,{drafts:[...drafts.values()],operations:operations.size,calls});return;}
 if(req.url==='/fixture/revoke'){denied=true;send(200,{});return;}
 if(req.url==='/fixture/expire'){auth=false;send(200,{});return;}
 if(req.headers['x-syn443-csrf']!=='1'||req.headers.origin!=='http://127.0.0.1:17851'){send(403,{});return;}
 if(!auth){send(401,{});return;}
 if(req.url==='/session'){send(200,{authenticated:true});return;}
 if(req.url==='/logout'){auth=false;send(200,{ok:true});return;}
 if(denied){send(403,{});return;}
 if(req.url!=='/control/action'||body.version!==1){send(404,{});return;}
 calls.push(body.action);
 const p=body.payload;
 switch(body.action){
 case 'source.list':send(200,{sources:[{id:'source-a',name:'<img src=x onerror="window.injected=true">',state:'active',revision:1,networkModes:['wifi'],activeSnapshot:'snapshot-a'}],next:p.after?'':'source-a'});break;
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
