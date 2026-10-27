// Synthetic browser UI fixture only. SQL/OAuth/DPoP are tested by the Go suites.
import http from 'node:http';import fs from 'node:fs';import crypto from 'node:crypto';
const conversation='a'.repeat(32),owner='A'.repeat(43);let messages=[],uploads=new Map(),calls=0,auth=true,denied=false,failSend=false;
const hash=data=>crypto.createHash('sha256').update(data).digest('hex');
const server=http.createServer(async(req,res)=>{
 const send=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
 if(req.method==='GET'&&['/','/app.js','/style.css'].includes(req.url)){const name=req.url==='/'?'index.html':req.url.slice(1);res.writeHead(200,{'Content-Type':name.endsWith('js')?'text/javascript':name.endsWith('css')?'text/css':'text/html','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"});res.end(fs.readFileSync(new URL('../internal/chatweb/assets/'+name,import.meta.url)));return;}
 let raw='';for await(const chunk of req){raw+=chunk;if(raw.length>360448){send(413,{});return;}}const body=JSON.parse(raw||'{}');
 if(req.url==='/fixture/reset'){messages=[];uploads=new Map();calls=0;auth=true;denied=false;failSend=!!body.failSend;send(200,{});return;}
 if(req.url==='/fixture/state'){send(200,{messages:messages.length,uploads:uploads.size,calls});return;}
 if(req.url==='/fixture/revoke'){denied=true;send(200,{});return;}
 if(req.url==='/fixture/expire'){auth=false;send(200,{});return;}
 calls++;if(req.headers['x-syn443-csrf']!=='1'||req.headers.origin!=='http://127.0.0.1:17850'){send(403,{});return;}
 if(!auth){send(401,{});return;}
 if(req.url==='/session'){send(200,{authenticated:true});return;}
 if(req.url==='/logout'){auth=false;send(200,{ok:true});return;}
 if(denied&&req.url.startsWith('/chat/')){send(403,{});return;}
 switch(req.url){
 case '/chat/self':send(200,{admin:true,conversation:{id:conversation,owner,lastSeq:messages.length,readSeq:0,updatedAt:1800000000}});break;
 case '/chat/inbox':send(200,[{id:conversation,owner,lastSeq:messages.length,readSeq:0,updatedAt:1800000000}]);break;
 case '/chat/messages':send(200,{messages:messages.filter(m=>m.sequence>body.after&&(!body.before||m.sequence<body.before)).slice(-20),peerRead:messages.length});break;
 case '/chat/read':send(200,{ok:true});break;
 case '/chat/uploads/begin':{let u=uploads.get(body.clientId);if(!u){u={attachment:{id:body.clientId,name:body.name,mime:body.mime,size:body.size,sha256:body.sha256,kind:body.kind},parts:new Map(),complete:false};uploads.set(body.clientId,u);}send(200,{attachment:u.attachment,complete:u.complete,parts:[...u.parts.keys()]});break;}
 case '/chat/uploads/part':{const u=uploads.get(body.upload),bytes=Buffer.from(body.data,'base64');if(!u||hash(bytes)!==body.sha256){send(400,{});break;}u.parts.set(body.part,bytes);send(200,{ok:true});break;}
 case '/chat/uploads/complete':{const u=uploads.get(body.upload),bytes=Buffer.concat([...u.parts.entries()].sort((a,b)=>a[0]-b[0]).map(x=>x[1]));if(bytes.length!==u.attachment.size||hash(bytes)!==u.attachment.sha256){send(409,{});break;}u.complete=true;send(200,{attachment:u.attachment,complete:true,parts:[...u.parts.keys()]});break;}
 case '/chat/send':{let message=messages.find(m=>m.clientId===body.clientId);if(!message){message={id:body.clientId,clientId:body.clientId,conversation,sequence:messages.length+1,sender:owner,senderRole:'admin',text:body.text,createdAt:1800000000,attachments:body.attachments.map(id=>uploads.get(id).attachment)};messages.push(message);}if(failSend){failSend=false;send(503,{});}else send(200,message);break;}
 case '/chat/download':{const data=uploads.get(body.attachment).parts.get(body.part);send(200,{data:data.toString('base64'),sha256:hash(data)});break;}
 default:send(404,{});
 }
});server.listen(17850,'127.0.0.1');
