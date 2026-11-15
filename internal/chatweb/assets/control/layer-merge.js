// A review aid only. Server preview/publication repeats live ACL, inheritance,
// source and revision checks; this function grants no publication authority.
function canonical(value){
 if(value===undefined)return 'absent';
 if(value===null||typeof value!=='object')return 'json:'+JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
const equal=(a,b)=>canonical(a)===canonical(b);
const clone=value=>value===undefined?undefined:structuredClone(value);
const own=(layer,device)=>layer.id===device&&['device','local'].includes(layer.kind);
function indexed(items){
 const map=new Map();if(items!=null&&!Array.isArray(items))throw Error('invalid');
 for(const item of items||[]){if(!item||typeof item.path!=='string'||map.has(item.path))throw Error('invalid');map.set(item.path,item);}
 return map;
}
function portable(layer){
 if(!layer)return undefined;
 if(Object.keys(layer).some(k=>!['id','kind','priority','revision','changes','permissions'].includes(k))||layer.priority!==0||!Number.isSafeInteger(layer.revision)||layer.revision<1)throw Error('invalid');
 return {id:layer.id,kind:layer.kind,priority:layer.priority,changes:layer.changes||[],permissions:layer.permissions||[]};
}
function parentLayers(layers,device){return layers.filter(l=>!own(l,device)).sort((a,b)=>(a.kind+'/'+a.id).localeCompare(b.kind+'/'+b.id));}

export function mergeDeviceProposal(base,current,proposal,choices={}){
 const bundle=proposal?.bundles?.[0],device=proposal?.targetId;
 if(proposal?.targetKind!=='device'||proposal.bundles.length!==1||!bundle||bundle.device!==device||base?.device!==device||current?.device!==device||base.owner!==current.owner||current.historical||base.revision!==bundle.baseRevision||base.hash!==bundle.baseHash||current.revision<base.revision||!Array.isArray(base.layers)||!Array.isArray(current.layers)||!Array.isArray(bundle.layers)||!equal(parentLayers(base.layers,device),parentLayers(bundle.layers,device)))throw Error('invalid');
 const conflicts=[];
 function pick(path,b,l,r){
  if(equal(l,b))return clone(r);
  if(equal(r,b)||equal(l,r))return clone(l);
  const choice=Object.hasOwn(choices,path)?choices[path]:'';
  if(choice&&!['local','remote'].includes(choice))throw Error('invalid');
  conflicts.push({path,base:clone(b),local:clone(l),remote:clone(r),choice});
  return clone(choice==='local'?l:r);
 }
 function records(path,b,l,r){
  const bm=indexed(b),lm=indexed(l),rm=indexed(r),out=[];
  for(const key of [...new Set([...bm.keys(),...lm.keys(),...rm.keys()])].sort()){
   const value=pick(path+key,bm.get(key),lm.get(key),rm.get(key));if(value!==undefined)out.push(value);
  }
  return out;
 }
 const targetLayers=[];
 for(const kind of ['device','local']){
  const get=layers=>{const found=layers.filter(l=>l.kind===kind&&l.id===device);if(found.length>1)throw Error('invalid');return found[0];};
  const b=get(base.layers),l=get(bundle.layers),r=get(current.layers),bp=portable(b),lp=portable(l),rp=portable(r);
  let value;
  if(l&&r){
   value={id:device,kind,priority:0,changes:records(kind+'/changes',bp?.changes,lp.changes,rp.changes),permissions:records(kind+'/permissions',bp?.permissions,lp.permissions,rp.permissions)};
  }else value=pick(kind,bp,lp,rp);
  if(value===undefined)continue;
  const paths=value.changes.map(c=>c.path);
  if(paths.some((p,i)=>paths.some((q,j)=>i!==j&&(p===q||p.startsWith(q+'/')))))throw Error('overlap');
  const unchanged=equal(value,rp),revision=unchanged?r.revision:(r?.revision||0)+1;
  if(!Number.isSafeInteger(revision)||revision>Number.MAX_SAFE_INTEGER)throw Error('invalid');
  // Preserve exact immutable null/empty representation when reusing a head.
  targetLayers.push(unchanged?clone(r):{...value,revision});
 }
 const next=structuredClone(proposal);
 next.mode=pick('mode',base.mode,proposal.mode,current.mode);
 next.approvalUntilMs=pick('approvalUntilMs',base.approvalUntilMs,proposal.approvalUntilMs,current.approvalUntilMs);
 next.bundles=[{device,baseRevision:current.revision,baseHash:current.hash,layers:[...clone(parentLayers(current.layers,device)),...targetLayers]}];
 return {proposal:next,conflicts,ready:conflicts.every(c=>!!c.choice)};
}
