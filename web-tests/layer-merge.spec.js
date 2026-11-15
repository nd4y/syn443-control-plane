import {test,expect} from '@playwright/test';
import {mergeDeviceProposal} from '../internal/chatweb/assets/control/layer-merge.js';
const change=(path,value)=>({path,operation:'set',value});
const template=revision=>({id:'template-a',kind:'template',priority:0,revision,changes:[change('/root',{network:{}})],permissions:[]});
const device=(revision,changes)=>({id:'device-a',kind:'device',priority:0,revision,changes,permissions:[]});
function fixture(){
 const base={device:'device-a',owner:'user-a',revision:4,hash:'a'.repeat(64),mode:'wifi',approvalUntilMs:1800003600000,layers:[template(1),device(1,[change('/network/dnsStrategy','prefer_ipv4')])]};
 const current=structuredClone(base);current.revision=5;current.hash='b'.repeat(64);current.layers[0]=template(2);current.layers[1].revision=2;
 const proposal={draftId:'draft-a',draftRevision:1,targetKind:'device',targetId:'device-a',mode:base.mode,approvalUntilMs:base.approvalUntilMs,bundles:[{device:base.device,baseRevision:base.revision,baseHash:base.hash,layers:structuredClone(base.layers)}]};proposal.bundles[0].layers[1].revision=2;
 return {base,current,proposal};
}
test('three-way layer merge preserves current parents and combines independent paths',()=>{
 const {base,current,proposal}=fixture();proposal.bundles[0].layers[1].changes[0].value='ipv4_only';current.layers[1].changes.push(change('/activation/timeoutSeconds',45));
 const originals=JSON.stringify([base,current,proposal]);const result=mergeDeviceProposal(base,current,proposal);
 expect(result.ready).toBe(true);expect(result.conflicts).toEqual([]);expect(result.proposal.bundles[0].baseRevision).toBe(5);expect(result.proposal.bundles[0].baseHash).toBe(current.hash);expect(result.proposal.bundles[0].layers[0]).toEqual(current.layers[0]);
 const layer=result.proposal.bundles[0].layers[1];expect(layer.revision).toBe(3);expect(layer.changes).toContainEqual(change('/network/dnsStrategy','ipv4_only'));expect(layer.changes).toContainEqual(change('/activation/timeoutSeconds',45));expect(JSON.stringify([base,current,proposal])).toBe(originals);
});
test('three-way layer conflict requires an explicit local or server choice',()=>{
 const {base,current,proposal}=fixture();proposal.bundles[0].layers[1].changes[0].value='ipv4_only';current.layers[1].changes[0].value='ipv6_only';
 const result=mergeDeviceProposal(base,current,proposal);expect(result.ready).toBe(false);expect(result.conflicts).toHaveLength(1);const path=result.conflicts[0].path;
 const local=mergeDeviceProposal(base,current,proposal,{[path]:'local'});expect(local.ready).toBe(true);expect(local.proposal.bundles[0].layers[1].changes[0].value).toBe('ipv4_only');expect(local.proposal.bundles[0].layers[1].revision).toBe(3);
 const remote=mergeDeviceProposal(base,current,proposal,{[path]:'remote'});expect(remote.ready).toBe(true);expect(remote.proposal.bundles[0].layers[1]).toEqual(current.layers[1]);
 current.layers[1].permissions=null;
 const exact=mergeDeviceProposal(base,current,proposal,{[path]:'remote'});expect(exact.proposal.bundles[0].layers[1]).toEqual(current.layers[1]);
});
test('three-way layer merge refuses inherited edits unbound history and overlapping paths',()=>{
 for(const fault of ['parent','hash','device','historical','overlap']){
  const {base,current,proposal}=fixture();
  if(fault==='parent')proposal.bundles[0].layers[0].revision=3;
  if(fault==='hash')base.hash='c'.repeat(64);
  if(fault==='device')current.device='other-device';
  if(fault==='historical')current.historical=true;
  if(fault==='overlap'){proposal.bundles[0].layers[1].changes.push(change('/activation',{timeoutSeconds:30}));current.layers[1].changes.push(change('/activation/timeoutSeconds',45));}
  expect(()=>mergeDeviceProposal(base,current,proposal)).toThrow();
 }
});
test('three-way layer merge represents removals and concurrent creation without lost edits',()=>{
 const {base,current,proposal}=fixture();proposal.bundles[0].layers[1].changes=[];
 const removed=mergeDeviceProposal(base,current,proposal);expect(removed.ready).toBe(true);expect(removed.proposal.bundles[0].layers[1].changes).toEqual([]);
 base.layers=base.layers.slice(0,1);proposal.bundles[0].layers=[base.layers[0],device(1,[change('/network/dnsStrategy','ipv4_only')])];current.layers[1]=device(1,[change('/activation/timeoutSeconds',45)]);
 const created=mergeDeviceProposal(base,current,proposal);expect(created.ready).toBe(true);expect(created.proposal.bundles[0].layers[1].revision).toBe(2);expect(created.proposal.bundles[0].layers[1].changes).toHaveLength(2);
});
