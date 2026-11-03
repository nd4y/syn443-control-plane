import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
async function state(request){return (await request.post(origin+'/fixture/state',{data:{}})).json();}
async function start(page,request,options={}){
 await request.post(origin+'/fixture/reset',{data:options});await page.goto(origin);
 await expect(page.locator('#load-inventory')).toBeEnabled();await page.locator('#inventory-device').fill('device-a');await page.locator('#load-inventory').click();
 await expect(page.locator('#layer-from-device')).toBeEnabled();await page.locator('#layer-from-device').click();
 const proposal=JSON.parse(await page.locator('#layer-proposal').inputValue());
 expect(proposal.bundles[0].baseRevision).toBe(7);expect(proposal.bundles[0].baseHash).toBe('a'.repeat(64));
 expect(proposal.bundles[0].layers[0]).toEqual({id:'template-a',kind:'template',priority:0,revision:2,changes:[],permissions:null});
 const own=proposal.bundles[0].layers.find(l=>l.kind==='device');own.changes=[{path:'/network/dnsStrategy',operation:'set',value:'ipv4_only'}];
 await page.locator('#layer-proposal').fill(JSON.stringify(proposal,null,2));return proposal;
}
async function save(page){await page.locator('#layer-save').click();await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');}
async function preview(page){await page.locator('#layer-preview').click();await expect(page.locator('#layer-poll')).toBeEnabled();await page.locator('#layer-poll').click();}

test('layer editor preserves inheritance and requires explicit reviewed publication',async({page,request})=>{
 const proposal=await start(page,request);await save(page);await preview(page);
 await expect(page.locator('#layer-review')).toBeVisible();await expect(page.locator('#layer-impact')).toContainText('template-a');await expect(page.locator('#layer-impact')).toContainText('device-a');
 await expect(page.locator('#layer-publish')).toBeDisabled();expect((await state(request)).calls).not.toContain('configuration.publish');
 await page.locator('#layer-confirm').check();await page.locator('#layer-publish').click();
 await expect(page.locator('#layer-proposal')).toBeDisabled();await page.locator('#layer-poll').click();
 await expect(page.locator('#layer-result')).toContainText('Желаемая конфигурация опубликована. Активация Android ещё не подтверждена.');
 const s=await state(request);expect(s.operations).toBe(3);expect(s.layerDrafts).toHaveLength(1);expect(s.layerDrafts[0].proposal).toEqual(proposal);
 await page.setViewportSize({width:360,height:800});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test('layer save lost acknowledgment replays one private revision and remains reopenable',async({page,request})=>{
 await start(page,request,{failSave:true});await page.locator('#layer-save').click();await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#layer-proposal')).toBeDisabled();
 await page.locator('#retry-save').click();await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');await expect(page.locator('#pending')).toBeHidden();
 await page.locator('#layer-proposal').fill('{}');await page.locator('#layer-load').click();await expect(page.locator('#layer-proposal')).toHaveValue(/"draftRevision": 1/);
 expect(JSON.parse(await page.locator('#layer-proposal').inputValue()).draftRevision).toBe(1);
 const s=await state(request);expect(s.operations).toBe(1);expect(s.layerDrafts[0].revision).toBe(1);expect(s.calls).not.toContain('configuration.publish');
});

test('layer publication lost acknowledgment reuses operation even after terminal commit',async({page,request})=>{
 await start(page,request,{failPublish:true});await save(page);await preview(page);await page.locator('#layer-confirm').check();await page.locator('#layer-publish').click();
 await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#discard-save')).toBeDisabled();await page.locator('#retry-save').click();await expect(page.locator('#pending')).toBeHidden();
 await page.locator('#layer-poll').click();await expect(page.locator('#layer-result')).toContainText('Активация Android ещё не подтверждена');
 const s=await state(request);expect(s.operations).toBe(3);expect(s.calls.filter(a=>a==='configuration.publish')).toHaveLength(2);
});

test('layer conflict mismatched preview and expiry never enable publication',async({page,request})=>{
 for(const options of [{previewConflict:true},{previewMismatch:true},{previewExpired:true}]){
  await start(page,request,options);await save(page);await preview(page);await expect(page.locator('#layer-review')).toBeHidden();await expect(page.locator('#layer-publish')).toBeDisabled();
  const s=await state(request);expect(s.calls).not.toContain('configuration.publish');expect(s.layerDrafts).toHaveLength(1);
 }
});

test('layer edit invalidates review and authorization withdrawal erases private proposal',async({page,request})=>{
 await start(page,request);await save(page);await preview(page);await page.locator('#layer-confirm').check();await expect(page.locator('#layer-publish')).toBeEnabled();
 const text=await page.locator('#layer-proposal').inputValue();await page.locator('#layer-proposal').fill(text+' ');await expect(page.locator('#layer-review')).toBeHidden();await expect(page.locator('#layer-publish')).toBeDisabled();await expect(page.locator('#layer-confirm')).not.toBeChecked();
 await page.locator('#layer-proposal').fill(text);await preview(page);await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#layer-load').click();
 await expect(page.locator('#status')).toContainText('Доступ отозван');await expect(page.locator('#layer-proposal')).toHaveValue('');await expect(page.locator('#layer-impact')).toHaveText('');await expect(page.locator('#layer-id')).toHaveValue('');
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
 await start(page,request);await save(page);await preview(page);await page.locator('#logout').click();await expect(page.locator('#layer-proposal')).toHaveValue('');await expect(page.locator('#layer-impact')).toHaveText('');
});
