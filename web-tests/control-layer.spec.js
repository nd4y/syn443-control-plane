import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
async function state(request){return (await request.post(origin+'/fixture/state',{data:{}})).json();}
async function start(page,request,options={}){
 await request.post(origin+'/fixture/reset',{data:options});await page.goto(origin);
 await expect(page.locator('#load-inventory')).toBeEnabled();await page.locator('#inventory-device').fill('device-a');await page.locator('#load-inventory').click();
 await page.getByRole('link',{name:'Открыть публикацию'}).click();
 await expect(page.locator('#layer-from-device')).toBeEnabled();await page.locator('#layer-from-device').click();
 const proposal=JSON.parse(await page.locator('#layer-proposal').inputValue());
 expect(proposal.bundles[0].baseRevision).toBe(7);expect(proposal.bundles[0].baseHash).toBe('a'.repeat(64));
 expect(proposal.bundles[0].layers[0]).toEqual({id:'template-a',kind:'template',priority:0,revision:2,changes:[],permissions:null});
 const own=proposal.bundles[0].layers.find(l=>l.kind==='device');own.changes=[{path:'/network/dnsStrategy',operation:'set',value:'ipv4_only'}];
 await page.locator('#layer-proposal').fill(JSON.stringify(proposal,null,2));return proposal;
}
async function save(page){await page.locator('#layer-save').click();await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');}
async function preview(page){await page.locator('#layer-preview').click();await expect(page.locator('#layer-poll')).toBeEnabled();await page.locator('#layer-poll').click();}

test('private layer discard requires confirmation and retains unsaved editor without publication',async({page,request})=>{
 await start(page,request);await save(page);await page.locator('#layer-list').click();
 const edited=JSON.parse(await page.locator('#layer-proposal').inputValue());edited.mode='home_wifi';
 const text=JSON.stringify(edited,null,2);await page.locator('#layer-proposal').fill(text);
 await expect(page.locator('#layer-discard')).toBeDisabled();await page.locator('#layer-discard-confirm').check();await page.locator('#layer-discard').click();
 await expect(page.locator('#layer-version')).toHaveText('Сохранённый черновик удалён');await expect(page.locator('#layer-proposal')).toHaveValue(text);
 await expect(page.locator('#layer-saved option')).toHaveCount(0);await expect(page.locator('#layer-preview')).toBeDisabled();await expect(page.locator('#layer-discard')).toBeDisabled();
 const s=await state(request);expect(s.layerDrafts).toHaveLength(0);expect(s.operations).toBe(2);expect(s.calls).not.toContain('configuration.preview.request');expect(s.calls).not.toContain('configuration.publish');
});

test('private layer discard lost acknowledgment retains exact operation until verified receipt',async({page,request})=>{
 await start(page,request,{discardFailOnce:true});await save(page);const text=await page.locator('#layer-proposal').inputValue();
 await page.locator('#layer-discard-confirm').check();await page.locator('#layer-discard').click();
 await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#discard-save')).toBeDisabled();
 await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');expect((await state(request)).operations).toBe(2);
 await page.locator('#retry-save').click();await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#layer-version')).toHaveText('Сохранённый черновик удалён');
 await expect(page.locator('#layer-proposal')).toHaveValue(text);const s=await state(request);expect(s.operations).toBe(2);expect(s.calls.filter(x=>x==='configuration.layers.draft.discard')).toHaveLength(2);
});

test('private layer discard conflicts and substituted receipts never clear the current editor',async({page,request})=>{
 for(const options of [{discardConflict:true},{discardMismatch:true}]){
  await start(page,request,options);await save(page);const text=await page.locator('#layer-proposal').inputValue();
  await page.locator('#layer-discard-confirm').check();await page.locator('#layer-discard').click();
  await expect(page.locator('#status')).toContainText(options.discardConflict?'Версия изменилась':'Проверьте поля');
  await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');await expect(page.locator('#layer-proposal')).toHaveValue(text);await expect(page.locator('#layer-publish')).toBeDisabled();
  const s=await state(request);expect(s.calls).not.toContain('configuration.publish');expect(s.calls).not.toContain('configuration.preview.request');
 }
});

test('private layer draft inventory lists metadata and reopens without implicit publication',async({page,request})=>{
 await start(page,request);await save(page);const before=await page.locator('#layer-proposal').inputValue();
 await page.locator('#layer-list').click();await expect(page.locator('#layer-saved option')).toHaveCount(1);
 await expect(page.locator('#layer-proposal')).toHaveValue(before);expect((await state(request)).operations).toBe(1);
 await page.locator('#layer-proposal').fill('{}');await page.locator('#layer-open-saved').click();
 await expect(page.locator('#layer-proposal')).toHaveValue(before);await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');
 const s=await state(request);expect(s.calls).toContain('configuration.layers.drafts.list');expect(s.calls).toContain('configuration.layers.draft.get');expect(s.calls).not.toContain('configuration.preview.request');expect(s.calls).not.toContain('configuration.publish');expect(s.operations).toBe(1);
});

test('private layer draft inventory rejects substituted duplicate oversized and unexpected metadata',async({page,request})=>{
 for(const options of [{draftListMismatch:true},{draftListDuplicate:true},{draftListExcess:true},{draftListExtra:true}]){
  await start(page,request,options);await save(page);const before=await page.locator('#layer-proposal').inputValue();
  await page.locator('#layer-list').click();await expect(page.locator('#status')).toContainText('Проверьте поля');
  await expect(page.locator('#layer-saved option')).toHaveCount(0);await expect(page.locator('#layer-open-saved')).toBeDisabled();await expect(page.locator('#layer-proposal')).toHaveValue(before);
  expect(await page.evaluate(()=>window.injected)).toBeUndefined();expect((await state(request)).operations).toBe(1);
 }
});

test('private layer draft inventory disappears on rights withdrawal and logout',async({page,request})=>{
 await start(page,request);await save(page);await page.locator('#layer-list').click();await expect(page.locator('#layer-saved option')).toHaveCount(1);
 await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#layer-list').click();await expect(page.locator('#status')).toContainText('Доступ отозван');
 await expect(page.locator('#layer-saved option')).toHaveCount(0);await expect(page.locator('#layer-proposal')).toHaveValue('');await expect(page.locator('#layer-list')).toBeDisabled();
 await start(page,request);await save(page);await page.locator('#layer-list').click();await expect(page.locator('#layer-saved option')).toHaveCount(1);
 await page.locator('#logout').click();await expect(page.locator('#layer-saved option')).toHaveCount(0);await expect(page.locator('#layer-list-status')).toHaveText('');
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('empty private layer draft inventory preserves an unsaved proposal and does not invent a copy',async({page,request})=>{
 await start(page,request);const before=await page.locator('#layer-proposal').inputValue();await page.locator('#layer-list').click();
 await expect(page.locator('#layer-list-status')).toContainText('нет сохранённых');await expect(page.locator('#layer-saved option')).toHaveCount(0);
 await expect(page.locator('#layer-open-saved')).toBeDisabled();await expect(page.locator('#layer-proposal')).toHaveValue(before);expect((await state(request)).operations).toBe(0);
});

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

test('layer comparison resolves conflict into a draft without silently saving or publishing',async({page,request})=>{
 await start(page,request);await save(page);await request.post(origin+'/fixture/advance',{data:{}});await page.locator('#layer-compare').click();
 await expect(page.locator('#layer-comparison')).toBeVisible();await expect(page.locator('#layer-conflicts')).toContainText('device/changes/network/dnsStrategy');await expect(page.locator('#layer-merge')).toBeDisabled();
 await page.locator('#layer-conflicts').getByRole('button',{name:'Оставить локальное'}).click();await expect(page.locator('#layer-merge')).toBeEnabled();
 expect((await state(request)).operations).toBe(1);await page.locator('#layer-merge').click();await expect(page.locator('#layer-comparison')).toBeHidden();
 const merged=JSON.parse(await page.locator('#layer-proposal').inputValue());expect(merged.bundles[0].baseRevision).toBe(8);expect(merged.bundles[0].baseHash).toBe('d'.repeat(64));expect(merged.bundles[0].layers.find(l=>l.kind==='device').revision).toBe(2);
 await expect(page.locator('#layer-preview')).toBeDisabled();expect((await state(request)).operations).toBe(1);
 await page.locator('#layer-save').click();await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 2');const s=await state(request);expect(s.operations).toBe(2);expect(s.calls).not.toContain('configuration.publish');
});

test('unassigned device can stage its first layer draft from an explicit plan',async({page,request})=>{
 await request.post(origin+'/fixture/reset',{data:{}});
 await page.goto(origin);
 await page.locator('#inventory-device').fill('device-unassigned');
 await page.locator('#load-inventory').click();
 await page.getByRole('link',{name:'Открыть публикацию'}).click();
 const first=page.locator('#layer-first-from-plan'),proposal=page.locator('#layer-proposal');
 await expect(first).toBeEnabled();
 await first.click();
 await expect(page.locator('#status')).toContainText('Проверьте поля');
 await expect(proposal).toHaveValue('');
 await page.getByRole('link',{name:'Открыть планы'}).click();
 const plan={
  schemaVersion:1,
  graph:{profiles:{},chains:{},balancers:{},final:'direct'},
  network:{schemaVersion:1,requiredNetworks:['tcp'],dnsFinal:'system',dnsStrategy:'prefer_ipv4'},
  activation:{timeoutSeconds:60,allowDegraded:false,checks:[{id:'internet',type:'https_204',target:'https://health.example.invalid/generate_204',required:true}]},
 };
 await page.locator('#plan').fill(JSON.stringify(plan));
 await page.getByRole('link',{name:'Публикация',exact:true}).click();
 await page.locator('#layer-first-mode').selectOption('home_wifi');
 await first.click();
 const value=JSON.parse(await proposal.inputValue());
 expect(value).toMatchObject({draftRevision:1,targetKind:'device',targetId:'device-unassigned',mode:'home_wifi'});
 expect(value.bundles[0]).toMatchObject({device:'device-unassigned',baseRevision:0,baseHash:''});
 const [layer]=value.bundles[0].layers;
 expect(layer).toMatchObject({kind:'template',priority:0,revision:1,permissions:[]});
 expect(Object.fromEntries(layer.changes.map(change=>[change.path.slice(1),change.value]))).toEqual(plan);
 await expect(first).toBeDisabled();
 await expect(page.locator('#layer-preview')).toBeDisabled();
 expect((await state(request)).operations).toBe(0);
 await save(page);
 await expect(page.locator('#layer-preview')).toBeEnabled();
 await expect(page.locator('#layer-publish')).toBeDisabled();
 const saved=await state(request);
 expect(saved.layerDrafts).toHaveLength(1);
 expect(saved.calls).not.toContain('configuration.publish');
});
