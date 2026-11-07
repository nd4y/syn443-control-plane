import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const plan={schemaVersion:1,graph:{profiles:{proxy:{sourceId:'source-a',profileId:'profile-a'}},chains:{},balancers:{},final:'proxy'},network:{schemaVersion:1,requiredNetworks:['tcp'],dnsFinal:'system',dnsStrategy:'prefer_ipv4'},activation:{timeoutSeconds:30,checks:[{id:'internet',type:'https_204',target:'https://health.example.invalid/generate_204',required:true}]}};
async function reset(request,body={}){await request.post(origin+'/fixture/reset',{data:body});}

test('source job history shows bounded retries and clears scoped results on logout',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#load-sources')).toBeEnabled();
 await expect(page.locator('#source-history')).toBeDisabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 await page.locator('#source-history').click();
 const history=page.locator('#source-history-list');
 await expect(history.locator('li')).toHaveCount(20);
 await expect(history).toContainText('В очереди');
 await expect(history).toContainText('не ранее');
 await expect(history).toContainText('subscription_fetch_unavailable');
 await expect(history).not.toContainText('synthetic-untrusted-data');
 await page.locator('#source-history-more').click();
 await expect(history.locator('li')).toHaveCount(21);
 await expect(history).toContainText('Истёк срок или лимит повторов');
 await expect(page.locator('#source-history-more')).toBeDisabled();
 await page.locator('#logout').click();
 await expect(history).toHaveText('');
 await expect(page.locator('#source-history')).toBeDisabled();
});

test('manual subscription file retries exactly once without exposing or storing its contents',async({page,request})=>{
 await reset(request,{manualSource:true,importFailOnce:true});await page.goto(origin);await expect(page.locator('#load-sources')).toBeEnabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 const file=page.locator('#source-import-file');
 await expect(file).toBeEnabled();
 await file.setInputFiles({name:'synthetic.txt',mimeType:'text/plain',buffer:Buffer.from('http://proxy.example.invalid:443')});
 await expect(page.locator('#source-import')).toBeEnabled();
 await page.locator('#source-import').click({timeout:5000});
 await expect(page.locator('#pending')).toBeVisible();await expect(file).toHaveValue('');
 await page.locator('#retry-save').click();
 await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#job-status')).toContainText('synthetic-import-job');
 await expect(page.locator('main')).not.toContainText('proxy.example.invalid');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls.filter(call=>call==='source.import')).toHaveLength(2);expect(state.operations).toBe(1);
 expect(state.calls).not.toContain('configuration.publish');
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});
async function draft(page){await page.locator('#draft-id').fill('draft-a');await page.locator('#target-id').fill('device-a');await page.locator('#plan').fill(JSON.stringify(plan,null,2));}
test('console safely renders source metadata and saves/reopens its private draft',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#save-draft')).toBeEnabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await expect(page.locator('#sources')).toContainText('<img src=x');expect(await page.evaluate(()=>window.injected)).toBeUndefined();expect(await page.locator('#sources img').count()).toBe(0);
 await page.getByRole('button',{name:'Показать профили'}).click();await expect(page.locator('#profiles')).toContainText('profile-a');await expect(page.locator('#source-details')).toContainText('snapshot-a');
 await page.locator('#more-sources').click();await expect(page.locator('#sources li')).toHaveCount(2);
 await draft(page);await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toHaveText('Версия черновика: 1');
 await page.locator('#plan').fill('{}');await page.locator('#open-draft').click();await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan,null,2));
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('lost save response retries identical operation without another revision',async({page,request})=>{
 await reset(request,{failSave:true});await page.goto(origin);await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);await page.locator('#save-draft').click();
 await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#plan')).toBeDisabled();await page.locator('#retry-save').click();
 await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#draft-version')).toHaveText('Версия черновика: 1');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);expect(state.drafts[0].revision).toBe(1);
});
test('invalid plan keeps edit available, revoked rights and logout clear private memory',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);await page.locator('#plan').fill('{"schemaVersion":1}');await page.locator('#save-draft').click();
 await expect(page.locator('#status')).toContainText('Проверьте поля');await expect(page.locator('#plan')).toBeEnabled();await expect(page.locator('#pending')).toBeHidden();
 await page.locator('#plan').fill(JSON.stringify(plan));await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#save-draft').click();
 await expect(page.locator('#status')).toContainText('Доступ отозван');await expect(page.locator('#plan')).toHaveValue('');await expect(page.locator('#save-draft')).toBeDisabled();
 await reset(request);await page.reload();await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);await page.locator('#logout').click();await expect(page.locator('#plan')).toHaveValue('');await expect(page.locator('#target-id')).toHaveValue('');
 expect(await page.evaluate(()=>localStorage.length)).toBe(0);expect(await page.evaluate(()=>sessionStorage.length)).toBe(0);
});
test('phone layout stays dark and within viewport; expired session hides old data',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:360,height:800});await page.goto(origin);await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);expect(await page.evaluate(()=>getComputedStyle(document.documentElement).colorScheme)).toBe('dark');
 await request.post(origin+'/fixture/expire',{data:{}});await page.locator('#save-draft').click();await expect(page.locator('#status')).toContainText('Сессия завершена');await expect(page.locator('#plan')).toHaveValue('');
});

async function newSource(page){await page.locator('#owner').fill('synthetic-user');await page.locator('#new-source').click();await page.locator('#source-name').fill('Provider subscription');await page.locator('#source-secret-operation').selectOption('replace');await page.locator('#source-secret').fill(JSON.stringify({url:'https://provider.example.invalid/subscription'}));}
test('source editor saves metadata without exposing prior secrets and tracks sync job',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);const id=await page.locator('#source-id').inputValue();
 await page.locator('#save-source').click();await expect(page.locator('#source-version')).toContainText('Версия источника: 1');await expect(page.locator('#source-secret')).toHaveValue('');await expect(page.locator('#source-secret-operation')).toHaveValue('keep');
 await page.locator('#sync-source').click();await expect(page.locator('#job-status')).toContainText('queued');await page.locator('#source-job').click();await expect(page.locator('#job-status')).toContainText('succeeded');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.sources.find(s=>s.id===id).name).toBe('Provider subscription');expect(state.operations).toBe(2);expect(state.calls).not.toContain('configuration.publish');
 await page.locator('#load-sources').click();await page.locator('#sources li').filter({hasText:'Provider subscription'}).getByRole('button',{name:'Настроить источник'}).click();await expect(page.locator('#source-secret')).toHaveValue('');await expect(page.locator('#source-id')).toBeDisabled();
});
test('source mutation lost acknowledgment retries the same request and clears new secret on success',async({page,request})=>{
 await reset(request,{failSave:true});await page.goto(origin);await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);await page.locator('#save-source').click();await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#source-secret')).toBeDisabled();
 await page.locator('#retry-save').click();await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#source-version')).toContainText('Версия источника: 1');await expect(page.locator('#source-secret')).toHaveValue('');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);expect(state.sources.filter(s=>s.name==='Provider subscription')).toHaveLength(1);
});
test('source permission withdrawal erases unsent credentials and disables mutation',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#save-source').click();
 await expect(page.locator('#status')).toContainText('Доступ отозван');await expect(page.locator('#source-secret')).toHaveValue('');await expect(page.locator('#source-name')).toHaveValue('');await expect(page.locator('#save-source')).toBeDisabled();
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('desired device view keeps revision provenance and hostile content separate from activation',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#load-inventory')).toBeEnabled();
 await page.locator('#inventory-device').fill('device-a');await page.locator('#load-inventory').click();
 await expect(page.locator('#inventory-view')).toBeVisible();await expect(page.locator('#inventory-state')).toContainText('Назначена');
 await expect(page.locator('#inventory-meta')).toContainText('Желаемая версия7');await expect(page.locator('#inventory-meta')).toContainText('Версия выданной политики23');
 await expect(page.locator('#inventory-meta')).toContainText('Источник выданной политикиСоответствует желаемой');
 await expect(page.locator('#inventory-meta')).toContainText('Откат · политика 23');await expect(page.locator('#inventory-meta')).toContainText('Версия по отчёту21');
 await expect(page.locator('#inventory-meta')).toContainText('a'.repeat(64));
 await expect(page.locator('#inventory-layers')).toContainText('template-a');await expect(page.locator('#inventory-fields')).toContainText('/network/dnsStrategy');await expect(page.locator('#inventory-fields')).toContainText('template-a');
 await expect(page.locator('#inventory-restrictions')).toContainText('choice');await expect(page.locator('#inventory-effective')).toContainText('<img src=x');
 expect(await page.locator('#inventory-view img').count()).toBe(0);expect(await page.evaluate(()=>window.injected)).toBeUndefined();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.calls).toContain('configuration.inventory.get');expect(state.calls).not.toContain('configuration.publish');expect(state.operations).toBe(0);
 await page.setViewportSize({width:360,height:800});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.locator('#logout').click();await expect(page.locator('#inventory-view')).toBeHidden();await expect(page.locator('#inventory-effective')).toHaveText('');
});

test('desired device view distinguishes unassigned expired and mismatched responses',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#load-inventory')).toBeEnabled();
 await page.locator('#inventory-device').fill('device-unassigned');await page.locator('#load-inventory').click();await expect(page.locator('#inventory-state')).toContainText('Не назначена');await expect(page.locator('#inventory-effective')).toHaveText('Нет действующих настроек.');
 await expect(page.locator('#inventory-meta')).toContainText('Ожидаем результат применения');
 await expect(page.locator('#inventory-meta')).toContainText('Источник не зафиксирован');
 await page.locator('#inventory-device').fill('device-expired');await page.locator('#load-inventory').click();await expect(page.locator('#inventory-state')).toContainText('Истекла');
 await expect(page.locator('#inventory-meta')).toContainText('Откат · политика 22 · предыдущая или истёкшая выдача');
 await expect(page.locator('#inventory-meta')).toContainText('Выдана из другой ревизии');
 await page.locator('#inventory-device').fill('device-mismatch');await page.locator('#load-inventory').click();await expect(page.locator('#status')).toContainText('Проверьте поля');await expect(page.locator('#inventory-view')).toBeHidden();
 await page.locator('#inventory-device').fill('device-a');await page.locator('#load-inventory').click();await expect(page.locator('#inventory-view')).toBeVisible();
 await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#load-inventory').click();await expect(page.locator('#inventory-view')).toBeHidden();await expect(page.locator('#inventory-meta')).toHaveText('');
});
