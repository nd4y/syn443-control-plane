import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const plan={schemaVersion:1,graph:{profiles:{proxy:{sourceId:'source-a',profileId:'profile-a'}},chains:{},balancers:{},final:'proxy'},network:{schemaVersion:1,requiredNetworks:['tcp'],dnsFinal:'system',dnsStrategy:'prefer_ipv4'},activation:{timeoutSeconds:30,checks:[{id:'internet',type:'https_204',target:'https://health.example.invalid/generate_204',required:true}]}};
async function reset(request,body={}){await request.post(origin+'/fixture/reset',{data:body});}

test('hourly telemetry distinguishes data empty and mismatched reports and clears on expiry',async({page,request})=>{
 await reset(request);await page.goto(origin);
 const button=page.locator('#load-telemetry'),hour=page.locator('#telemetry-hour'),rows=page.locator('#telemetry-rows'),status=page.locator('#telemetry-status');
 await expect(button).toBeEnabled();
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(status).toHaveText('Сводка за 2026-01-02T01:00Z');
 await expect(rows.locator('td')).toHaveText(['probe','ok','wifi','3','26 мс']);
 await hour.fill('2026-01-02T02:00');await button.click();
 await expect(status).toContainText('нет готовой сводки');await expect(rows).toHaveText('');
 await hour.fill('2026-01-02T03:00');await button.click();
 await expect(status).toContainText('Не удалось загрузить');await expect(rows).toHaveText('');
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(rows.locator('tr')).toHaveCount(1);
 await request.post(origin+'/fixture/expire',{data:{}});
 await button.click();await expect(button).toBeDisabled();await expect(rows).toHaveText('');
 await expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('scoped telemetry denial preserves an unrelated unsaved draft',async({page,request})=>{
 await reset(request,{telemetryDenied:true});await page.goto(origin);
 await expect(page.locator('#load-telemetry')).toBeEnabled();
 await draft(page);
 await page.locator('#load-telemetry').click();
 await expect(page.locator('#telemetry-status')).toContainText('Нет доступа');
 await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan,null,2));
 await expect(page.locator('#logout')).toBeEnabled();
 await request.post(origin+'/fixture/revoke',{data:{}});
 await page.locator('#load-telemetry').click();
 await expect(page.locator('#plan')).toHaveValue('');
 await expect(page.locator('#logout')).toBeDisabled();
});

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

test('source recipient edits require confirmation and retry the same scoped mutation',async({page,request})=>{
 await reset(request,{sharesFailOnce:true});await page.goto(origin);await expect(page.locator('#load-sources')).toBeEnabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 await page.locator('#source-shares-load').click();
 const recipient=page.locator('#source-shares-id'),list=page.locator('#source-shares-list');
 await expect(recipient).toBeEnabled();await page.locator('#source-shares-kind').selectOption('device');
 await recipient.fill('device-a');await page.locator('#source-shares-add').click();await expect(list).toContainText('Устройство · device-a');
 await expect(page.locator('#source-shares-save')).toBeDisabled();
 await page.locator('#source-shares-confirm').check();await page.locator('#source-shares-save').click();
 await expect(page.locator('#pending')).toBeVisible();await expect(recipient).toBeDisabled();
 await page.locator('#retry-save').click();
 await expect(page.locator('#source-shares-revision')).toContainText('Версия списка: 1');
 await expect(page.locator('#pending')).toBeHidden();await expect(list).toContainText('device-a');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls.filter(call=>call==='source.shares.put')).toHaveLength(2);
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
 await request.post(origin+'/fixture/revoke',{data:{}});
 await page.locator('#source-shares-load').click();
 await expect(list).toHaveText('');await expect(page.locator('#source-shares-save')).toBeDisabled();
});
async function draft(page){await page.locator('#draft-id').fill('draft-a');await page.locator('#target-id').fill('device-a');await page.locator('#plan').fill(JSON.stringify(plan,null,2));}
test('route checks editor changes only its private draft and restores saved checks',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#save-draft')).toBeEnabled();
 await expect(page.locator('#route-check-add')).toBeDisabled();
 await draft(page);
 const target=page.locator('#route-check-target'),method=page.locator('#route-check-method');
 const list=page.locator('#route-check-list'),add=page.locator('#route-check-add');
 await expect(page.locator('#route-check-path')).toHaveValue('proxy');
 await page.locator('#route-check-required').check();
 await target.fill('home.example.invalid:22');await add.click();
 await expect(list).toContainText('home.example.invalid:22 · обязательная');
 await method.selectOption('https_204');await target.fill('https://health.example.invalid/204');await add.click();
 const expectedIP=page.locator('#route-check-ip');
 await expect(expectedIP).toBeHidden();await method.selectOption('https_exit_ip');await expect(expectedIP).toBeVisible();
 await target.fill('https://health.example.invalid/address');await expectedIP.fill('192.0.2.9');await add.click();
 await expect(list.locator('li')).toHaveCount(3);await expect(list).toContainText('192.0.2.9');
 let state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);
 const current=JSON.parse(await page.locator('#plan').inputValue());
 expect(current.network.routeChecks).toEqual([{outbound:'proxy',required:true,checks:[
  {method:'tcp',target:'home.example.invalid:22'},{method:'https_204',target:'https://health.example.invalid/204'},
  {method:'https_exit_ip',target:'https://health.example.invalid/address',expected_ip:'192.0.2.9'},
 ]}]);
 expect(current.graph).toEqual(plan.graph);
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await page.locator('#plan').fill('{}');await page.locator('#open-draft').click();
 await expect(list.locator('li')).toHaveCount(3);
 await list.locator('li').first().getByRole('button',{name:'Удалить проверку'}).click();
 await expect(list.locator('li')).toHaveCount(2);
 await target.fill('unsaved.example.invalid:443');await page.locator('#logout').click();
 await expect(target).toHaveValue('');await expect(expectedIP).toHaveValue('');await expect(list).toHaveText('');
 state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('reserve probe cooldown requires explicit draft opt in and never publishes',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const box=page.locator('#route-reserve-cooldown'),input=page.locator('#plan');
 await expect(box).toBeDisabled();
 const fixture=structuredClone(plan);
 fixture.graph.profiles.reserve={sourceId:'source-a',profileId:'profile-b'};
 fixture.graph.balancers['internal']={type:'selector',members:['proxy','reserve'],default:'proxy',interruptExisting:false};
 fixture.network.routeFailover={selector:'internal',networkMode:'wifi',intent:'INTERNAL'};
 await input.fill(JSON.stringify(fixture,null,2));await expect(box).toBeEnabled();await expect(box).not.toBeChecked();
 await box.check();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldown).toBe(true);
 const rolloutId=page.locator('#route-rollout-id'),share=page.locator('#route-rollout-share');
 await rolloutId.fill('fixture-canary');await share.fill('12.34');await page.locator('#route-rollout-save').click();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldownRollout).toEqual({id:'fixture-canary',basisPoints:1234});
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await input.fill('{}');await page.locator('#open-draft').click();await expect(box).toBeChecked();
 await expect(rolloutId).toHaveValue('fixture-canary');await expect(share).toHaveValue('12.34');
 await share.fill('0');await page.locator('#route-rollout-save').click();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldownRollout.basisPoints).toBe(0);
 await box.uncheck();const removed=JSON.parse(await input.inputValue()).network.routeFailover;
 expect(removed.probeCooldown).toBeUndefined();expect(removed.probeCooldownRollout).toBeUndefined();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
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
test('device subscription saves an immutable Wi-Fi binding without retaining the credential',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#new-source')).toBeEnabled();
 await newSource(page);const id=await page.locator('#source-id').inputValue(),binding=page.locator('#source-device');
 await expect(binding).toBeHidden();
 await page.locator('#source-mode').selectOption('device');await expect(binding).toBeEnabled();
 await binding.fill('device-a');await page.locator('#source-modes').selectOption('cellular');
 await page.locator('#save-source').click();await expect(page.locator('#status')).toContainText('Проверьте');
 await page.locator('#source-modes').selectOption('wifi');await page.locator('#save-source').click();
 await expect(page.locator('#source-version')).toContainText('Версия источника: 1');
 await expect(binding).toHaveValue('device-a');await expect(binding).toBeDisabled();
 await expect(page.locator('#source-mode')).toBeDisabled();await expect(page.locator('#source-secret')).toHaveValue('');
 await page.locator('#sync-source').click();await expect(page.locator('#job-status')).toContainText('queued');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.sources.find(s=>s.id===id)).toMatchObject({mode:'device',fetchDeviceId:'device-a',networkModes:['wifi']});
 expect(state.calls.filter(call=>call==='source.put')).toHaveLength(1);
 expect(state.calls).not.toContain('configuration.publish');
 await page.locator('#logout').click();await expect(binding).toHaveValue('');await expect(binding).toBeHidden();
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
