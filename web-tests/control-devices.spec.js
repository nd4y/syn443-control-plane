import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const reset=(request,body={})=>request.post(origin+'/fixture/reset',{data:body});

test('authorized device inventory opens a card without copying identifiers and separates old reports',async({page,request})=>{
 await reset(request);await page.goto(origin);
 await expect(page.locator('#device-rows tr')).toHaveCount(1);
 await expect(page.locator('#devices-status')).toHaveText('Загружено устройств: 1.');
 await expect(page.locator('#device-rows')).toContainText('Архивный отчёт · Откат');
 await expect(page.locator('#device-rows')).not.toContainText('Online');
 await page.getByRole('button',{name:'Открыть устройство device-a',exact:true}).click();
 await expect(page.locator('#inventory-device')).toHaveValue('device-a');
 await expect(page.locator('#inventory-view')).toBeVisible();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls).not.toContain('configuration.publish');
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('device inventory pagination is explicit and fits a narrow keyboard scroll region',async({page,request})=>{
 await reset(request,{devicePages:true});await page.setViewportSize({width:360,height:800});await page.goto(origin);
 await expect(page.locator('#device-rows tr')).toHaveCount(32);
 await expect(page.locator('#more-devices')).toBeEnabled();
 await page.locator('#more-devices').click();await expect(page.locator('#device-rows tr')).toHaveCount(33);
 await expect(page.locator('#more-devices')).toBeHidden();
 await page.locator('#devices-region').focus();await expect(page.locator('#devices-region')).toBeFocused();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByRole('button',{name:'Открыть устройство device-a',exact:true}).click();await expect(page.locator('#inventory-view')).toBeVisible();
});

test('selected device moves keyboard focus out of the collapsed discovery list',async({page,request})=>{
 await reset(request);await page.goto(origin);
 const button=page.getByRole('button',{name:'Открыть устройство device-a',exact:true});
 await expect(button).toBeEnabled();await button.focus();await button.press('Enter');
 const card=page.getByRole('region',{name:'Конфигурация выбранного устройства',exact:true});
 await expect(card).toBeVisible();await expect(card).toBeFocused();
 await expect(page.locator('#devices-disclosure')).not.toHaveAttribute('open','');
 await card.press('Tab');await expect(page.getByRole('link',{name:'Открыть публикацию',exact:true})).toBeFocused();
});

test('issued algorithm metadata has its own line and cannot keep stale device data',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#device=device-a');
 const issued=page.locator('#inventory-issued'),algorithm=page.locator('#inventory-issued-algorithm');
 await expect(algorithm).toHaveText('Алгоритм m4-confirmed-v1');
 for(const width of [1280,360]){
  await page.setViewportSize({width,height:900});
  const policyBox=await issued.boundingBox(),algorithmBox=await algorithm.boundingBox();
  expect(algorithmBox.y).toBeGreaterThanOrEqual(policyBox.y+policyBox.height+7);
  expect(await algorithm.evaluate(el=>getComputedStyle(el,'::before').content)).toBe('none');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }
 await page.locator('#inventory-device').fill('device-expired');await page.locator('#inventory-device').press('Enter');
 await expect(algorithm).toBeHidden();await expect(algorithm).toHaveText('');
});

test('device inventory refuses malformed oversized duplicate and substituted metadata atomically',async({page,request})=>{
 for(const invalidDeviceList of ['duplicate','extra','cursor','oversize','revision','report','order','missing-expiry','archive-expiry']){
  await reset(request,{invalidDeviceList});await page.goto(origin);
  await expect(page.locator('#devices-status')).toHaveText('Сервер вернул некорректный список. Устройства скрыты.');
  await expect(page.locator('#device-rows')).toBeEmpty();await expect(page.locator('#devices-region')).toBeHidden();
  await expect(page.locator('#inventory-view')).toBeHidden();expect(await page.evaluate(()=>window.injected)).toBeUndefined();
 }
});

test('device inventory clears withdrawn or expired sessions and keeps manual lookup after unavailable discovery',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#device-rows tr')).toHaveCount(1);
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action==='configuration.devices.list')await route.fulfill({status:503,json:{}});else await route.continue();
 });
 await page.locator('#refresh-devices').click();await expect(page.locator('#device-rows')).toBeEmpty();
 await expect(page.locator('#devices-status')).toContainText('Список устройств недоступен');
 await page.locator('#inventory-device').fill('device-a');await page.locator('#inventory-device').press('Enter');await expect(page.locator('#inventory-view')).toBeVisible();
 await expect(page.locator('#devices-disclosure')).not.toHaveAttribute('open','');
 await page.locator('#devices-disclosure > summary').click();
 await page.unroute('**/control/action');
 await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#refresh-devices').click();
 await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#device-rows')).toBeEmpty();await expect(page.locator('#inventory-device')).toHaveValue('');
 await reset(request);await page.goto(origin);await expect(page.locator('#device-rows tr')).toHaveCount(1);
 await request.post(origin+'/fixture/expire',{data:{}});await page.locator('#refresh-devices').click();await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#device-rows')).toBeEmpty();
 await reset(request,{emptyDevices:true});await page.goto(origin);await expect(page.locator('#devices-status')).toContainText('Доступных устройств нет');await expect(page.locator('#device-rows')).toBeEmpty();
});

test('mobile device search filters the loaded pages and opens the newly matching card',async({page,request})=>{
 await reset(request,{devicePages:true});await page.setViewportSize({width:360,height:800});await page.goto(origin);
 await expect(page.locator('#device-rows tr')).toHaveCount(32);
 await page.getByLabel('Поиск по загруженным ID').fill('VICE-A');
 await expect(page.locator('#devices-status')).toContainText('0 из 32. Можно загрузить ещё.');
 await expect(page.locator('#devices-region')).toBeHidden();
 await page.getByRole('button',{name:'Ещё устройства'}).click();
 await expect(page.locator('#devices-status')).toContainText('1 из 33.');
 await expect(page.locator('#device-rows tr:visible')).toHaveCount(1);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 const open=page.getByRole('button',{name:'Открыть устройство device-a',exact:true});await open.focus();await open.press('Enter');
 await expect(page.locator('#inventory-view')).toBeFocused();await expect(page.locator('#inventory-device')).toHaveValue('device-a');
});

test('phone attention filter distinguishes current degraded and rollback receipts from previous or missing reports',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:360,height:800});
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action!=='configuration.devices.list')return route.continue();
  const item=(device,state,outcome)=>({device,desiredRevision:7,policyRevision:23,report:outcome?
   {state,outcome,receivedAtMs:1800000000000,policyRevision:state==='historical'?22:23,activePolicyRevision:outcome==='rolled_back'?22:23}:{state,activePolicyRevision:0}});
  await route.fulfill({json:{devices:[item('device-a','historical','rolled_back'),item('device-b','reported','degraded'),
   item('device-c','reported','rolled_back'),item('device-d','reported','committed'),item('device-e','awaiting_report')],
   next:'',observedAtMs:1800000000000}});
 });
 await page.goto(origin);await expect(page.locator('#device-rows tr')).toHaveCount(5);
 const filter=page.getByLabel('Показать',{exact:true});await filter.selectOption('attention');
 await expect(page.locator('#device-rows tr:visible')).toHaveCount(2);
 await expect(page.locator('#device-rows tr:visible').first()).toContainText('device-b');
 await expect(page.locator('#device-rows tr:visible').last()).toContainText('device-c');
 await expect(page.locator('#devices-status')).toContainText('2 из 5.');
});

test('session favorites use only the authorized list and clear on loss of access',async({page,request})=>{
 await reset(request);await page.goto(origin);const saved=page.getByRole('button',{name:'Избранное для device-a',exact:true});
 await expect(saved).toBeEnabled();const initial=(await(await request.post(origin+'/fixture/state',{data:{}})).json()).calls;
 await saved.focus();await saved.press('Space');await expect(saved).toHaveAttribute('aria-pressed','true');
 const filter=page.getByLabel('Показать',{exact:true});await filter.selectOption('favorites');
 await expect(page.locator('#device-rows tr:visible')).toHaveCount(1);await saved.press('Space');
 await expect(filter).toBeFocused();await expect(page.locator('#device-rows tr:visible')).toHaveCount(0);
 await filter.selectOption('all');await saved.press('Space');await filter.selectOption('favorites');
 const current=(await(await request.post(origin+'/fixture/state',{data:{}})).json()).calls;expect(current).toEqual(initial);
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
 await page.locator('#refresh-devices').click();await expect(saved).toHaveAttribute('aria-pressed','true');
 await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#refresh-devices').click();
 await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#device-rows')).toBeEmpty();
 await expect(filter).toHaveValue('all');
 await reset(request);await page.goto(origin);await expect(saved).toHaveAttribute('aria-pressed','false');
});

test('late authorized inventory response stays cleared after a concurrent session expiry',async({page,request})=>{
 await page.clock.install();await reset(request,{runtime:'recent'});await page.goto(origin);
 await page.getByRole('button',{name:'Открыть устройство device-a',exact:true}).click();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
 await page.clock.pauseAt(new Date(Date.now()+1000));
 let startRuntime,startList,releaseRuntime,releaseList;
 const runtimeStarted=new Promise(resolve=>{startRuntime=resolve;});
 const listStarted=new Promise(resolve=>{startList=resolve;});
 const runtimeGate=new Promise(resolve=>{releaseRuntime=resolve;});
 const listGate=new Promise(resolve=>{releaseList=resolve;});
 await page.route('**/control/action',async route=>{
  const action=route.request().postDataJSON().action;
  if(action==='configuration.runtime.get'){startRuntime();await runtimeGate;return route.fulfill({status:401,json:{}});}
  if(action==='configuration.devices.list'){const response=await route.fetch();startList();await listGate;return route.fulfill({response});}
  return route.continue();
 });
 try{
  await page.clock.runFor(60000);await runtimeStarted;
  await page.locator('#devices-disclosure > summary').click();await page.locator('#refresh-devices').click();
  await listStarted;releaseRuntime();await expect(page.locator('#workspace')).toBeHidden();
  const received=page.waitForResponse(r=>r.url().endsWith('/control/action')&&r.request().postDataJSON().action==='configuration.devices.list');
  releaseList();await (await received).finished();await expect(page.locator('#login')).toBeEnabled();
  await expect(page.locator('#device-rows')).toBeEmpty();await expect(page.locator('#device-filters')).toBeHidden();
  await expect(page.locator('#devices-status')).toHaveText('');
 }finally{releaseRuntime();releaseList();}
});

test('full inventory prefix search finds a later authorized device without walking the first pages',async({page,request})=>{
 await reset(request,{devicePages:true});await page.setViewportSize({width:360,height:800});
 const lists=[];page.on('request',r=>{if(r.url().endsWith('/control/action')){const op=r.postDataJSON();if(op.action==='configuration.devices.list')lists.push(op.payload);}});
 await page.goto(origin);await expect(page.locator('#device-rows tr')).toHaveCount(32);
 const search=page.locator('#device-search');await search.fill('DEVICE-A');await search.press('Enter');
 await expect(page.locator('#device-rows tr')).toHaveCount(1);await expect(page.locator('#devices-status')).toContainText('В базе выбран префикс «DEVICE-A»');
 expect(lists).toEqual([{after:'',includeReportExpiry:true},{after:'',prefix:'DEVICE-A',includeReportExpiry:true}]);await expect(page.locator('#more-devices')).toBeHidden();
 await search.fill('absent');await page.locator('#search-all-devices').click();
 await expect(page.locator('#devices-status')).toContainText('Доступных устройств с началом ID «absent» нет');
 await expect(search).toBeVisible();await page.locator('#clear-device-prefix').click();await expect(page.locator('#device-rows tr')).toHaveCount(32);
 await expect(search).toBeFocused();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test('device favorites survive unrelated prefix searches and expire when their own scope is empty',async({page,request})=>{
 await reset(request);
 await page.setViewportSize({width:360,height:800});
 await page.goto(origin);
 const favorite=page.getByRole('button',{name:'Избранное для device-a',exact:true});
 const search=page.locator('#device-search');
 const clear=page.locator('#clear-device-prefix');
 const rows=page.locator('#device-rows tr');
 await favorite.click();
 await expect(favorite).toHaveAttribute('aria-pressed','true');
 await search.fill('other');
 await search.press('Enter');
 await expect(page.locator('#devices-status')).toContainText('«other»');
 await expect(rows).toHaveCount(0);
 await clear.click();
 await expect(favorite).toHaveAttribute('aria-pressed','true');
 await page.getByLabel('Показать',{exact:true}).selectOption('favorites');
 await expect(page.locator('#device-rows tr:visible')).toHaveCount(1);
 await page.getByRole('button',{name:'Открыть устройство device-a',exact:true}).click();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
 await page.locator('#devices-disclosure > summary').click();
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();
  if(op.action!=='configuration.devices.list'||op.payload.prefix!=='DEV')return route.continue();
  const response=await route.fetch({postData:{...op,payload:{after:'',prefix:'absent'}}});
  return route.fulfill({response});
 });
 await search.fill('DEV');await search.press('Enter');
 await expect(page.locator('#devices-status')).toContainText('«DEV»');
 await expect(rows).toHaveCount(0);
 await clear.click();
 await page.getByLabel('Показать',{exact:true}).selectOption('all');
 await expect(favorite).toHaveAttribute('aria-pressed','false');
 await expect(page.locator('#device-rows tr:visible')).toHaveCount(1);
});

test('remote device search rejects an answer belonging to a different prefix',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#device-rows tr')).toHaveCount(1);
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();if(op.action!=='configuration.devices.list')return route.continue();
  const response=await route.fetch({postData:{...op,payload:{after:''}}});return route.fulfill({response});
 });
 await page.locator('#device-search').fill('other');await page.locator('#search-all-devices').click();
 await expect(page.locator('#devices-status')).toContainText('Сервер вернул некорректный список');
 await expect(page.locator('#device-rows')).toBeEmpty();await expect(page.locator('#inventory-view')).toBeHidden();
});

test('reported rollback expires from the visible list and attention filter without another request',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:360,height:800});
 await page.clock.install({time:new Date('2027-01-01T12:00:00Z')});await page.clock.pauseAt(new Date('2027-01-01T12:01:00Z'));
 let calls=0;
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();if(op.action!=='configuration.devices.list')return route.continue();
  calls++;expect(op.payload.includeReportExpiry).toBe(true);
  const observedAtMs=1800000000000;
  const row=(device,duration)=>({device,policyRevision:3,desiredRevision:2,reportValidUntilMs:observedAtMs+duration,
   report:{state:'reported',outcome:'rolled_back',policyRevision:3,activePolicyRevision:2,receivedAtMs:observedAtMs-900}});
  return route.fulfill({json:{devices:[row('device-a',10000),row('device-b',20000)],next:'',observedAtMs,reportExpiry:true}});
 });
 await page.goto(origin);const rows=page.locator('#device-rows tr'),filter=page.getByLabel('Показать',{exact:true});
 await expect(rows).toHaveCount(2);await filter.selectOption('attention');await expect(rows.first()).toBeVisible();
 await page.clock.fastForward(9999);await expect(rows.first()).toContainText('Отчёт о выданной политике');
 await page.clock.fastForward(1);await expect(rows.first()).toBeHidden();await expect(rows.last()).toBeVisible();
 await filter.selectOption('all');await expect(rows.first()).toContainText('Архивный отчёт · Откат');
 await page.clock.setSystemTime(new Date('2027-01-02T00:00:00Z'));await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
 await expect(rows.last()).toContainText('Архивный отчёт');expect(calls).toBe(1);
});

test('legacy device catalog keeps an explicitly dated snapshot and never retries denied access',async({page,request})=>{
 await reset(request);
 let deny=false;const payloads=[];
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();if(op.action!=='configuration.devices.list')return route.continue();
  payloads.push(op.payload);
  if(deny||op.payload.includeReportExpiry)return route.fulfill({status:deny?403:400,json:{}});
  return route.fulfill({json:{next:'',observedAtMs:1800000000000,devices:[{device:'device-a',desiredRevision:1,policyRevision:2,
   report:{state:'reported',policyRevision:2,activePolicyRevision:2,outcome:'committed',receivedAtMs:1799999999999}}]}});
 });
 await page.goto(origin);await expect(page.locator('#device-rows tr')).toContainText('при загрузке');
 expect(payloads).toEqual([{after:'',includeReportExpiry:true},{after:''}]);
 deny=true;await page.locator('#refresh-devices').click();await expect(page.locator('#device-rows')).toBeEmpty();
 await expect.poll(()=>payloads.length).toBe(3);expect(payloads.at(-1)).toEqual({after:'',includeReportExpiry:true});
});
