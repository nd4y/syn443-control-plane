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
 for(const invalidDeviceList of ['duplicate','extra','cursor','oversize','revision','report','order']){
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
