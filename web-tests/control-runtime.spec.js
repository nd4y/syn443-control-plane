import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const state=async request=>(await request.post(origin+'/fixture/state',{data:{}})).json();
async function open(page,request,options={}){
 await request.post(origin+'/fixture/reset',{data:options});await page.goto(origin);await page.reload();
 await expect(page.locator('#device-rows tr')).toHaveCount(1);
 await page.getByRole('button',{name:'Открыть устройство device-a',exact:true}).click();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
}
test('runtime observation is separately attributed and never invents an activation or mutation',async({page,request})=>{
 await open(page,request,{runtime:'recent'});
 await expect(page.locator('#inventory-runtime')).toHaveText('Сообщено: VPN включён');
 await expect(page.locator('#inventory-runtime-detail')).toContainText('По данным клиента · Wi-Fi · сборка 74 · политика 23');
 await expect(page.locator('#inventory-runtime-time')).toContainText('Получен сервером:');
 await expect(page.locator('#inventory-report')).toContainText('Откат');
 const observed=await state(request);
 expect(observed.calls.filter(x=>x==='configuration.runtime.get')).toHaveLength(1);
 expect(observed.calls).not.toContain('configuration.publish');expect(observed.operations).toBe(0);
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});
test('adaptive algorithm follows the current issued policy and ages with the active device report',async({page,request})=>{
 const algorithm='m4-graph-tcp-v1';
 await page.setViewportSize({width:360,height:800});
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();
  if(op.action!=='configuration.inventory.get'||op.payload.id!=='device-a')return route.fallback();
  const response=await route.fetch(),view=await response.json();
  view.issuedSettings.algorithmRevision=algorithm;
  return route.fulfill({response,json:view});
 });
 const issued=page.locator('#inventory-issued-algorithm'),observed=page.locator('#inventory-runtime-detail');
 await open(page,request,{runtime:'recent'});
 await expect(issued).toHaveText('Алгоритм '+algorithm);
 await expect(observed).toContainText('алгоритм политики '+algorithm);
 await open(page,request,{runtime:'expires'});
 await expect(issued).toHaveText('Алгоритм '+algorithm);
 await expect(page.locator('#inventory-runtime')).toHaveText('Отчёт устарел',{timeout:8000});
 await expect(observed).not.toContainText(algorithm);
 await expect(issued).toHaveText('Алгоритм '+algorithm);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});

test('issued algorithm is never attributed to a stopped engine or a different observed revision',async({page,request})=>{
 const detail=page.locator('#inventory-runtime-detail');
 await open(page,request,{runtime:'recent',runtimeEngine:'starting_stopped'});
 await expect(detail).toContainText('движок остановлен');
 await expect(detail).not.toContainText('алгоритм политики');
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action!=='configuration.runtime.get')return route.fallback();
  const response=await route.fetch(),view=await response.json();
  view.report.policyRevision=22;
  return route.fulfill({response,json:view});
 });
 await open(page,request,{runtime:'recent'});
 await expect(detail).toContainText('политика 22');
 await expect(detail).not.toContainText('алгоритм политики');
 await expect(page.locator('#inventory-issued-algorithm')).toHaveText('Алгоритм m4-confirmed-v1');
});

test('runtime observation expires locally without polling or refreshing a historical receipt',async({page,request})=>{
 await open(page,request,{runtime:'expires'});
 await expect(page.locator('#inventory-runtime')).toHaveText('Сообщено: VPN включён');
 const stamp=await page.locator('#inventory-runtime-time').getAttribute('datetime');
 await expect(page.locator('#inventory-runtime')).toHaveText('Отчёт устарел',{timeout:5000});
 await expect(page.locator('#inventory-runtime-detail')).toContainText('Последнее сообщение: VPN включён');
 await expect(page.locator('#inventory-runtime-time')).toHaveAttribute('datetime',stamp);
 expect((await state(request)).calls.filter(x=>x==='configuration.runtime.get')).toHaveLength(1);
 await open(page,request,{runtime:'stale'});await expect(page.locator('#inventory-runtime')).toHaveText('Отчёт устарел');
});

test('mobile runtime shows the reported engine independently of the phase and never supplies a missing cause',async({page,request})=>{
 await page.setViewportSize({width:320,height:900});
 const summary=page.locator('#inventory-runtime'),detail=page.locator('#inventory-runtime-detail');
 for(const [runtimeEngine,phase,engine] of [
  ['blocked_unknown','VPN заблокирован','состояние движка неизвестно'],
  ['starting_stopped','Запуск VPN','движок остановлен'],
  ['recovering_active','Восстановление VPN','движок активен'],
 ]){
  await open(page,request,{runtime:'recent',runtimeEngine});
  await expect(summary).toHaveText('Сообщено: '+phase);
  const algorithm=runtimeEngine==='recovering_active'?' · алгоритм политики m4-confirmed-v1':'';
  await expect(detail).toHaveText('По данным клиента · Wi-Fi · сборка 74 · политика 23 · '+engine+algorithm);
  await expect(page.locator('#inventory-report')).toContainText('Откат');
 }
 await open(page,request,{runtime:'stale',runtimeEngine:'recovering_active'});
 await expect(summary).toHaveText('Отчёт устарел');
 await expect(detail).toHaveText('Последнее сообщение: Восстановление VPN · Wi-Fi · сборка 74 · политика 23 · движок активен');
 await expect(page.locator('#inventory-runtime-time')).toHaveAttribute('datetime',/^20/);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 expect((await state(request)).operations).toBe(0);
});
test('runtime observation refuses substituted future extra contradictory and stale sample metadata',async({page,request})=>{
 for(const runtime of ['foreign','extra','future','old-sample','false-online','false-fresh']){
  await open(page,request,{runtime});
  await expect(page.locator('#inventory-view')).toBeVisible();await expect(page.locator('#inventory-runtime')).toHaveText('Состояние недоступно');
  await expect(page.locator('#inventory-runtime-detail')).toContainText('некорректный отчёт');await expect(page.locator('#inventory-runtime-time')).toBeHidden();
  await expect(page.locator('#inventory-view')).not.toContainText('synthetic-untrusted');
 }
});
test('runtime observation denial and session expiry erase cached state and private proposals',async({page,request})=>{
 for(const action of ['revoke','expire']){
  await open(page,request,{runtime:'recent'});
  await page.getByRole('link',{name:'Открыть публикацию',exact:true}).click();await page.locator('#layer-from-device').click();
  await expect(page.locator('#layer-proposal')).not.toHaveValue('');
  await page.getByRole('link',{name:'Устройства',exact:true}).click();
  await request.post(origin+'/fixture/'+action,{data:{}});await page.locator('#refresh-runtime').click();
  await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#layer-proposal')).toHaveValue('');
  await expect(page.locator('#inventory-runtime')).toHaveText('');await expect(page.locator('#inventory-runtime-time')).toBeHidden();
 }
});
test('unknown or unavailable runtime keeps its configuration card and narrow keyboard actions usable',async({page,request})=>{
 await page.setViewportSize({width:320,height:900});await open(page,request);
 await expect(page.locator('#inventory-runtime')).toHaveText('Нет отчёта');await expect(page.locator('#inventory-runtime-time')).toBeHidden();
 await open(page,request,{runtimeUnavailable:true});await expect(page.locator('#inventory-runtime')).toHaveText('Состояние недоступно');
 await expect(page.locator('#inventory-view')).toBeVisible();await expect(page.locator('#inventory-state')).not.toHaveText('');
 await page.locator('#inventory-view').press('Tab');await expect(page.getByRole('link',{name:'Открыть публикацию',exact:true})).toBeFocused();
 await page.getByRole('link',{name:'Открыть публикацию',exact:true}).press('Tab');await expect(page.locator('#refresh-runtime')).toBeFocused();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 expect((await state(request)).operations).toBe(0);
});
