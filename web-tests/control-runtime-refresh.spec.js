import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const state=async request=>(await request.post(origin+'/fixture/state',{data:{}})).json();
const reads=async request=>(await state(request)).calls.filter(x=>x==='configuration.runtime.get').length;
async function open(page,request,options={runtime:'recent'}){
 await page.clock.install();
 await request.post(origin+'/fixture/reset',{data:options});await page.goto(origin);await page.reload();
 await expect(page.locator('#device-rows tr')).toHaveCount(1);
 await page.getByRole('button',{name:'Открыть устройство device-a',exact:true}).click();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
 await page.clock.pauseAt(new Date(Date.now()+1000));
}
async function advance(page,request,milliseconds){
 await request.post(origin+'/fixture/runtime-clock',{data:{advanceMs:milliseconds}});
 await page.clock.runFor(milliseconds);
}
async function visibility(page,hidden){
 await page.evaluate(value=>{Object.defineProperty(document,'hidden',{configurable:true,value});document.dispatchEvent(new Event('visibilitychange'));},hidden);
}
test('open runtime card follows real new observations but polling cannot renew an old receipt',async({page,request})=>{
 await open(page,request);
 const stamp=await page.locator('#inventory-runtime-time').getAttribute('datetime');
 for(let i=0;i<3;i++){
  await advance(page,request,60000);await expect.poll(()=>reads(request)).toBe(i+2);
  await expect(page.locator('#inventory-runtime-time')).toHaveAttribute('datetime',stamp);
 }
 await expect(page.locator('#inventory-runtime')).toHaveText('Отчёт устарел');
 await request.post(origin+'/fixture/runtime-update',{data:{device:'device-a',phase:'recovering'}});
 await advance(page,request,60000);
 await expect(page.locator('#inventory-runtime')).toHaveText('Сообщено: Восстановление VPN');
 await expect(page.locator('#inventory-runtime-time')).not.toHaveAttribute('datetime',stamp);
 await expect(page.locator('#inventory-report')).toContainText('Откат');
 expect((await state(request)).operations).toBe(0);
});
test('runtime refresh pauses outside the visible device section and erases expired authority',async({page,request})=>{
 let sent=0;page.on('request',r=>{if(r.url().endsWith('/control/action')&&r.postDataJSON()?.action==='configuration.runtime.get')sent++;});
 await open(page,request);expect(sent).toBe(1);
 await visibility(page,true);await advance(page,request,180000);expect(sent).toBe(1);
 await visibility(page,false);await page.clock.runFor(5);await expect.poll(()=>sent).toBe(2);
 await expect(page.locator('#inventory-runtime')).toHaveText('Отчёт устарел');
 await page.getByRole('link',{name:'Телеметрия',exact:true}).click();await advance(page,request,120000);expect(sent).toBe(2);
 await page.getByRole('link',{name:'Устройства',exact:true}).click();await page.clock.runFor(5);await expect.poll(()=>sent).toBe(3);
 await request.post(origin+'/fixture/expire',{data:{}});await advance(page,request,60000);
 await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#inventory-runtime')).toHaveText('');
 const after=sent;await advance(page,request,300000);expect(sent).toBe(after);
});
test('pending automatic runtime read stays single and cannot paint a changed device',async({page,request})=>{
 let block=false,held=0,released=false,release;
 const gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON();
  if(block&&body.action==='configuration.runtime.get'&&body.payload.id==='device-a'){
   held++;await gate;
   const now=Date.now();
   try{await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({device:'device-a',observedAtMs:now,state:'recent',report:{version:1,sequence:1,build:123,phase:'recovering',policyRevision:23,engineKnown:true,engineActive:true,network:'wifi',sampledAtMs:now,receivedAtMs:now}})});}
   catch{/* The old fetch was deliberately cancelled. */}finally{released=true;}
  }else await route.continue();
 });
 try{
  await open(page,request);block=true;await advance(page,request,60000);await expect.poll(()=>held).toBe(1);
  await expect(page.locator('#refresh-runtime')).toBeDisabled();await advance(page,request,5000);expect(held).toBe(1);
  await page.locator('#inventory-device').fill('device-b');await page.getByRole('button',{name:'Открыть карточку',exact:true}).click();
  await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
  release();await expect.poll(()=>released).toBe(true);
  await expect(page.locator('#inventory-device')).toHaveValue('device-b');
  await expect(page.locator('#inventory-runtime')).toHaveText('Сообщено: VPN включён');
  await expect(page.locator('#inventory-runtime-detail')).not.toContainText('123');
 }finally{release();}
});
test('runtime read timeout keeps unrelated controls usable and later refresh recovers',async({page,request})=>{
 let block=false,held=0,release;
 const gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/action',async route=>{
  if(block&&route.request().postDataJSON().action==='configuration.runtime.get'){
   block=false;held++;await gate;try{await route.abort();}catch{/* Expected timeout cancellation. */}
  }else await route.continue();
 });
 try{
  await open(page,request);block=true;await advance(page,request,60000);await expect.poll(()=>held).toBe(1);
  await expect(page.getByRole('button',{name:'Выйти',exact:true})).toBeEnabled();
  await expect(page.locator('#inventory-device')).toBeEnabled();
  await advance(page,request,15001);await expect(page.locator('#inventory-runtime')).toHaveText('Состояние недоступно');
  await expect(page.locator('#inventory-view')).toBeVisible();await expect(page.locator('#refresh-runtime')).toBeEnabled();
  release();await advance(page,request,45000);await expect(page.locator('#inventory-runtime')).toHaveText('Сообщено: VPN включён');
  expect((await state(request)).operations).toBe(0);
 }finally{release();}
});
test('a previously empty runtime card receives a later observation without a manual reload',async({page,request})=>{
 await open(page,request,{});await expect(page.locator('#inventory-runtime')).toHaveText('Нет отчёта');
 await request.post(origin+'/fixture/runtime-update',{data:{device:'device-a'}});await advance(page,request,60000);
 await expect(page.locator('#inventory-runtime')).toHaveText('Сообщено: VPN включён');
 await expect(page.locator('#inventory-runtime-time')).toBeVisible();expect(await reads(request)).toBe(2);
 expect((await state(request)).operations).toBe(0);
});
