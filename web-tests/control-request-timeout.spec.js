import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const plan={schemaVersion:1,graph:{profiles:{proxy:{sourceId:'source-a',profileId:'profile-a'}},chains:{},balancers:{},final:'proxy'},network:{schemaVersion:1,requiredNetworks:['tcp'],dnsFinal:'system',dnsStrategy:'prefer_ipv4'},activation:{timeoutSeconds:30,checks:[{id:'internet',type:'https_204',target:'https://health.example.invalid/generate_204',required:true}]}};
const state=async request=>(await request.post(origin+'/fixture/state',{data:{}})).json();

test('stalled initial session never blocks sign-in indefinitely or paints a late identity',async({page,request})=>{
 let started=0,release,released=false;
 const gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/session',async route=>{
  started++;await gate;
  try{await route.fulfill({json:{authenticated:true}});}catch{/* The initial session request was cancelled. */}finally{released=true;}
 });
 try{
  await page.clock.install();await request.post(origin+'/fixture/reset',{data:{}});await page.goto(origin,{waitUntil:'commit'});
  await expect.poll(()=>started).toBe(1);await expect(page.locator('#login')).toBeDisabled();await expect(page.locator('#workspace')).toBeHidden();
  await page.clock.pauseAt(new Date(Date.now()+1000));await page.clock.runFor(15001);
  await expect(page.locator('#login')).toBeEnabled();await expect(page.locator('#status')).toContainText('Сервер не ответил вовремя');
  release();await expect.poll(()=>released).toBe(true);await page.clock.runFor(60000);
  expect(started).toBe(1);await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#signin')).toBeVisible();
 }finally{release();}
});

test('stalled sign-in releases controls at its deadline and only an explicit retry navigates',async({page,request})=>{
 let attempts=0,release,released=false;
 const gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/login',async route=>{
  attempts++;
  if(attempts===1){await gate;try{await route.fulfill({json:{url:origin+'/fixture/id/protocol/openid-connect/auth?late=1'}});}catch{/* Cancelled first attempt. */}finally{released=true;}}
  else await route.fulfill({json:{url:origin+'/fixture/id/protocol/openid-connect/auth?retry=1'}});
 });
 try{
  await page.clock.install();await request.post(origin+'/fixture/reset',{data:{}});await request.post(origin+'/fixture/expire',{data:{}});
  await page.goto(origin);await expect(page.locator('#login')).toBeEnabled();
  await page.clock.pauseAt(new Date(Date.now()+1000));await page.locator('#login').click();await expect.poll(()=>attempts).toBe(1);
  await expect(page.locator('#login')).toBeDisabled();await page.clock.runFor(15001);
  await expect(page.locator('#login')).toBeEnabled();await expect(page.locator('#status')).toContainText('Сервер не ответил вовремя');
  await page.clock.runFor(60000);expect(attempts).toBe(1);expect(page.url()).toBe(origin+'/');
  release();await expect.poll(()=>released).toBe(true);expect(page.url()).toBe(origin+'/');
  await page.locator('#login').click();await expect(page.getByRole('heading',{name:'Synthetic identity provider'})).toBeVisible();expect(attempts).toBe(2);
 }finally{release();}
});

test('a committed save with a stalled response keeps its exact pending request for manual retry',async({page,request})=>{
 let release,committed=0,released=false;const bodies=[];
 const gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action!=='configuration.draft.put'){await route.continue();return;}
  bodies.push(route.request().postData());
  if(bodies.length===1){const response=await route.fetch();expect(response.status()).toBe(200);committed++;await gate;try{await route.fulfill({response});}catch{/* Client deadline already cancelled this response. */}finally{released=true;}}
  else await route.continue();
 });
 try{
  await page.clock.install();await request.post(origin+'/fixture/reset',{data:{}});await page.goto(origin+'/#draft-title');
  await expect(page.locator('#new-draft')).toBeEnabled();await page.locator('#new-draft').click();await page.locator('#target-id').fill('device-a');await page.locator('#plan').fill(JSON.stringify(plan));
  await page.clock.pauseAt(new Date(Date.now()+1000));await page.locator('#save-draft').click();await expect.poll(()=>committed).toBe(1);
  expect((await state(request)).operations).toBe(1);await page.clock.runFor(15001);
  await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#retry-save')).toBeEnabled();await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan));
  await page.clock.runFor(60000);expect(bodies).toHaveLength(1);
  release();await expect.poll(()=>released).toBe(true);await page.locator('#retry-save').click();
  await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#draft-version')).toHaveText('Версия черновика: 1');
  expect(bodies).toHaveLength(2);expect(bodies[1]).toBe(bodies[0]);const result=await state(request);expect(result.operations).toBe(1);expect(result.drafts[0].revision).toBe(1);
 }finally{release();}
});
