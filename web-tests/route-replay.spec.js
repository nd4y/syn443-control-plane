import {readFileSync} from 'node:fs';
import {test,expect} from '@playwright/test';

const origin='http://127.0.0.1:17851';
const sample=JSON.parse(readFileSync(new URL('../contracts/v1/decision-vectors.json',import.meta.url),'utf8')).cases[0].input;

async function openReplay(page,request){
 await request.post(origin+'/fixture/reset',{data:{}});
 await page.setViewportSize({width:393,height:852});
 await page.goto(origin+'/#draft-title');
 await page.locator('#route-replay summary').click();
 await expect(page.locator('#route-replay-run')).toBeEnabled();
}

test('mobile replay compares both policies on reference and uploaded observations without publishing',async({page,request})=>{
 await openReplay(page,request);
 const run=page.locator('#route-replay-run'),out=page.locator('#route-replay-result'),plan=page.locator('#plan');
 const initial=await plan.inputValue(),requests=[];
 await page.route('**/control/route-replay',async route=>{
  const body=route.request().postDataJSON();requests.push(body);
  if(body.source==='reference')await route.fulfill({json:{frames:30,samePath:20,changedPath:0,lostPath:0,gainedPath:0,neither:10}});
  else await route.fulfill({json:{frames:1,samePath:0,changedPath:0,lostPath:1,gainedPath:0,neither:0}});
 });
 await run.click();await expect(out).toContainText('Проверено кадров - 30');
 await page.locator('#route-replay-ttl').fill('1');
 await expect(out).toBeEmpty();
 await page.locator('#route-replay-file').setInputFiles({name:'fixture.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify([sample]))});
 await run.click();
 await expect(out).toContainText('Проверено кадров - 1');
 await expect(out).toContainText('Потерян доступный маршрут - 1');
 expect(requests).toEqual([{source:'reference',trialTtlMs:60000},{source:'trace',trialTtlMs:1,frames:[sample]}]);
 expect(await plan.inputValue()).toBe(initial);
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);expect(state.calls).not.toContain('configuration.publish');
});

test('malformed traces and a late comparison cannot replace a changed replay',async({page,request})=>{
 await openReplay(page,request);
 const run=page.locator('#route-replay-run'),result=page.locator('#route-replay-result');
 const file=page.locator('#route-replay-file');
 await file.setInputFiles({name:'bad.json',mimeType:'application/json',buffer:Buffer.from('{}')});
 await run.click();await expect(result).toBeEmpty();await expect(run).toBeEnabled();
 await file.setInputFiles([]);
 let release,arrived;
 const gate=new Promise(r=>release=r),received=new Promise(r=>arrived=r);
 await page.route('**/control/route-replay',async route=>{arrived();await gate;await route.fulfill({json:{frames:1,samePath:1,changedPath:0,lostPath:0,gainedPath:0,neither:0}});});
 await run.click();await received;
 await page.locator('#route-replay-ttl').fill('31');
 release();await expect(run).toBeEnabled();await expect(result).toBeEmpty();
});

