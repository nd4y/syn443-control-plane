import {test,expect} from '@playwright/test';
import fs from 'node:fs/promises';
import crypto from 'node:crypto';
const origin='http://127.0.0.1:17851',chatOrigin='http://127.0.0.1:17850';
const state=async request=>(await request.post(origin+'/fixture/state',{data:{}})).json();
test.beforeEach(async({request})=>{
 for(const host of [origin,chatOrigin])expect((await request.post(host+'/fixture/reset',{data:{}})).status()).toBe(200);
});
async function open(page){
 await page.goto(origin+'/#support-title');
 await expect(page.locator('#support-title')).toBeVisible();
 await page.locator('#support-inbox').getByRole('button',{name:/Пользователь/}).click();
 await expect(page.locator('#support-text')).toBeEnabled();
 await expect(page.locator('#support-send')).toBeDisabled();
}

test('PatternFly console chat sends hostile text safely without leaving device administration',async({page})=>{
 await open(page);
 await page.getByRole('link',{name:'Устройства',exact:true}).click();
 await page.getByRole('link',{name:'Чат поддержки',exact:true}).click();
 await expect(page.locator('#support-title')).toBeFocused();
 const text='<img src=x onerror="window.executed=true">';
 await page.locator('#support-text').fill(text);await page.locator('#support-send').click();
 await expect(page.locator('#support-messages')).toContainText(text);
 await expect(page.locator('#support-messages img')).toHaveCount(0);
 expect(await page.evaluate(()=>window.executed)).toBeUndefined();
 await expect(page.locator('#support-send')).toBeDisabled();
 await page.getByRole('link',{name:'Устройства',exact:true}).click();
 await expect(page.locator('#inventory-title')).toBeVisible();
 await page.getByRole('link',{name:'Чат поддержки',exact:true}).click();
 await expect(page.locator('#support-messages')).toContainText(text);
});

test('PatternFly console chat transfers and verifies a full 25 MiB file',async({page})=>{
 await open(page);const bytes=Buffer.alloc(25*1024*1024,37);
 await page.locator('#support-file').setInputFiles({name:'synthetic-console.bin',mimeType:'application/octet-stream',buffer:bytes});
 await page.locator('#support-send').click();
 const download=page.locator('#support-messages').getByRole('button',{name:/Скачать: synthetic-console.bin/});
 await expect(download).toBeVisible({timeout:90000});await download.click();
 const save=page.getByRole('link',{name:'Сохранить файл: synthetic-console.bin',exact:true});
 await expect(save).toBeVisible({timeout:90000});const event=page.waitForEvent('download');await save.click();
 const result=await event,received=await fs.readFile(await result.path());
 expect(received.length).toBe(bytes.length);
 expect(crypto.createHash('sha256').update(received).digest('hex')).toBe(crypto.createHash('sha256').update(bytes).digest('hex'));
 await page.locator('#logout').click();await expect(save).toHaveCount(0);
});

test('PatternFly console chat retries a lost acknowledgment without duplicate delivery',async({page,request})=>{
 await request.post(chatOrigin+'/fixture/reset',{data:{failSend:true}});
 await open(page);await page.locator('#support-text').fill('synthetic immutable console retry');await page.locator('#support-send').click();
 await expect(page.locator('#support-status')).toContainText('повторить');
 await page.locator('#support-inbox').getByRole('button',{name:/Пользователь/}).click();
 await expect(page.locator('#support-status')).toContainText('Сначала отправьте');
 await page.locator('#support-send').click();
 await expect(page.locator('#support-messages li')).toHaveCount(1);
 const receipt=await (await request.post(chatOrigin+'/fixture/state',{data:{}})).json();expect(receipt.messages).toBe(1);
});

test('chat authority withdrawal erases its thread and preserves an unrelated console draft',async({page,request})=>{
 await page.goto(origin+'/#draft-title');await expect(page.locator('#draft-id')).toBeEnabled();await page.locator('#draft-id').fill('synthetic-unsaved-chat-draft');
 await page.getByRole('link',{name:'Чат поддержки',exact:true}).click();
 await page.locator('#support-inbox').getByRole('button',{name:/Пользователь/}).click();
 await page.locator('#support-text').fill('synthetic retained SQL history');await page.locator('#support-send').click();
 await expect(page.locator('#support-messages li')).toHaveCount(1);
 await request.post(origin+'/fixture/chat-revoke',{data:{}});await page.locator('#support-older').click();
 await expect(page.locator('#support-status')).toContainText('не разрешён');
 await expect(page.locator('#support-messages li')).toHaveCount(0);await expect(page.locator('#support-text')).toHaveValue('');
 await page.getByRole('link',{name:'Черновики',exact:true}).click();
 await expect(page.locator('#draft-id')).toHaveValue('synthetic-unsaved-chat-draft');
 await expect(page.locator('#logout')).toBeVisible();
 expect((await (await request.post(chatOrigin+'/fixture/state',{data:{}})).json()).messages).toBe(1);
});

test('console logout cancels a late chat response and never paints the previous session',async({page})=>{
 let release,arrived=0,released=false;const gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/chat/messages',async route=>{
  arrived++;await gate;
  try{await route.fulfill({json:{messages:[{id:'b'.repeat(32),sequence:1,senderRole:'user',text:'synthetic late private history',attachments:[],createdAt:1800000000}],peerRead:0}});}
  catch{/* The owned request was cancelled when its session ended. */}finally{released=true;}
 });
 try{
  await page.goto(origin+'/#support-title');await page.locator('#support-inbox').getByRole('button',{name:/Пользователь/}).click();
  await expect.poll(()=>arrived).toBe(1);await page.locator('#logout').click();
  await expect(page.locator('#workspace')).toBeHidden();release();await expect.poll(()=>released).toBe(true);
  await expect(page.locator('#support-messages li')).toHaveCount(0);await expect(page.locator('#support-text')).toHaveValue('');
  await expect(page.locator('#support-text')).toBeDisabled();await expect(page.locator('#signin')).toBeVisible();
 }finally{release();}
});

test('console chat backs off failures and hidden navigation cannot bypass its admission',async({page,request})=>{
 await request.post(origin+'/fixture/reset',{data:{chatUnavailable:true}});await page.clock.install();await page.goto(origin+'/#support-title');
 await expect(page.locator('#support-status')).toContainText('повторить');
 const before=(await state(request)).chatCalls.length;expect(before).toBe(1);
 await page.clock.pauseAt(new Date(Date.now()+1000));await page.clock.runFor(50000);
 expect((await state(request)).chatCalls.length).toBe(before);
 await page.locator('#support-retry').click();await expect.poll(async()=>(await state(request)).chatCalls.length).toBe(before+1);
 await expect(page.locator('#support-retry')).toBeDisabled();
 await page.getByRole('link',{name:'Устройства',exact:true}).click();await page.clock.runFor(180000);
 expect((await state(request)).chatCalls.length).toBe(before+1);
 await request.post(origin+'/fixture/chat-available',{data:{}});await page.getByRole('link',{name:'Чат поддержки',exact:true}).click();
 await expect(page.locator('#support-inbox').getByRole('button',{name:/Пользователь/})).toBeVisible();
});

test('console chat has a narrow empty state and rejects oversize attachments locally',async({page,request})=>{
 await page.setViewportSize({width:390,height:844});await request.post(origin+'/fixture/reset',{data:{chatEmpty:true}});await page.goto(origin+'/#support-title');
 await expect(page.locator('#support-empty')).toHaveText('Диалогов пока нет.');await expect(page.locator('#support-empty')).toBeVisible();
 await expect(page.locator('#support-send')).toBeDisabled();
 await request.post(origin+'/fixture/reset',{data:{}});await page.reload();
 await page.locator('#support-inbox').getByRole('button',{name:/Пользователь/}).click();await expect(page.locator('#support-text')).toBeEnabled();
 await page.locator('#support-file').setInputFiles({name:'synthetic-too-large.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc(25*1024*1024+1)});
 await page.locator('#support-send').click();await expect(page.locator('#support-status')).toContainText('повторить');
 expect((await (await request.post(chatOrigin+'/fixture/state',{data:{}})).json()).uploads).toBe(0);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
});
