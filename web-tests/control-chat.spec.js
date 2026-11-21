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

for (const surface of ['standalone', 'console']) {
 test(`explicit send preserves composition and exact Unicode on ${surface}`, async ({page,request}) => {
  const el=name=>page.locator('#'+(surface==='console'?'support-':'')+name);
  const attempts=[];
  page.on('request',req=>{if(new URL(req.url()).pathname==='/chat/send')attempts.push(req.postDataJSON().text);});
  await page.goto(surface==='console'?origin+'/#support-title':chatOrigin+'/');
  await el('inbox').getByRole('button',{name:/Пользователь/}).click();
  const draft=el('text'),send=el('send');
  await draft.fill('編');
  await draft.dispatchEvent('compositionstart',{data:'編'});
  await expect(send).toBeDisabled();
  await draft.dispatchEvent('keydown',{key:'Enter',isComposing:true});
  await el('compose').evaluate(form=>form.requestSubmit());
  await expect(send).toBeDisabled();
  await send.evaluate(button=>button.click());
  await expect(draft).toHaveValue('編');
  await draft.dispatchEvent('compositionend',{data:'編'});
  await expect(send).toBeEnabled();
  await el('compose').evaluate(form=>form.requestSubmit());
  await draft.evaluate(input=>{input.value=String.fromCharCode(0xd800);input.dispatchEvent(new Event('input'));});
  await send.click();
  await expect(el('status')).toContainText('недопустимый символ');
  expect(await draft.evaluate(input=>input.value.charCodeAt(0))).toBe(0xd800);
  expect(attempts).toEqual([]);
  const finalText='編\n🛰️ \uFFFD';
  await draft.fill(finalText);
  await send.focus();
  await page.keyboard.press('Enter');
  await expect(el('messages').locator('li')).toHaveCount(1);
  await expect(draft).toHaveValue('');
  expect(attempts).toEqual([finalText]);
  const fixture=await (await request.post(chatOrigin+'/fixture/state',{data:{}})).json();
  expect(fixture.messages).toBe(1);
 });
 test(`mismatched send receipts retain the exact draft and files on ${surface}`, async ({page,request}) => {
  const el=name=>page.locator('#'+(surface==='console'?'support-':'')+name);
  const attempts=[];
  await page.route('**/chat/send',async route=>{
   attempts.push(route.request().postDataJSON());
   const response=await route.fetch();
   expect(response.status()).toBe(200);
   const message=await response.json();
   switch(attempts.length) {
    case 1: message.conversation='foreign';break;
    case 2: message.clientId='unrelated';break;
    case 3: message.attachments[0].sha256='0'.repeat(64);break;
    case 4: message.attachments[1]=message.attachments[0];break;
    case 5: message.sequence=0;break;
    default: message.attachments.reverse();
   }
   await route.fulfill({json:message});
  });
  await page.goto(surface==='console'?origin+'/#support-title':chatOrigin+'/');
  await el('inbox').getByRole('button',{name:/Пользователь/}).click();
  await el('text').fill('synthetic receipt retry');
  await el('file').setInputFiles(['one','two'].map(name=>({name:name+'.txt',mimeType:'text/plain',buffer:Buffer.from(name)})));
  for(let i=0;i<5;i++) {
   await el('send').click();
   await expect(el('send')).toBeEnabled();
   await expect(el('status')).toContainText('повторить');
   await expect(el('text')).toHaveValue('synthetic receipt retry');
   await expect(el('text')).toBeDisabled();
   expect(await el('file').evaluate(input=>input.files.length)).toBe(2);
  }
  await el('send').click();
  await expect(el('text')).toHaveValue('');
  await expect(el('messages').locator('li')).toHaveCount(1);
  expect(attempts).toHaveLength(6);
  for(const attempt of attempts)expect(attempt).toEqual(attempts[0]);
  const fixture=await (await request.post(chatOrigin+'/fixture/state',{data:{}})).json();
  expect(fixture.messages).toBe(1);
  expect(fixture.uploads).toBe(2);
 });
 test(`long inbox and message history remain navigable on ${surface}`, async ({page}) => {
  const prefix=surface==='console'?'support-':'';
  const el=name=>page.locator('#'+prefix+name);
  const conversations=Array.from({length:212},(_,i)=>({
   id:i.toString(16).padStart(32,'0'),owner:'owner-'+String(i).padStart(4,'0'),
   updatedAt:2_000_000_000-Math.floor(i/3),lastSeq:241,readSeq:0
  }));
  const message=sequence=>({id:String(sequence),sequence,senderRole:'user',text:'Message #'+sequence+'.',attachments:[],createdAt:1700000000+sequence});
  const reads=[];
  let total=241;
  await page.clock.install();
  await page.route('**/chat/inbox',async route=>{
   const {before,beforeId}=route.request().postDataJSON();
   const start=before?conversations.findIndex(row=>row.id===beforeId&&row.updatedAt===before)+1:0;
   if(before)expect(start).toBeGreaterThan(0);
   await route.fulfill({json:conversations.slice(start,start+50)});
  });
  await page.route('**/chat/messages',async route=>{
   const {conversation,before,after}=route.request().postDataJSON();
   expect(conversation).toBe(conversations[211].id);
   const rows=Array.from({length:total},(_,i)=>message(i+1));
   const results=after?rows.filter(row=>row.sequence>after).slice(0,20):
    rows.filter(row=>!before||row.sequence<before).slice(-20).reverse();
   await route.fulfill({json:{messages:results,peerRead:0}});
  });
  await page.route('**/chat/read',async route=>{
   reads.push(route.request().postDataJSON().sequence);
   await route.fulfill({json:{}});
  });
  await page.goto(surface==='console'?origin+'/#support-title':chatOrigin+'/');
  for(let i=0;i<4;i++){
   await el('more').click();
   await expect(el('inbox').locator('li').first()).toContainText(conversations[(i+1)*50].owner);
  }
  await expect(el('inbox').locator('li')).toHaveCount(12);
  await expect(el('more')).toBeDisabled();
  await el('inbox').getByRole('button',{name:/owner-0211/}).click();
  const items=el('messages').locator('li');
  await expect(items.last()).toContainText('Message #241.');
  for(let end=221;end>=21;end-=20){
   await el('older').click();
   await expect(items.last()).toContainText('Message #'+end+'.');
   await expect(items).toHaveCount(20);
  }
  await el('older').click();
  await expect(items).toHaveCount(1);await expect(items.first()).toContainText('Message #1.');
  await expect(el('older')).toBeDisabled();
  total=242;
  const poll=page.waitForResponse(r=>r.url().endsWith('/chat/messages')&&r.request().postDataJSON().before===2);
  await page.clock.fastForward(22000);await poll;
  await expect(el('newer')).toBeEnabled();
  await expect(items).toHaveCount(1);
  expect(reads).toEqual([241]);
  await expect(el('inbox').locator('li')).toHaveCount(12);
  await el('newer').click();await expect(items.last()).toContainText('Message #21.');
  await el('latest').click();await expect(items.last()).toContainText('Message #242.');
  await expect.poll(()=>reads.at(-1)).toBe(242);
  await el('inbox-first').click();
  await expect(el('inbox').locator('li').first()).toContainText(conversations[0].owner);
  await expect(el('inbox-first')).toBeHidden();
 });

 test(`switching conversations clears the previous history and file on ${surface}`, async ({page}) => {
  const prefix=surface==='console'?'support-':'';
  const el=name=>page.locator('#'+prefix+name);
  const second={id:'b'.repeat(32),owner:'B'.repeat(43),lastSeq:0,readSeq:0,updatedAt:1700000000};
  await page.route('**/chat/inbox',async route=>{
   const response=await route.fetch();
   await route.fulfill({response,json:[...(await response.json()),second]});
  });
  await page.goto(surface==='console'?origin+'/#support-title':chatOrigin+'/');
  await el('inbox').getByRole('button',{name:/Пользователь A/}).click();
  await el('text').fill('Message for the first fixture account');
  await el('file').setInputFiles({name:'first-thread.txt',mimeType:'text/plain',buffer:Buffer.from('first thread')});
  await el('send').click();
  await el('messages').getByRole('button',{name:/Скачать: first-thread/}).click();
  const link=el('download-ready').getByRole('link');
  await expect(link).toBeVisible();
  const href=await link.getAttribute('href');
  await page.evaluate(()=>{
   const original=URL.revokeObjectURL;
   window.revokedFixtureUrls=[];
   URL.revokeObjectURL=url=>{window.revokedFixtureUrls.push(url);original.call(URL,url);};
  });
  let release;
  const blocked=new Promise(resolve=>{release=resolve;});
  await page.route('**/chat/messages',async route=>{
   if(route.request().postDataJSON().conversation!==second.id){await route.continue();return;}
   await blocked;
   await route.fulfill({status:503,json:{}});
  });
  try {
   await el('inbox').getByRole('button',{name:/Пользователь B/}).click();
   await expect(el('thread-title')).toContainText(second.owner.slice(0,10));
   await expect(el('messages').locator('li')).toHaveCount(0);
   await expect(link).toHaveCount(0);
   expect(await page.evaluate(()=>window.revokedFixtureUrls)).toContain(href);
  } finally { release(); }
  await expect(el('status')).toContainText('повторить');
  await expect(el('messages').locator('li')).toHaveCount(0);
  await expect(link).toHaveCount(0);
 });
}

test('leaving support during final file verification cannot publish a save link',async({page})=>{
 await open(page);
 await page.locator('#support-file').setInputFiles({name:'verification.txt',mimeType:'text/plain',buffer:Buffer.from('synthetic')});
 await page.locator('#support-send').click();
 const download=page.locator('#support-messages').getByRole('button',{name:/Скачать: verification/});
 await expect(download).toBeVisible();
 await page.evaluate(()=>{
  const original=SubtleCrypto.prototype.digest;
  let calls=0;
  SubtleCrypto.prototype.digest=async function(...args){
   const result=await original.apply(this,args);
   if(++calls===2)await new Promise(resolve=>{window.releaseFileDigest=resolve;});
   return result;
  };
 });
 await download.click();
 await page.waitForFunction(()=>typeof window.releaseFileDigest==='function');
 await page.getByRole('link',{name:'Устройства',exact:true}).click();
 await page.evaluate(()=>window.releaseFileDigest());
 await expect(page.locator('#support-file')).toBeEnabled();
 await expect(page.locator('#support-download-ready a')).toHaveCount(0);
 await page.getByRole('link',{name:'Чат поддержки',exact:true}).click();
 await expect(page.locator('#support-text')).toBeEnabled();
 await expect(page.locator('#support-download-ready a')).toHaveCount(0);
});

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

for (const surface of ['standalone','console']) {
 test(`look up an exact incident without opening or acknowledging a thread on ${surface}`, async ({page})=>{
  const el=name=>page.locator('#'+(surface==='console'?'support-':'')+name);
  const ref='SYN-0123456789ab';
  const text='Обращение '+ref+'\n<svg/onload=invalid>';
  const lookups=[];
  let readCalls=0;
  page.on('request',req=>{if(new URL(req.url()).pathname==='/chat/read')readCalls++;});
  await page.route('**/chat/incident/lookup',async route=>{
   const value=route.request().postDataJSON().reference;
   lookups.push(value);
   const reply=value===ref?{reference:ref,state:'found',report:{text,createdAt:1700000000}}:
    {reference:value,state:value.endsWith('1')?'ambiguous':'missing'};
   await route.fulfill({json:reply});
  });
  await page.setViewportSize({width:390,height:844});
  await page.goto(surface==='console'?origin+'/#support-title':chatOrigin+'/');
  await expect(el('inbox').getByRole('button',{name:/Пользователь/})).toBeVisible();
  await el('incident-ref').fill('SYN-0123');
  await expect(el('incident-find')).toBeDisabled();
  await el('incident-ref').fill(ref);
  expect(lookups).toEqual([]);
  await el('incident-ref').press('Enter');
  await expect(el('incident-result')).toContainText(text);
  await expect(el('incident-result').locator('svg')).toHaveCount(0);
  await el('incident-ref').fill('SYN-000000000001');
  await expect(el('incident-result')).toBeHidden();
  await el('incident-find').click();
  await expect(el('incident-result')).toContainText('совпал у нескольких');
  await el('incident-ref').fill('SYN-000000000002');
  await el('incident-find').click();
  await expect(el('incident-result')).toContainText('не найдено');
  expect(lookups).toHaveLength(3);
  expect(readCalls).toBe(0);
 });
}
test('late incident lookup cannot disclose the previous query on the phone',async({page})=>{
 let release;const pause=new Promise(r=>release=r);
 const ref='SYN-0123456789ab';
 await page.route('**/chat/incident/lookup',async route=>{
  await pause;await route.fulfill({json:{reference:ref,state:'found',report:{text:'Обращение '+ref+'\nprivate fixture text',createdAt:1700000000}}});
 });
 await page.goto(origin+'/#support-title');
 await expect(page.locator('#support-inbox').getByRole('button',{name:/Пользователь/})).toBeVisible();
 const field=page.locator('#support-incident-ref');
 await field.fill(ref);
 const started=page.waitForRequest(request=>new URL(request.url()).pathname==='/chat/incident/lookup');
 await page.locator('#support-incident-find').click();await started;
 await field.fill('SYN-000000000001');
 release();
 await expect(page.locator('#support-incident-find')).toBeEnabled();
 await expect(page.locator('#support-incident-result')).toBeHidden();
 await expect(page.locator('#support-incident-result')).toHaveText('');
});
