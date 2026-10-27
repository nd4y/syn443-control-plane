import {test,expect} from '@playwright/test';import fs from 'node:fs/promises';import crypto from 'node:crypto';
test.beforeEach(async({request})=>{await request.post('/fixture/reset',{data:{}});});
async function open(page){await page.goto('/');await page.getByRole('button',{name:/Пользователь/}).click();await expect(page.locator('#send')).toBeEnabled();}
test('administrator sends text and hostile content remains text',async({page})=>{
 await open(page);const value='<img src=x onerror="window.executed=true">';await page.locator('#text').fill(value);await page.locator('#send').click();await expect(page.locator('#messages')).toContainText(value);await expect(page.locator('#messages img')).toHaveCount(0);expect(await page.evaluate(()=>window.executed)).toBeUndefined();
 await page.locator('#text').fill('first');await page.locator('#text').press('Enter');await expect(page.locator('#messages li')).toHaveCount(1);
});
test('25 MiB upload and authenticated verified download',async({page,request})=>{
 await open(page);const bytes=Buffer.alloc(25*1024*1024,37);await page.locator('#file').setInputFiles({name:'synthetic.bin',mimeType:'application/octet-stream',buffer:bytes});await page.locator('#send').click();await expect(page.locator('#messages button')).toHaveText(/synthetic.bin/,{timeout:90000});
 await page.locator('#messages button').click();const save=page.getByRole('link',{name:'Сохранить файл: synthetic.bin',exact:true});await expect(save).toBeVisible({timeout:90000});const event=page.waitForEvent('download');await save.click();const result=await event;const received=await fs.readFile(await result.path());expect(received.length).toBe(bytes.length);expect(crypto.createHash('sha256').update(received).digest('hex')).toBe(crypto.createHash('sha256').update(bytes).digest('hex'));await request.post('/fixture/expire');await page.locator('#older').click();await expect(save).toHaveCount(0);
});
test('lost send acknowledgment retries exactly one message',async({page,request})=>{
 await request.post('/fixture/reset',{data:{failSend:true}});await open(page);await page.locator('#text').fill('immutable retry');await page.locator('#send').click();await expect(page.locator('#status')).toContainText('повторить');await page.getByRole('button',{name:/Пользователь/}).click();await expect(page.locator('#status')).toContainText('Сначала отправьте');await page.locator('#send').click();await expect(page.locator('#messages li')).toHaveCount(1);expect((await (await request.post('/fixture/state')).json()).messages).toBe(1);
});
test('oversize file is rejected locally and session expiry erases contents',async({page,request})=>{
 await page.setViewportSize({width:390,height:844});await open(page);await page.locator('#file').setInputFiles({name:'too-large.bin',mimeType:'application/octet-stream',buffer:Buffer.alloc(25*1024*1024+1)});await page.locator('#send').click();await expect(page.locator('#status')).toContainText('повторить');expect((await (await request.post('/fixture/state')).json()).uploads).toBe(0);
 await page.locator('#file').setInputFiles([]);await page.locator('#text').fill('private fixture text');await page.locator('#send').click();await expect(page.locator('#messages')).toContainText('private fixture text');await request.post('/fixture/expire');await page.locator('#older').click();await expect(page.locator('#messages li')).toHaveCount(0);await expect(page.locator('#text')).toHaveValue('');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
});

test('role withdrawal clears the visible thread without deleting server history',async({page,request})=>{
 await open(page);await page.locator('#text').fill('synthetic role withdrawal');await page.locator('#send').click();await expect(page.locator('#messages')).toContainText('synthetic role withdrawal');
 await request.post('/fixture/revoke');await page.locator('#older').click();await expect(page.locator('#messages li')).toHaveCount(0);await expect(page.locator('#send')).toBeDisabled();await expect(page.locator('#status')).toContainText('не разрешён');
 expect((await (await request.post('/fixture/state')).json()).messages).toBe(1);
});
