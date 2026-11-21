import {test,expect} from '@playwright/test';
import jsQR from 'jsqr';

const origin='http://127.0.0.1:17851';
const opaque=n=>Buffer.alloc(32,n).toString('base64url');
const owner=opaque(1),grant=opaque(2),id=opaque(3),deviceKey=opaque(4);
const link='syn443://enroll/v1?'+new URLSearchParams({bootstrap:'synthetic.signed.descriptor',code:opaque(5),
  origin:'https://service.example.invalid',service:'Fixture_1'});
async function open(page,request,options={}){
 await request.post(origin+'/fixture/reset',{data:options});
 await page.setViewportSize({width:393,height:852});await page.goto(origin+'/#invites-title');
 await expect(page.getByRole('heading',{name:'Приглашения'})).toBeVisible();
}
async function propose(page){
 await page.locator('#invite-issue-form').getByRole('textbox',{name:'ID получателя',exact:true}).fill(owner);
 await page.getByLabel('Отпечаток назначения получателя').fill(grant);
 await page.getByLabel('Сервис привязки').fill('Fixture_1');
 await page.getByLabel('Версия описания сервиса').fill('2');
 await page.getByRole('button',{name:'Выпустить приглашение'}).click();
}
test('mobile invitation QR decodes to the exact local link and pairing needs the phone code',async({page,request})=>{
 const calls=[],urls=[];page.on('request',req=>urls.push(req.url()));
 await open(page,request,{reauthentication:true});
 await page.getByRole('button',{name:'Обновить подтверждение входа'}).click();
 await expect(page.locator('#reauthentication-title')).toBeFocused();
 let expires;
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON();if(!body.action.startsWith('invite.'))return route.fallback();
  expect(route.request().headers()['x-syn443-csrf']).toBe('1');calls.push(body);
  if(body.action==='invite.issue'){
   expires=body.payload.expires;expect(body.payload).toEqual({owner,grantHash:grant,serviceId:'Fixture_1',bootstrapRevision:2,expires});
   return route.fulfill({json:{id,version:1,expires,link}});
  }
  const state=body.action==='invite.approve'?'provisioning':'pending_approval';
  await route.fulfill({json:{id,owner,version:state==='provisioning'?3:2,expires,state,thumbprint:deviceKey,pairCode:'204681',device:''}});
 });
 await propose(page);expect(calls).toHaveLength(0);
 await page.getByRole('button',{name:'Подтвердить действие'}).click();await expect(page.getByLabel('Одноразовая ссылка')).toHaveValue(link);
 const image=await page.locator('#invite-qr').evaluate(canvas=>{
  const {data}=canvas.getContext('2d').getImageData(0,0,canvas.width,canvas.height);
  let text='';for(let pos=0;pos<data.length;pos+=8192)text+=String.fromCharCode(...data.subarray(pos,pos+8192));
  return {width:canvas.width,height:canvas.height,bytes:btoa(text)};
 });
 expect(jsQR(new Uint8ClampedArray(Buffer.from(image.bytes,'base64')),image.width,image.height)?.data).toBe(link);
 expect(urls.every(url=>new URL(url).origin===origin&&!url.includes(opaque(5)))).toBeTruthy();
 await page.getByRole('button',{name:'Проверить состояние'}).click();
 await expect(page.getByLabel('Одноразовая ссылка')).toHaveValue('');
 await expect(page.locator('#invite-detail')).toContainText(deviceKey);
 expect(await page.locator('#invite-view').innerText()).not.toContain('204681');
 await page.getByLabel('Код с экрана нового устройства').fill('999999');
 await page.getByRole('button',{name:'Подтвердить привязку'}).click();expect(calls).toHaveLength(2);
 await page.getByLabel('Код с экрана нового устройства').fill('204681');
 await page.getByRole('button',{name:'Подтвердить привязку'}).click();
 await page.getByRole('button',{name:'Подтвердить действие'}).click();
 await expect(page.locator('#invite-detail')).toContainText('Конфигурация готовится');
 expect(calls.at(-1).payload).toEqual({id,version:2,thumbprint:deviceKey,pairCode:'204681'});
});
test('lost invitation reply repeats the same operation and expired link pixels are erased',async({page,request})=>{
 await open(page,request);await page.clock.install();
 const attempts=[];
 await page.route('**/control/action',async route=>{
  const operation=route.request().postDataJSON();if(operation.action!=='invite.issue')return route.fallback();
  attempts.push(route.request().postData());if(attempts.length===1)return route.abort('failed');
  await route.fulfill({json:{id,version:1,expires:operation.payload.expires,link}});
 });
 await propose(page);await page.getByRole('button',{name:'Подтвердить действие'}).click();
 await expect(page.getByRole('button',{name:'Повторить запрос'})).toBeVisible();
 await page.getByRole('button',{name:'Повторить запрос'}).click();
 await expect(page.locator('#invite-link')).toHaveValue(link);expect(attempts[0]).toBe(attempts[1]);
 await page.clock.fastForward(601000);await expect(page.locator('#invite-delivery')).toBeHidden();
 await expect(page.locator('#invite-link')).toHaveValue('');
 expect(await page.locator('#invite-qr').evaluate(canvas=>canvas.width)).toBe(0);
});
test('revocation requires explicit confirmation and leaving invitations discards a delayed link',async({page,request})=>{
 await open(page,request);const calls=[];
 let release;const hold=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();if(!op.action.startsWith('invite.'))return route.fallback();
  calls.push(op);const expires=Math.floor(Date.now()/1000)+300;
  if(op.action==='invite.issue'){
   await hold;
   try{await route.fulfill({json:{id,version:1,expires:op.payload.expires,link}});}catch{}
   return;
  }
  await route.fulfill({json:{id,owner,expires,version:op.action==='invite.revoke'?8:7,state:op.action==='invite.revoke'?'revoked':'issued',thumbprint:'',pairCode:'',device:''}});
 });
 await page.getByLabel('ID приглашения',{exact:true}).fill(id);await page.getByRole('button',{name:'Проверить состояние'}).click();
 await page.getByRole('button',{name:'Отозвать приглашение'}).click();await page.getByRole('button',{name:'Отмена',exact:true}).click();
 expect(calls).toHaveLength(1);await page.getByRole('button',{name:'Отозвать приглашение'}).click();
 await page.getByRole('button',{name:'Подтвердить действие'}).click();await expect(page.locator('#invite-detail')).toContainText('Приглашение отозвано');
 expect(calls.at(-1).payload).toEqual({id,version:7});
 await propose(page);const waiting=page.waitForRequest(req=>req.url().endsWith('/control/action')&&req.postDataJSON()?.action==='invite.issue');
 await page.getByRole('button',{name:'Подтвердить действие'}).click();await waiting;
 await page.evaluate(()=>{location.hash='#inventory-title';});await expect(page.locator('#invites-title')).toBeHidden();release();
 await expect(page.locator('#invite-link')).toHaveValue('');await expect(page.locator('#invite-delivery')).toBeHidden();
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});
