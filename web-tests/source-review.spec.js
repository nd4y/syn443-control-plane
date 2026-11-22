import {test,expect} from '@playwright/test';

const origin='http://127.0.0.1:17851';
const hash='A'.repeat(43);
async function openQuarantine(page,request,decide){
 await request.post(origin+'/fixture/reset',{data:{}});
 await page.setViewportSize({width:393,height:852});
 const source={id:'source-a',owner:'synthetic-user',name:'Fixture',mode:'server',format:'uri',enabled:true,state:'quarantined',
  revision:3,networkModes:['wifi'],activeSnapshot:'old',candidateSnapshot:'new',validUntil:1800990000,refreshSeconds:3600,maxStaleSeconds:86400};
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON(),p=body.payload;
  if(body.action==='source.get')return route.fulfill({json:source});
  if(body.action==='source.snapshot'){
   const active=p.snapshot===source.activeSnapshot;
   const profiles=active?[{id:'previous',kind:'http',name:'Previous proxy'}]:
    Array.from({length:41},(_,i)=>({id:'member-'+i,kind:'vless',name:'Node '+i}));
   const snapshot={id:p.snapshot,sourceId:source.id,sourceRevision:source.revision,state:active?'active':'quarantined',observedAt:1790000000,
    count:profiles.length,hash,reason:active?'':'excessive_removal'};
   return route.fulfill({json:{snapshot,profiles}});
  }
  if(body.action==='source.review')return decide(route,body,source);
  return route.fallback();
 });
 await page.goto(origin+'/#sources-title');await page.locator('#owner').fill(source.owner);
 await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 await page.locator('#source-review-load').click();
 await expect(page.locator('#source-review-summary')).toContainText('Профилей было 1, стало 41');
 return source;
}

test('mobile source review compares both versions and retries the identical approved candidate',async({page,request})=>{
 const sent=[];
 await openQuarantine(page,request,async(route,body,source)=>{
  sent.push(route.request().postData());
  if(sent.length===1)return route.abort('failed');
  return route.fulfill({json:{id:'new',sourceId:source.id,sourceRevision:3,hash,state:'active'}});
 });
 await expect(page.locator('#source-review-approve')).toBeDisabled();
 await expect(page.locator('#source-review-changes li')).toHaveCount(40);
 await page.locator('#source-review-more').click();await expect(page.locator('#source-review-changes li')).toHaveCount(42);
 await expect(page.locator('#source-review-summary')).toContainText('значительная часть профилей');
 await expect(page.locator('#source-review-changes')).toContainText('Удалён · Previous proxy');
 await page.locator('#source-review-confirm').check();await page.locator('#source-review-approve').click();
 await expect(page.locator('#pending')).toBeVisible();await page.locator('#retry-save').click();
 await expect(page.locator('#source-review')).toBeHidden();await expect(page.locator('#pending')).toBeHidden();
 expect(sent).toHaveLength(2);expect(sent[1]).toBe(sent[0]);
 expect(JSON.parse(sent[0]).payload).toEqual({sourceId:'source-a',sourceRevision:3,candidate:'new',hash,active:'old',approve:true});
});

test('changed subscription review requires a fresh comparison before rejecting its successor',async({page,request})=>{
 const sent=[];
 await openQuarantine(page,request,async(route,body,source)=>{
  sent.push(body);
  if(sent.length===1){source.candidateSnapshot='newer';return route.fulfill({status:409,json:{code:'catalog_revision_conflict'}});}
  return route.fulfill({json:{id:'newer',sourceId:source.id,sourceRevision:3,hash,state:'rejected'}});
 });
 await page.locator('#source-review-confirm').check();await page.locator('#source-review-reject').click();
 await expect(page.locator('#source-review-comparison')).toBeHidden();await expect(page.locator('#pending')).toBeHidden();
 await page.locator('#source-review-load').click();await expect(page.locator('#source-review-confirm')).not.toBeChecked();
 await expect(page.locator('#source-review-reject')).toBeDisabled();
 await page.locator('#source-review-confirm').check();await page.locator('#source-review-reject').click();
 await expect(page.locator('#source-review')).toBeHidden();
 expect(sent.map(b=>[b.payload.candidate,b.payload.approve])).toEqual([['new',false],['newer',false]]);
 expect(sent[0].requestId).not.toBe(sent[1].requestId);
});

const boundSource={
 id:'source-bound',owner:'synthetic-user',name:'Provider subscription',mode:'resource',format:'uri',enabled:true,state:'active',
 revision:7,resourceId:'panel-a',externalUserId:'42',networkModes:['wifi'],validUntil:1800990000,refreshSeconds:3600,maxStaleSeconds:86400
};
async function sourceEditorPage(page,request){
 await request.post(origin+'/fixture/reset',{data:{}});
 await page.setViewportSize({width:393,height:852});
 await page.goto(origin+'/#sources-title');
 await page.locator('#owner').fill(boundSource.owner);
 await page.locator('#load-sources').click();
 return page.getByRole('button',{name:'Настроить источник'}).first();
}
test('source editor binds selection and retry to the owner and external pair',async({page,request})=>{
 let detail=boundSource;
 const attempts=[];
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON();
  if(body.action==='source.list')return route.fulfill({json:{sources:[boundSource],next:''}});
  if(body.action==='source.get')return route.fulfill({json:detail});
  if(body.action==='source.put'){
   attempts.push(route.request().postData());
   const reply={...body.payload.source,revision:8,state:'active'};
   if(attempts.length===1)reply.externalUserId='43';
   return route.fulfill({json:reply});
  }
  return route.fallback();
 });
 const edit=await sourceEditorPage(page,request);
 for(const change of [{id:'another'},{owner:'foreign'},{resourceId:'panel-b'},{externalUserId:'43'}]){
  detail={...boundSource,...change};
  await edit.click();
  await expect(page.locator('#status')).toContainText('Проверьте');
  await expect(page.locator('#source-id')).toHaveValue('');
 }
 detail=boundSource;
 await edit.click();
 await expect(page.locator('#source-resource')).toHaveValue('panel-a');
 await expect(page.locator('#source-resource')).toBeDisabled();
 await expect(page.locator('#source-external')).toHaveValue('42');
 await expect(page.locator('#source-external')).toBeDisabled();
 await page.locator('#source-name').fill('Edited display name');
 await page.locator('#save-source').click();
 await expect(page.locator('#pending')).toBeVisible();
 await expect(page.locator('#source-external')).toHaveValue('42');
 await expect(page.locator('#source-version')).toContainText('7');
 await page.locator('#retry-save').click();
 await expect(page.locator('#pending')).toBeHidden();
 await expect(page.locator('#source-version')).toContainText('8');
 expect(attempts).toHaveLength(2);
 expect(attempts[1]).toBe(attempts[0]);
 expect(JSON.parse(attempts[0]).payload.source).toMatchObject({id:boundSource.id,owner:boundSource.owner,resourceId:'panel-a',externalUserId:'42'});
});
test('source editor forgets a late selection when the listed owner changes',async({page,request})=>{
 let release,started;
 const arrived=new Promise(resolve=>{started=resolve;});
 const held=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON();
  if(body.action==='source.list')return route.fulfill({json:{sources:[boundSource],next:''}});
  if(body.action==='source.get'){started();await held;return route.fulfill({json:boundSource});}
  return route.fallback();
 });
 const edit=await sourceEditorPage(page,request);
 await edit.click();await arrived;
 try{await page.locator('#owner').fill('second-owner');}finally{release();}
 await expect(page.locator('#load-sources')).toBeEnabled();
 await expect(page.locator('#source-id')).toHaveValue('');
 await expect(page.locator('#source-external')).toHaveValue('');
 await expect(page.locator('#sources li')).toHaveCount(0);
});

test('dependency preview keeps a source draft and distinguishes unknown from unused profiles',async({page,request})=>{
 let detail={...boundSource,routeDependencies:{profileIds:['selected-profile'],incomplete:false}};
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON();
  if(body.action==='source.list')return route.fulfill({json:{sources:[boundSource],next:''}});
  if(body.action==='source.get')return route.fulfill({json:detail});
  return route.fallback();
 });
 const edit=await sourceEditorPage(page,request);await edit.click();
 const summary=page.locator('#source-dependencies-summary'),list=page.locator('#source-dependencies-profiles');
 await expect(list.getByRole('listitem')).toHaveText('selected-profile');
 await expect(summary).toContainText('замените эти профили');
 const ids=Array.from({length:65},(_,index)=>'profile-'+String(index+1).padStart(2,'0'));
 detail={...boundSource,routeDependencies:{profileIds:ids,incomplete:false}};
 await page.locator('#source-dependencies-refresh').click();
 await expect(list.getByRole('listitem')).toHaveCount(32);await page.locator('#source-dependencies-more').click();
 await expect(list.getByRole('listitem')).toHaveCount(64);await page.locator('#source-dependencies-more').click();
 await expect(list.getByRole('listitem')).toHaveCount(65);await expect(list.getByRole('listitem').last()).toHaveText('profile-65');
 await expect(page.locator('#source-dependencies-more')).toBeHidden();
 await page.locator('#source-name').fill('Unsaved source name');
 detail={...boundSource,routeDependencies:{profileIds:[],incomplete:true}};
 await page.locator('#source-dependencies-refresh').click();
 await expect(list).toBeHidden();await expect(summary).toContainText('ещё проверяется');
 await expect(summary).not.toContainText('не используются');
 await expect(page.locator('#source-name')).toHaveValue('Unsaved source name');
 detail={...boundSource,routeDependencies:{profileIds:[],incomplete:false}};
 await page.locator('#source-dependencies-refresh').click();await expect(summary).toContainText('не используются');
 detail={...boundSource,routeDependencies:{profileIds:['<invalid>'],incomplete:false}};
 await page.locator('#source-dependencies-refresh').click();await expect(summary).toContainText('пока неизвестны');
 await expect(list).toBeHidden();await page.locator('#new-source').click();await expect(page.locator('#source-dependencies')).toBeHidden();
});

test('mobile quarantine distinguishes an unreadable refresh from a reviewable source version',async({page,request})=>{
 const source={...boundSource,mode:'server',resourceId:'',externalUserId:'',state:'quarantined',activeSnapshot:'previous',candidateSnapshot:'previous'};
 const actions=[];
 await page.route('**/control/action',async route=>{
  const body=route.request().postDataJSON();
  actions.push(body.action);
  if(body.action==='source.list')return route.fulfill({json:{sources:[source],next:''}});
  if(body.action==='source.get')return route.fulfill({json:source});
  return route.fallback();
 });
 const edit=await sourceEditorPage(page,request);
 await edit.click();
 await expect(page.locator('#source-version')).toContainText('Предыдущая версия профилей сохранена');
 await expect(page.locator('#source-version')).toContainText('истории обновлений');
 await expect(page.locator('#source-review')).toBeHidden();
 delete source.activeSnapshot;delete source.candidateSnapshot;
 await edit.click();
 await expect(page.locator('#source-version')).toContainText('Опубликованных профилей пока нет');
 await expect(page.locator('#source-version')).not.toContainText('сохранена');
 await expect(page.locator('#source-review')).toBeHidden();
 await page.locator('#new-source').click();
 await expect(page.locator('#source-version')).not.toContainText('карантине');
 expect(actions).not.toContain('source.review');
 expect(actions).not.toContain('source.snapshot');
});
