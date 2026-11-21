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
