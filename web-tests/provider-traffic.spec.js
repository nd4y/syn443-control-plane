import {test,expect} from '@playwright/test';

const origin='http://127.0.0.1:17851';
const snapshot={id:'snapshot-a',sourceId:'source-a',observedAt:1790001000,validUntil:1790004600};
async function open(page,request,getView){
 await request.post(origin+'/fixture/reset',{data:{}});
 await page.setViewportSize({width:393,height:852});
 await page.route('**/control/action',route=>{
  if(route.request().postDataJSON().action==='source.snapshot')return route.fulfill({json:getView()});
  return route.fallback();
 });
 await page.goto(origin+'/#sources-title');
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 return page.getByRole('button',{name:'Показать профили'}).first();
}
test('mobile provider usage preserves exact counters and the original provider timestamp',async({page,request})=>{
 const view={snapshot:{...snapshot,quota:{known:true,used:1.8e19,limit:1.8e19,observedAt:1790000000,expiresAt:1800000000}},
  trafficBytes:{used:'18446744073709551614',limit:'18446744073709551615'},profiles:[]};
 const show=await open(page,request,()=>view);await show.click();
 await expect(page.locator('#source-traffic-left')).toHaveText('1 Б');
 expect((await page.locator('#source-traffic-used').innerText()).replace(/\s/g,'')).toBe('18446744073709551614Б');
 await expect(page.locator('#source-traffic-time')).toHaveAttribute('datetime',new Date(1790000000000).toISOString());
 await expect(page.locator('#source-snapshot-time')).toHaveAttribute('datetime',new Date(snapshot.observedAt*1000).toISOString());
 await expect(page.locator('#source-traffic-expiry')).toHaveAttribute('datetime',new Date(1800000000000).toISOString());
 await page.locator('#owner').fill('different-user');await expect(page.locator('#source-details')).toBeHidden();
 await expect(page.locator('#source-traffic-used')).toHaveText('');
});
test('unknown unlimited and exhausted provider quotas keep distinct labels on the phone',async({page,request})=>{
 let quota={known:false,used:0,limit:0,observedAt:1790000000};
 const show=await open(page,request,()=>({snapshot:{...snapshot,quota},profiles:[]}));await show.click();
 await expect(page.locator('#source-traffic-left')).toHaveText('Неизвестно');
 await expect(page.locator('#source-traffic-time')).toHaveText('Сведений нет');
 quota={known:true,used:9,limit:0,observedAt:1790000000,expiresAt:0};await show.click();
 await expect(page.locator('#source-traffic-limit')).toHaveText('Без ограничения');
 await expect(page.locator('#source-traffic-used')).toHaveText('9 Б');
 await expect(page.locator('#source-traffic-expiry')).toHaveText('Не указан');
 quota.limit=7;await show.click();await expect(page.locator('#source-traffic-left')).toHaveText('0 Б');
 quota.used=9007199254740992;await show.click();await expect(page.locator('#source-traffic-left')).toHaveText('Неизвестно');
});
