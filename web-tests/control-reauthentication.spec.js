import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const state=async request=>(await request.post(origin+'/fixture/state',{data:{}})).json();

async function stagedChange(page,request,options={}){
 await request.post(origin+'/fixture/reset',{data:{reauthentication:true,...options}});await page.goto(origin+'/#device=device-a');
 await expect(page.locator('#inventory-view')).toBeVisible();await page.getByRole('link',{name:'Открыть публикацию',exact:true}).click();
 await page.locator('#layer-from-device').click();const text=await page.locator('#layer-proposal').inputValue();
 await page.locator('#layer-save').click();return text;
}

test('control reauthentication preserves the exact pending draft and requires explicit retry',async({page,request})=>{
 const text=await stagedChange(page,request);await expect(page.locator('#reauthentication')).toBeVisible();
 await expect(page.locator('#reauthentication-title')).toBeFocused();await expect(page.locator('#layer-proposal')).toHaveValue(text);
 let observed=await state(request);expect(observed.assuranceRequests).toHaveLength(1);expect(observed.layerDrafts).toHaveLength(0);
 const pending=observed.assuranceRequests[0];
 const popupReady=page.waitForEvent('popup');await page.locator('#reauthentication-start').click();const popup=await popupReady;
 await expect(popup).toHaveURL(/\/fixture\/id\/protocol\/openid-connect\/auth\?/);
 expect(await popup.evaluate(()=>window.opener===null)).toBe(true);
 await page.locator('#reauthentication-check').click();await expect(page.locator('#reauthentication')).toBeVisible();
 await request.post(origin+'/fixture/reauth-complete',{data:{}});await page.locator('#reauthentication-check').click();
 await expect(page.locator('#reauthentication')).toBeHidden();await expect(page.locator('#layer-proposal')).toHaveValue(text);
 observed=await state(request);expect(observed.assuranceRequests).toHaveLength(1);expect(observed.layerDrafts).toHaveLength(0);
 await page.locator('#retry-save').click();await expect(page.locator('#layer-version')).toHaveText('Сохранённая версия слоёв: 1');
 observed=await state(request);expect(observed.assuranceRequests).toEqual([pending,pending]);expect(observed.layerDrafts).toHaveLength(1);
 expect(observed.calls).not.toContain('configuration.publish');expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
 await popup.close();
});

test('control reauthentication never turns withdrawn authority into a recoverable sign-in',async({page,request})=>{
 await stagedChange(page,request);await expect(page.locator('#reauthentication')).toBeVisible();
 await request.post(origin+'/fixture/reauth-complete',{data:{}});await page.locator('#reauthentication-check').click();
 await expect(page.locator('#reauthentication')).toBeHidden();await request.post(origin+'/fixture/revoke',{data:{}});
 await page.locator('#retry-save').click();await expect(page.locator('#workspace')).toBeHidden();
 await expect(page.locator('#layer-proposal')).toHaveValue('');await expect(page.locator('#reauthentication')).toBeHidden();
 const observed=await state(request);expect(observed.layerDrafts).toHaveLength(0);expect(observed.calls).not.toContain('configuration.publish');
});

test('blocked reauthentication windows retain the unsaved draft without starting authentication',async({page,request})=>{
 await page.addInitScript(()=>{window.open=()=>null;});const text=await stagedChange(page,request);
 await page.locator('#reauthentication-start').click();await expect(page.locator('#status')).toContainText('Разрешите новую вкладку');
 expect((await state(request)).authenticationStarts).toBe(0);await expect(page.locator('#layer-proposal')).toHaveValue(text);
 await expect(page.locator('#reauthentication-title')).toBeFocused();
});

test('substituted reauthentication navigation and expired sessions fail closed',async({page,request})=>{
 const text=await stagedChange(page,request,{substitutedAssurance:true});
 const popupReady=page.waitForEvent('popup');await page.locator('#reauthentication-start').click();const popup=await popupReady;
 await expect(page.locator('#status')).toContainText('Проверьте поля');expect(popup.isClosed()).toBe(true);
 await expect(page.locator('#layer-proposal')).toHaveValue(text);expect((await state(request)).layerDrafts).toHaveLength(0);
 expect(page.context().pages()).toEqual([page]);
 await request.post(origin+'/fixture/expire',{data:{}});await page.locator('#reauthentication-check').click();
 await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#layer-proposal')).toHaveValue('');
 await expect(page.locator('#reauthentication')).toBeHidden();
});

test('assurance recovery is keyboard accessible on a narrow screen and rejects untrusted error metadata',async({page,request})=>{
 await page.setViewportSize({width:320,height:900});await stagedChange(page,request);
 const heading=page.locator('#reauthentication-title');await expect(heading).toBeFocused();
 await heading.press('Tab');await expect(page.locator('#reauthentication-start')).toBeFocused();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await stagedChange(page,request,{malformedAssurance:true});
 await expect(page.locator('#workspace')).toBeHidden();await expect(page.locator('#reauthentication')).toBeHidden();await expect(page.locator('#layer-proposal')).toHaveValue('');
});
