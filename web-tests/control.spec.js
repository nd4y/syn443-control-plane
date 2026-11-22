import {test,expect} from '@playwright/test';
const origin='http://127.0.0.1:17851';
const plan={schemaVersion:1,graph:{profiles:{proxy:{sourceId:'source-a',profileId:'profile-a'}},chains:{},balancers:{},final:'proxy'},network:{schemaVersion:1,requiredNetworks:['tcp'],dnsFinal:'system',dnsStrategy:'prefer_ipv4'},activation:{timeoutSeconds:30,checks:[{id:'internet',type:'https_204',target:'https://health.example.invalid/generate_204',required:true}]}};
async function reset(request,body={}){await request.post(origin+'/fixture/reset',{data:body});}

async function openIssuedPaths(page,request,issued){
 await reset(request);
 await page.setViewportSize({width:393,height:852});
 await page.route('**/control/action',async route=>{
  const op=route.request().postDataJSON();
  if(op.action!=='configuration.inventory.get'||op.payload.id!=='device-a')return route.fallback();
  const upstream=await route.fetch(),reply=await upstream.json();
  reply.issuedSettings={...reply.issuedSettings,...issued};
  await route.fulfill({response:upstream,json:reply});
 });
 await page.goto(origin+'/#device=device-a');
 await page.getByText('Настройки выданной политики',{exact:true}).click();
}
test('phone displays configured entry and exit in network order and leaves balancer choice to device',async({page,request})=>{
 await openIssuedPaths(page,request,{routeFinal:'last',outbounds:[
  {tag:'last',type:'vless',detour:'middle'},{tag:'start',type:'http'},{tag:'middle',type:'ssh',detour:'start'},
  {tag:'automatic',type:'urltest',outbounds:['last','start'],default:'last'}]});
 const choice=page.getByLabel('Выход для просмотра'),steps=page.getByRole('list',{name:'Порядок соединения'}).getByRole('listitem');
 await expect(choice).toHaveValue('last');
 await expect(steps).toHaveText(['start · HTTP','middle · SSH','last · VLESS']);
 await choice.selectOption('automatic');
 await expect(page.locator('#issued-path-note')).toContainText('выбирает устройство');
 await expect(steps).toHaveText(['automatic · Балансер · варианты: last, start']);
 await page.locator('#inventory-device').fill('device-expired');await page.locator('#load-inventory').click();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
 await expect(page.locator('#issued-path')).toBeHidden();await expect(choice.locator('option')).toHaveCount(0);
});
test('missing or circular detours never display a guessed route and switching to direct recovers',async({page,request})=>{
 await openIssuedPaths(page,request,{routeFinal:'cycle',outbounds:[
  {tag:'cycle',type:'vless',detour:'cycle'},{tag:'incomplete',type:'ssh',detour:'absent'},{tag:'direct',type:'direct'}]});
 const choice=page.getByLabel('Выход для просмотра'),steps=page.locator('#issued-path-steps li');
 await expect(page.locator('#issued-path-note')).toContainText('неизвестен');await expect(steps).toHaveCount(0);
 await choice.selectOption('incomplete');await expect(steps).toHaveCount(0);
 await choice.selectOption('direct');await expect(steps).toHaveText(['direct · Прямое соединение']);
 await page.locator('#logout').click();await expect(page.locator('#issued-path-steps')).toHaveText('');
});

test('hourly telemetry distinguishes data empty and mismatched reports and clears on expiry',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#telemetry-title');
 const button=page.locator('#load-telemetry'),hour=page.locator('#telemetry-hour'),rows=page.locator('#telemetry-rows'),status=page.locator('#telemetry-status');
 await expect(button).toBeEnabled();
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(status).toHaveText('Сводка за 2026-01-02T01:00Z');
 await expect(rows.locator('td')).toHaveText(['probe','ok','wifi','3','2','26 мс','—']);
 await hour.fill('2026-01-02T02:00');await button.click();
 await expect(status).toContainText('нет готовой сводки');await expect(rows).toHaveText('');
 await hour.fill('2026-01-02T03:00');await button.click();
 await expect(status).toContainText('Не удалось загрузить');await expect(rows).toHaveText('');
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(rows.locator('tr')).toHaveCount(1);
 await request.post(origin+'/fixture/expire',{data:{}});
 await button.click();await expect(button).toBeDisabled();await expect(rows).toHaveText('');
 await expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('mobile telemetry discards delayed data and errors after selecting an hour again',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});await reset(request);await page.goto(origin+'/#telemetry-title');
 const hour=page.locator('#telemetry-hour'),load=page.locator('#load-telemetry'),status=page.locator('#telemetry-status'),rows=page.locator('#telemetry-rows');
 await expect(load).toBeEnabled();
 for(const code of [200,500]){
  let entered,finish;const started=new Promise(r=>entered=r),hold=new Promise(r=>finish=r);
  const handler=async route=>{
   if(route.request().postDataJSON().action!=='telemetry.summary.get')return route.fallback();
   entered();await hold;
   await route.fulfill({status:code,json:{schemaVersion:1,hourStartMs:Date.parse('2026-01-02T01:00Z'),available:true,
     rows:[{kind:'probe',code:'ok',mode:'wifi',events:4,timed:1,duration:22}]}});
  };
  await page.route('**/control/action',handler);
  await hour.fill('2026-01-02T01:00');await load.click();await started;
  await expect(hour).toBeEnabled();await hour.fill('2026-01-02T02:00');await hour.fill('2026-01-02T01:00');finish();
  await expect(load).toBeEnabled();await expect(status).toBeEmpty();await expect(rows).toBeEmpty();
  await page.unroute('**/control/action',handler);
 }
 await load.click();await expect(rows.locator('td')).toHaveText(['probe','ok','wifi','3','2','26 мс','—']);
});
test('hourly telemetry rejects duplicate buckets and totals above the server limit as a whole',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#telemetry-title');
 const hour=page.locator('#telemetry-hour'),load=page.locator('#load-telemetry'),status=page.locator('#telemetry-status'),rows=page.locator('#telemetry-rows');
 await expect(load).toBeEnabled();await hour.fill('2026-01-02T01:00');
 let payload;
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action!=='telemetry.summary.get')return route.fallback();
  await route.fulfill({json:{schemaVersion:1,hourStartMs:Date.parse('2026-01-02T01:00Z'),available:true,rows:payload}});
 });
 const bucket={kind:'probe',code:'ok',mode:'wifi',events:60000,timed:0,duration:0};
 for(const extra of [{...bucket,events:1},{...bucket,mode:'unknown',events:40001}]){
  payload=[bucket,extra];await load.click();await expect(status).toContainText('Не удалось загрузить');await expect(rows).toBeEmpty();
 }
 payload=[bucket,{...bucket,mode:'unknown',events:40000}];await load.click();await expect(rows.locator('tr')).toHaveCount(2);
});
test('hourly route summary shows only valid counts for the two decision algorithms',async({page,request})=>{
 await reset(request,{decisionTelemetry:true});await page.goto(origin+'/#telemetry-title');
 const button=page.locator('#load-telemetry'),hour=page.locator('#telemetry-hour'),rows=page.locator('#telemetry-rows');
 await expect(button).toBeEnabled();
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(rows.locator('td')).toHaveText(['route','reselected','wifi','4','0','—','Базовый: 1, консервативный: 2']);
 await hour.fill('2026-01-02T04:00');await button.click();
 await expect(page.locator('#telemetry-status')).toContainText('Не удалось загрузить');
 await expect(rows).toHaveText('');
});

test('hourly route summary preserves legacy counts when the adaptive count is absent',async({page,request})=>{
 await reset(request,{adaptiveTelemetry:'absent'});await page.goto(origin+'/#telemetry-title');
 const button=page.locator('#load-telemetry'),hour=page.locator('#telemetry-hour'),rows=page.locator('#telemetry-rows');
 await expect(button).toBeEnabled();
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(page.locator('#telemetry-status')).toHaveText('Сводка за 2026-01-02T01:00Z');
 await expect(rows.locator('td')).toHaveText(['route','reselected','wifi','4','0','—','Базовый: 1, консервативный: 2']);
});

test('hourly route summary adds a positive adaptive count to the existing counts',async({page,request})=>{
 await reset(request,{adaptiveTelemetry:'positive'});await page.goto(origin+'/#telemetry-title');
 const button=page.locator('#load-telemetry'),hour=page.locator('#telemetry-hour'),rows=page.locator('#telemetry-rows');
 await expect(button).toBeEnabled();
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(rows.locator('td')).toHaveText(['route','reselected','wifi','4','0','—','Базовый: 1, консервативный: 1, адаптивный: 2']);
 await reset(request,{adaptiveTelemetry:'only'});await page.reload();
 await expect(button).toBeEnabled();
 await hour.fill('2026-01-02T01:00');await button.click();
 await expect(rows.locator('td')).toHaveText(['route','reselected','wifi','3','0','—','адаптивный: 2']);
});

test('hourly route summary rejects invalid adaptive aggregates without partial stats',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#telemetry-title');
 const button=page.locator('#load-telemetry'),hour=page.locator('#telemetry-hour'),rows=page.locator('#telemetry-rows');
 for(const adaptiveTelemetry of ['invalid','null','negative','total','non-route','partial']){
  await reset(request,{adaptiveTelemetry});await page.reload();
  await expect(button).toBeEnabled();
  await hour.fill('2026-01-02T01:00');await button.click();
  await expect(page.locator('#telemetry-status')).toContainText('Не удалось загрузить');
  await expect(rows).toHaveText('');
 }
});

test('scoped telemetry denial preserves an unrelated unsaved draft',async({page,request})=>{
 await reset(request,{telemetryDenied:true});await page.goto(origin+'/#draft-title');
 await draft(page);
 await page.getByRole('link',{name:'Телеметрия'}).click();
 await expect(page.locator('#load-telemetry')).toBeEnabled();
 await page.locator('#load-telemetry').click();
 await expect(page.locator('#telemetry-status')).toContainText('Нет доступа');
 await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan,null,2));
 await expect(page.locator('#logout')).toBeEnabled();
 await request.post(origin+'/fixture/revoke',{data:{}});
 await page.locator('#load-telemetry').click();
 await expect(page.locator('#plan')).toHaveValue('');
 await expect(page.locator('#logout')).toBeDisabled();
});

test('source job history shows bounded retries and clears scoped results on logout',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#sources-title');await expect(page.locator('#load-sources')).toBeEnabled();
 await expect(page.locator('#source-history')).toBeDisabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 await page.locator('#source-history').click();
 const history=page.locator('#source-history-list');
 await expect(history.locator('li')).toHaveCount(20);
 await expect(history).toContainText('В очереди');
 await expect(history).toContainText('не ранее');
 await expect(history).toContainText('subscription_fetch_unavailable');
 await expect(history).not.toContainText('synthetic-untrusted-data');
 await page.locator('#source-history-more').click();
 await expect(history.locator('li')).toHaveCount(21);
 await expect(history).toContainText('Истёк срок или лимит повторов');
 await expect(page.locator('#source-history-more')).toBeDisabled();
 await page.locator('#logout').click();
 await expect(history).toHaveText('');
 await expect(page.locator('#source-history')).toBeDisabled();
});

test('manual subscription file retries exactly once without exposing or storing its contents',async({page,request})=>{
 await reset(request,{manualSource:true,importFailOnce:true});await page.goto(origin+'/#sources-title');await expect(page.locator('#load-sources')).toBeEnabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 const file=page.locator('#source-import-file');
 await expect(file).toBeEnabled();
 await file.setInputFiles({name:'synthetic.txt',mimeType:'text/plain',buffer:Buffer.from('http://proxy.example.invalid:443')});
 await expect(page.locator('#source-import')).toBeEnabled();
 await page.locator('#source-import').click({timeout:5000});
 await expect(page.locator('#pending')).toBeVisible();await expect(file).toHaveValue('');
 await page.locator('#retry-save').click();
 await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#job-status')).toContainText('synthetic-import-job');
 await expect(page.locator('main')).not.toContainText('proxy.example.invalid');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls.filter(call=>call==='source.import')).toHaveLength(2);expect(state.operations).toBe(1);
 expect(state.calls).not.toContain('configuration.publish');
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('source recipient edits require confirmation and retry the same scoped mutation',async({page,request})=>{
 await reset(request,{sharesFailOnce:true});await page.goto(origin+'/#sources-title');await expect(page.locator('#load-sources')).toBeEnabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await page.getByRole('button',{name:'Настроить источник'}).first().click();
 await page.locator('#source-shares-load').click();
 const recipient=page.locator('#source-shares-id'),list=page.locator('#source-shares-list');
 await expect(recipient).toBeEnabled();await page.locator('#source-shares-kind').selectOption('device');
 await recipient.fill('device-a');await page.locator('#source-shares-add').click();await expect(list).toContainText('Устройство · device-a');
 await expect(page.locator('#source-shares-save')).toBeDisabled();
 await page.locator('#source-shares-confirm').check();await page.locator('#source-shares-save').click();
 await expect(page.locator('#pending')).toBeVisible();await expect(recipient).toBeDisabled();
 await page.locator('#retry-save').click();
 await expect(page.locator('#source-shares-revision')).toContainText('Версия списка: 1');
 await expect(page.locator('#pending')).toBeHidden();await expect(list).toContainText('device-a');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls.filter(call=>call==='source.shares.put')).toHaveLength(2);
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
 await request.post(origin+'/fixture/revoke',{data:{}});
 await page.locator('#source-shares-load').click();
 await expect(list).toHaveText('');await expect(page.locator('#source-shares-save')).toBeDisabled();
});
async function draft(page){await page.locator('#draft-id').fill('draft-a');await page.locator('#target-id').fill('device-a');await page.locator('#plan').fill(JSON.stringify(plan,null,2));}
test('manual route preview sends only on request and shows DNS and proxy dial order on a phone',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:393,height:852});
 await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const value=structuredClone(plan);
 value.graph.profiles.first={sourceId:'first-source',profileId:'first-profile'};
 value.graph.chains.work={dialOrder:['first','proxy']};
 value.network.rules=[{id:'work-rule',match:{domainSuffixes:['example.invalid']},action:'route',outbound:'work',matchAll:false}];
 await page.locator('#plan').fill(JSON.stringify(value));
 await page.getByText('Как сработают правила черновика',{exact:true}).click();
 let calls=0;
 await page.route('**/control/route-explanation',async route=>{
  const body=route.request().postDataJSON();expect(route.request().method()).toBe('POST');
  expect(body).toEqual({routeFinal:'proxy',dnsFinal:'system',rules:value.network.rules,dnsRules:[],
   query:{domain:'test.example.invalid',network:'tcp',port:443,dnsType:'A'}});
  calls++;await route.fulfill({json:{route:{status:'matched',rule:'work-rule',target:'work'},dns:{status:'default',target:'system'}}});
 });
 const run=page.locator('#explain-run'),result=page.locator('#explain-result');
 await expect(run).toBeDisabled();
 await page.getByLabel('Домен',{exact:true}).fill('test.example.invalid');
 await page.locator('#explain-network').selectOption('tcp');await page.locator('#explain-port').fill('443');
 await page.locator('#explain-dnsType').selectOption('A');expect(calls).toBe(0);
 await run.click();await expect(result).toContainText('Правило work-rule · first → proxy');
 await expect(result).toContainText('По умолчанию · system');expect(calls).toBe(1);
 await page.locator('#target-id').fill('other-device');
 await expect(result).toBeEmpty();await expect(page.locator('#explain-domain')).toHaveValue('');await expect(run).toBeDisabled();
});
test('phone route preview distinguishes an unavailable hostname on a shared IP from an IP literal',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});await reset(request);await page.goto(origin+'/#draft-title');
 await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 await page.getByText('Как сработают правила черновика',{exact:true}).click();
 const context=page.getByLabel('Что известно об адресе'),address=page.getByLabel('IP-адрес назначения');
 const run=page.locator('#explain-run'),out=page.locator('#explain-result'),queries=[];
 await page.route('**/control/route-explanation',async route=>{
  const q=route.request().postDataJSON().query;queries.push(q);
  await route.fulfill({json:q.domainUnavailable?{route:{status:'incomplete',rule:'named'},dns:{status:'incomplete'}}:
      {route:{status:'default',target:'direct'},dns:{status:'not_applicable'}}});
 });
 await expect(context).toBeDisabled();await address.fill('2001:db8::10');await expect(context).toBeEnabled();
 await context.selectOption('unknown');await run.click();await expect(out).toContainText('Недостаточно данных для правила named.');
 expect(queries[0]).toEqual({address:'2001:db8::10',domainUnavailable:true});
 await context.selectOption('');await expect(out).toBeEmpty();await run.click();await expect(out).toContainText('Прямое соединение');
 expect(queries[1]).toEqual({address:'2001:db8::10'});
 await context.selectOption('unknown');await page.locator('#explain-domain').fill('known.example.invalid');
 await expect(context).toBeDisabled();await expect(context).toHaveValue('');await expect(out).toBeEmpty();
 await run.click();await expect(out).toContainText('Прямое соединение');
 expect(queries[2]).toEqual({domain:'known.example.invalid',address:'2001:db8::10'});
});
test('manual route preview discards late results and distinguishes missing facts from default',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 await page.getByText('Как сработают правила черновика',{exact:true}).click();
 const app=page.locator('#explain-application'),out=page.locator('#explain-result'),run=page.locator('#explain-run');
 let arrived,release,calls=0;const started=new Promise(resolve=>{arrived=resolve;}),hold=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/route-explanation',async route=>{
  calls++;if(calls===1){arrived();await hold;}
  await route.fulfill({json:{route:{status:'incomplete',rule:'ordered'},dns:{status:'incomplete'}}});
 });
 await app.fill('org.example.one');await run.click();await started;await app.fill('org.example.two');release();
 await expect(run).toBeEnabled();await expect(out).toBeEmpty();
 await run.click();await expect(out).toContainText('Недостаточно данных для правила ordered.');
 await expect(out).not.toContainText('По умолчанию');await expect(out).not.toContainText('org.example');
 await page.locator('#plan').fill(JSON.stringify({...plan,graph:{...plan.graph,final:'direct'}}));
 await expect(app).toHaveValue('');await expect(out).toBeEmpty();
});
test('phone-sized editor previews bounded adaptive routes and keeps an excessive draft editable',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});await reset(request);await page.goto(origin+'/#draft-title');
 await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const button=page.getByRole('button',{name:'Оценить число цепочек'}),output=page.locator('#route-bounds-result'),input=page.locator('#plan');
 await expect(button).toBeHidden();
 const adaptive={metadataB64:'synthetic',bindingsB64:'synthetic',groups:{work:'adaptive-work',video:'adaptive-video'}};
 const value=JSON.stringify({...plan,adaptive});
 await input.fill(value);await expect(button).toBeEnabled();
 let calls=0;
 await page.route('**/control/route-bounds',async route=>{
  expect(route.request().method()).toBe('POST');expect(route.request().postDataJSON()).toEqual(adaptive);calls++;
  const report=calls===1?{status:'ready',limit:4096,intents:{NON_RU:4096},groups:['video','work'].map(group=>({group,intent:'NON_RU',upperBound:4096,maxHops:3}))}:
   {status:'over_limit',limit:4096};
  await route.fulfill({json:report});
 });
 await button.click();
 await expect(output).toContainText('Зарубежный интернет - до 4096');await expect(output).toContainText('work - до 4096 цепочек, переходов до 3');
 await button.click();await expect(output).toContainText('Сузьте список узлов');await expect(output).not.toContainText('work - до');
 await expect(input).toHaveValue(value);await expect(page.locator('#save-draft')).toBeEnabled();
 await input.fill(JSON.stringify(plan));await expect(button).toBeHidden();await expect(output).toBeEmpty();expect(calls).toBe(2);
});

test('a delayed candidate count cannot repaint a changed draft',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const input=page.locator('#plan'),button=page.getByRole('button',{name:'Оценить число цепочек'});
 const adaptive={metadataB64:'synthetic',bindingsB64:'synthetic',groups:{work:'adaptive-work'}};
 await input.fill(JSON.stringify({...plan,adaptive}));
 let arrived,release;
 const requested=new Promise(resolve=>{arrived=resolve;}),gate=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/route-bounds',async route=>{
  arrived();await gate;await route.fulfill({json:{status:'over_limit',limit:4096}});
 });
 await button.click();await requested;
 // The editor may keep form controls disabled while the request is active.
 // Dispatch the same input event as restoring a different saved draft.
 await input.evaluate((node,next)=>{node.value=next;node.dispatchEvent(new Event('input',{bubbles:true}));},JSON.stringify(plan));
 release();await expect(page.locator('#save-draft')).toBeEnabled();
 await expect(page.locator('#route-bounds-result')).toBeEmpty();await expect(button).toBeHidden();
});
test('phone source editor inspects assigned API resource metadata and distinguishes planned providers',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});
 await reset(request);await page.goto(origin+'/#sources-title');
 const mode=page.locator('#source-mode'),id=page.getByLabel('ID ресурса Remnawave'),button=page.getByRole('button',{name:'Посмотреть ресурс'}),details=page.locator('#provider-details');
 await expect(id).toBeHidden();await mode.selectOption('resource');await expect(button).toBeDisabled();
 await id.fill('/invalid');await expect(button).toBeDisabled();
 await id.fill('panel-a');await button.click();
 await expect(details.locator('dd')).toHaveText(['Synthetic panel-a','Remnawave','3.4','Включён','3','2','Нет данных']);
 await expect(details).not.toContainText('fixture-impact-hash');
 await id.fill('panel-b');await expect(details).toBeEmpty();await button.click();await expect(details).toContainText('Отключён');
 await id.fill('future-a');await button.click();
 await expect(details).toContainText('3x-ui');await expect(details).toContainText('Поддержка запланирована');
 await expect(details).not.toContainText('Последняя попытка синхронизации');
 await mode.selectOption('manual');await expect(button).toBeHidden();await expect(details).toBeEmpty();
 await mode.selectOption('resource');await button.click();await expect(details).toContainText('Synthetic future-a');
 await id.fill('not-authorized');await button.click();await expect(page.locator('#status')).toContainText('недостаточно прав');
 await expect(details).toBeEmpty();await expect(page.locator('#signin')).toBeVisible();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);expect(state.calls.filter(name=>name==='resource.get')).toHaveLength(5);
});

async function editExistingProvider(page){
 await page.goto(origin+'/#sources-title');
 await page.locator('#source-mode').selectOption('resource');
 await page.getByLabel('ID ресурса Remnawave').fill('panel-a');
 await page.getByRole('button',{name:'Посмотреть ресурс'}).click();
 await page.getByText('Изменить ресурс Remnawave',{exact:true}).click();
 return page.getByRole('button',{name:'Сохранить ресурс'});
}

test('mobile resource rename replays its exact request after a lost response',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});await reset(request,{providerLostReply:true});
 const bodies=[];
 page.on('request',r=>{if(r.url().endsWith('/control/action')&&r.postDataJSON()?.action==='resource.put')bodies.push(r.postData());});
 const save=await editExistingProvider(page);
 await expect(save).toBeDisabled();await page.getByLabel('Название ресурса').fill('Тестовый провайдер');
 await page.getByLabel('Название ресурса').press('Enter');await expect(page.locator('#pending')).toBeVisible();
 await page.locator('#retry-save').click();await expect(page.locator('#provider-details')).toContainText('Тестовый провайдер');
 expect(bodies).toHaveLength(2);expect(bodies[1]).toBe(bodies[0]);
 const payload=JSON.parse(bodies[0]).payload;
 expect(payload.secret).toEqual({operation:'keep'});expect(payload.resource.revision).toBe(3);
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);
 expect(state.calls).not.toContain('configuration.publish');expect(state.calls).not.toContain('source.put');
});

test('sync changes require acknowledged impact and explicit retry after stronger login',async({page,request})=>{
 await reset(request,{reauthentication:true,providerReauth:true});
 const save=await editExistingProvider(page);
 await page.getByLabel('Разрешить синхронизацию').uncheck();
 await expect(page.locator('#provider-impact-text')).toContainText('Связанные источники: 2');
 await expect(save).toBeDisabled();await page.getByLabel('Подтверждаю изменение синхронизации').check();await save.click();
 await expect(page.locator('#reauthentication')).toBeVisible();
 await request.post(origin+'/fixture/reauth-complete',{data:{}});
 await page.locator('#reauthentication-check').click();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(0);
 await page.locator('#retry-save').click();await expect(page.locator('#provider-details')).toContainText('Отключён');
});

test('a conflicting resource update requires fresh inspection and planned providers stay read-only',async({page,request})=>{
 await reset(request);const save=await editExistingProvider(page);
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action==='resource.put')await route.fulfill({status:409,json:{}});
  else await route.continue();
 });
 await page.getByLabel('Название ресурса').fill('Conflicting edit');await save.click();
 await expect(page.locator('#status')).toContainText('Ресурс или его источники изменились');
 await expect(page.locator('#provider-editor')).toBeHidden();await expect(page.locator('#pending')).toBeHidden();
 await page.getByLabel('ID ресурса Remnawave').fill('future-a');await page.getByRole('button',{name:'Посмотреть ресурс'}).click();
 await expect(page.locator('#provider-details')).toContainText('Поддержка запланирована');
 await expect(page.locator('#provider-editor')).toBeHidden();
});

test('source change and expired session cannot retain a previous resource lookup',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#sources-title');
 const mode=page.locator('#source-mode'),id=page.getByLabel('ID ресурса Remnawave'),details=page.locator('#provider-details');
 const button=page.getByRole('button',{name:'Посмотреть ресурс'});
 await mode.selectOption('resource');await id.fill('panel-a');
 let arrived,release;
 const requested=new Promise(resolve=>{arrived=resolve}),gate=new Promise(resolve=>{release=resolve});
 await page.route('**/control/action',async route=>{
  if(route.request().postDataJSON().action!=='resource.get'){await route.continue();return;}
  const response=await route.fetch();arrived();await gate;await route.fulfill({response});
 });
 await button.click();await requested;
 await page.locator('#source-owner').evaluate(n=>{n.value='other-fixture';n.dispatchEvent(new Event('input',{bubbles:true}));});
 release();await expect(button).toBeEnabled();await expect(details).toBeEmpty();await page.unroute('**/control/action');
 await button.click();await expect(details).toContainText('Synthetic panel-a');
 await request.post(origin+'/fixture/expire',{data:{}});await button.click();
 await expect(details).toBeEmpty();await expect(page.locator('#signin')).toBeVisible();
});

test('route checks editor changes only its private draft and restores saved checks',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();
 await expect(page.locator('#route-check-add')).toBeDisabled();
 await draft(page);
 const target=page.locator('#route-check-target'),method=page.locator('#route-check-method');
 const list=page.locator('#route-check-list'),add=page.locator('#route-check-add');
 await expect(page.locator('#route-check-path')).toHaveValue('proxy');
 await page.locator('#route-check-required').check();
 await target.fill('home.example.invalid:22');await add.click();
 await expect(list).toContainText('home.example.invalid:22 · обязательная');
 await method.selectOption('https_204');await target.fill('https://health.example.invalid/204');await add.click();
 const expectedIP=page.locator('#route-check-ip');
 await expect(expectedIP).toBeHidden();await method.selectOption('https_exit_ip');await expect(expectedIP).toBeVisible();
 await target.fill('https://health.example.invalid/address');await expectedIP.fill('192.0.2.9');await add.click();
 await expect(list.locator('li')).toHaveCount(3);await expect(list).toContainText('192.0.2.9');
 let state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);
 const current=JSON.parse(await page.locator('#plan').inputValue());
 expect(current.network.routeChecks).toEqual([{outbound:'proxy',required:true,checks:[
  {method:'tcp',target:'home.example.invalid:22'},{method:'https_204',target:'https://health.example.invalid/204'},
  {method:'https_exit_ip',target:'https://health.example.invalid/address',expected_ip:'192.0.2.9'},
 ]}]);
 expect(current.graph).toEqual(plan.graph);
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await page.locator('#plan').fill('{}');await page.locator('#open-draft').click();
 await expect(list.locator('li')).toHaveCount(3);
 await list.locator('li').first().getByRole('button',{name:'Удалить проверку'}).click();
 await expect(list.locator('li')).toHaveCount(2);
 await target.fill('unsaved.example.invalid:443');await page.locator('#logout').click();
 await expect(target).toHaveValue('');await expect(expectedIP).toHaveValue('');await expect(list).toHaveText('');
 state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('each route retains only its own pending probe and required flag on a phone',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:393,height:852});
 await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const value=structuredClone(plan);
 value.graph.profiles.home={sourceId:'source-a',profileId:'home-a'};
 value.graph.profiles.office={sourceId:'source-a',profileId:'office-a'};
 const raw=page.locator('#plan');await raw.fill(JSON.stringify(value));
 const path=page.locator('#route-check-path'),method=page.locator('#route-check-method');
 const target=page.locator('#route-check-target'),required=page.locator('#route-check-required');
 const add=page.locator('#route-check-add'),verb=page.locator('#route-check-verb'),code=page.locator('#route-check-status');
 await path.selectOption('home');await required.check();await method.selectOption('ssh_banner');
 await expect(required).toBeChecked();await target.fill('home.example.invalid:22');
 await path.selectOption('office');await expect(target).toHaveValue('');await expect(required).not.toBeChecked();
 await method.selectOption('https_status');await target.fill('https://office.example.invalid/health');await verb.selectOption('GET');await code.fill('204');
 await path.selectOption('home');await expect(target).toHaveValue('home.example.invalid:22');await expect(method).toHaveValue('ssh_banner');await expect(required).toBeChecked();await add.click();
 await path.selectOption('office');await expect(method).toHaveValue('https_status');await expect(target).toHaveValue('https://office.example.invalid/health');
 await expect(verb).toHaveValue('GET');await expect(code).toHaveValue('204');await expect(required).not.toBeChecked();await add.click();
 await path.selectOption('proxy');await expect(target).toHaveValue('');await expect(method).toHaveValue('tcp');await target.fill('third.example.invalid:443');await add.click();
 const rows=JSON.parse(await raw.inputValue()).network.routeChecks;
 expect(rows).toEqual([
  {outbound:'home',required:true,checks:[{method:'ssh_banner',target:'home.example.invalid:22'}]},
  {outbound:'office',required:false,checks:[{method:'https_status',target:'https://office.example.invalid/health',http_method:'GET',expected_status:204}]},
  {outbound:'proxy',required:false,checks:[{method:'tcp',target:'third.example.invalid:443'}]},
 ]);
});

test('changing draft ownership or replacing the document drops unsubmitted route parameters',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const target=page.locator('#route-check-target'),method=page.locator('#route-check-method'),required=page.locator('#route-check-required');
 await method.selectOption('https_exit_ip');await target.fill('https://first.example.invalid/address');await page.locator('#route-check-ip').fill('192.0.2.27');await required.check();
 await page.locator('#target-id').fill('another-device');await expect(target).toHaveValue('');await expect(method).toHaveValue('tcp');await expect(required).not.toBeChecked();
 await page.locator('#target-id').fill('device-a');await expect(target).toHaveValue('');await method.selectOption('https_exit_ip');await expect(page.locator('#route-check-ip')).toHaveValue('');
 await target.fill('https://unsaved.example.invalid/address');const raw=page.locator('#plan');await raw.fill(JSON.stringify(plan));
 await expect(target).toHaveValue('');await expect(method).toHaveValue('tcp');expect(JSON.parse(await raw.inputValue()).network.routeChecks).toBeUndefined();
});

test('HTTPS status checks retain the chosen verb and status for each route draft',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await draft(page);
 const method=page.locator('#route-check-method'),target=page.locator('#route-check-target');
 const verb=page.getByLabel('Метод HTTP',{exact:true}),code=page.getByLabel('Ожидаемый код ответа',{exact:true});
 const add=page.locator('#route-check-add'),list=page.locator('#route-check-list li');
 const url='https://service.example.invalid/ready';
 await expect(verb).toBeHidden();await method.selectOption('https_status');
 await expect(verb).toHaveValue('HEAD');await expect(code).toHaveValue('200');
 await target.fill(url);await code.fill('199');await add.click();await expect(list).toHaveCount(0);
 await code.fill('200');await target.fill('http://service.example.invalid/ready');await add.click();await expect(list).toHaveCount(0);
 await target.fill(url);await add.click();await expect(list).toHaveCount(1);
 await target.fill(url);await add.click();await expect(list).toHaveCount(1);
 await verb.selectOption('GET');await add.click();await expect(list).toHaveCount(2);
 await target.fill(url);await code.fill('302');await add.click();await expect(list).toHaveCount(3);
 await list.filter({hasText:'GET · 200'}).getByRole('button',{name:'Удалить проверку'}).click();
 await expect(list).toHaveCount(2);await expect(list.filter({hasText:'GET · 302'})).toHaveCount(1);
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await page.locator('#plan').fill('{}');await page.locator('#open-draft').click();
 await expect(list).toHaveCount(2);await expect(list.filter({hasText:'HEAD · 200'})).toHaveCount(1);
 const saved=JSON.parse(await page.locator('#plan').inputValue()).network.routeChecks[0].checks;
 expect(saved).toEqual([{method:'https_status',target:url,http_method:'HEAD',expected_status:200},
  {method:'https_status',target:url,http_method:'GET',expected_status:302}]);
 await method.selectOption('tcp');await expect(verb).toBeHidden();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('mobile route editor reports invalid HTTPS addresses without changing the draft',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});
 await reset(request);await page.goto(origin+'/#draft-title');await draft(page);
 const method=page.locator('#route-check-method'),target=page.getByLabel('Адрес проверки');
 const planField=page.locator('#plan'),original=await planField.inputValue();
 await method.selectOption('https_status');
 for(const invalid of ['https://[','https:///path','https://example.invalid:99999/','https://example.invalid/a%','https://@example.invalid/']){
  await target.fill(invalid);await page.locator('#route-check-add').click();
  await expect(page.locator('#status')).toContainText('Проверьте поля');await expect(planField).toHaveValue(original);
 }
 await target.fill('https://service.example.invalid/ready');await page.locator('#route-check-add').click();
 await expect(page.locator('#route-check-list li')).toContainText('HEAD · 200');
 await expect(page.getByLabel('Ожидаемый код ответа')).toBeVisible();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);
});
test('mobile editor saves both exit country classes and removes only the selected predicate',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});
 await reset(request);await page.goto(origin+'/#draft-title');await draft(page);
 const method=page.getByLabel('Способ проверки'),target=page.getByLabel('Адрес проверки');
 const country=page.getByLabel('Расположение выхода'),add=page.getByRole('button',{name:'Добавить проверку'});
 const rows=page.locator('#route-check-list li'),input=page.locator('#plan');
 const original=await input.inputValue(),url='https://country.example.invalid:8443/';
 await expect(country).toBeHidden();await method.selectOption('https_exit_country');
 await target.fill(url);await add.click();await expect(input).toHaveValue(original);
 await country.selectOption('RU');
 for(const bad of ['http://country.example.invalid/','https://country.example.invalid/ip','https://country.example.invalid/?',
  'https://country.example.invalid/#','https://country.example.invalid/%2f','https://country.example.invalid/./',
  'https://user@country.example.invalid/','https://country.example.invalid:65536/']){
  await target.fill(bad);await add.click();await expect(input).toHaveValue(original);
 }
 await target.fill(url);await add.click();await expect(rows).toHaveCount(1);
 await target.fill(url);await add.click();await expect(rows).toHaveCount(1);
 await country.selectOption('NON_RU');await add.click();await expect(rows).toHaveCount(2);
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await input.fill('{}');await page.locator('#open-draft').click();await expect(rows).toHaveCount(2);
 expect(JSON.parse(await input.inputValue()).network.routeChecks[0].checks).toEqual(['RU','NON_RU'].map(expected_exit_class=>({
  method:'https_exit_country',target:url,expected_exit_class
 })));
 await rows.filter({hasText:'За пределами России'}).getByRole('button',{name:'Удалить проверку'}).click();
 await expect(rows).toHaveCount(1);await expect(rows).toContainText('· Россия');
 await method.selectOption('tcp');await expect(country).toBeHidden();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('structured route profile remains intact while editing another route and previewing the graph',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await draft(page);
 const input=page.locator('#plan'),selector=page.getByLabel('Выход',{exact:true}),add=page.getByRole('button',{name:'Добавить проверку'});
 const profile={schemaVersion:2,id:'home-health',revision:1,deadlineMs:3000,
  leaves:[{id:'home',check:{method:'tcp',target:'home.example.invalid:443'}}],gates:[],stages:[{leaf:'home'}]};
 const adaptive={metadataB64:'synthetic',bindingsB64:'synthetic',groups:{work:'adaptive-work'}};
 await input.fill(JSON.stringify({...plan,adaptive,network:{...plan.network,routeChecks:[{outbound:'proxy',required:true,profile}]}}));
 await selector.selectOption('proxy');await expect(page.getByText('Этот маршрут использует профиль проверок.',{exact:false})).toBeVisible();
 await expect(add).toBeDisabled();await expect(page.getByLabel('Способ проверки')).toBeDisabled();
 await expect(page.locator('#route-check-list')).toContainText('Профиль home-health');
 const required=page.getByLabel('Обязательная проверка при применении');await required.uncheck();
 await selector.selectOption('adaptive-work');await expect(add).toBeEnabled();await expect(page.locator('#route-profile-note')).toBeHidden();
 await page.getByLabel('Адрес проверки').fill('private.example.invalid:443');await add.click();
 const saved=JSON.parse(await input.inputValue()).network.routeChecks;
 expect(saved).toEqual([{outbound:'proxy',required:false,profile},{outbound:'adaptive-work',required:false,checks:[{method:'tcp',target:'private.example.invalid:443'}]}]);
 const bounds=page.getByRole('button',{name:'Оценить число цепочек'});await expect(bounds).toBeEnabled();
 await page.route('**/control/route-bounds',async route=>{
  expect(route.request().postDataJSON()).toEqual(adaptive);
  await route.fulfill({json:{status:'ready',limit:4096,intents:{INTERNAL:1},groups:[{group:'work',intent:'INTERNAL',upperBound:1,maxHops:1}]}});
 });
 await bounds.click();await expect(page.locator('#route-bounds-result')).toContainText('work');
 await input.fill(JSON.stringify({...plan,network:{...plan.network,routeChecks:[{outbound:'proxy',checks:[],profile}]}}));
 await expect(add).toBeDisabled();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(0);
});
test('mobile administrator groups route checks while TLS and exit evidence remain mandatory',async({page,request})=>{
 await page.setViewportSize({width:393,height:852});
 await reset(request);await page.goto(origin+'/#draft-title');await draft(page);
 const input=page.locator('#plan'),selector=page.locator('#route-check-path');
 const checks=[
  {method:'tls',target:'https://secure.example.invalid/'},
  {method:'https_exit_country',target:'https://country.example.invalid/',expected_exit_class:'RU'},
  {method:'tcp',target:'a.example.invalid:443'},{method:'tcp',target:'b.example.invalid:443'}
 ];
 const configured={...plan,network:{...plan.network,routeChecks:[{outbound:'direct',required:false,checks}]}};
 await input.fill(JSON.stringify(configured));await expect(selector).toHaveValue('proxy');
 await selector.selectOption('direct');await page.getByRole('button',{name:'Настроить условия проверок'}).click();
 await page.getByLabel('Как объединить проверки').selectOption('quorum');
 await page.getByLabel('Минимум успешных',{exact:true}).fill('1');await page.getByLabel('Общий тайм-аут, мс').fill('6500');
 let validated;
 await page.route('**/control/route-check-profile',async route=>{
  validated=route.request().postDataJSON();await route.fulfill({json:{valid:true}});
 });
 await page.getByRole('button',{name:'Применить условия к черновику'}).click();
 await expect(page.locator('#route-check-list')).toContainText('Профиль health-direct');
 expect(validated.gates).toEqual(['check-1','check-2']);expect(validated.deadlineMs).toBe(6500);
 expect(validated.stages).toEqual([{quorum:{k:1,of:[{leaf:'check-3'},{leaf:'check-4'}]}}]);
 const result=JSON.parse(await input.inputValue());
 expect(result.network.routeChecks).toEqual([{outbound:'direct',required:false,profile:validated}]);
 expect(result.graph).toEqual(configured.graph);
 await page.getByRole('button',{name:'Настроить условия проверок'}).click();
 await expect(page.getByLabel('Как объединить проверки')).toHaveValue('quorum');
 await page.getByLabel('Как объединить проверки').selectOption('any');
 await page.getByRole('button',{name:'Применить условия к черновику'}).click();
 await expect(page.locator('#route-profile-editor')).toBeHidden();
 expect(validated.revision).toBe(2);expect(validated.stages[0].any).toHaveLength(2);
 expect((await(await request.post(origin+'/fixture/state',{data:{}})).json()).operations).toBe(0);
});
test('complex profile stays editable and late validation cannot overwrite a changed draft',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await draft(page);
 const input=page.locator('#plan'),open=page.getByRole('button',{name:'Настроить условия проверок'});
 const leaves=['a','b','c'].map(id=>({id,check:{method:'tcp',target:id+'.example.invalid:443'}}));
 const profile={schemaVersion:2,id:'service',revision:4,deadlineMs:7000,leaves,gates:[],stages:[{any:[{leaf:'a'},{all:[{leaf:'b'},{leaf:'c'}]}]}]};
 const original=JSON.stringify({...plan,network:{...plan.network,routeChecks:[{outbound:'proxy',required:true,profile}]}});
 await input.fill(original);await open.click();
 const mode=page.getByLabel('Как объединить проверки'),advanced=page.getByLabel('Профиль проверок, JSON');
 await expect(mode).toHaveValue('custom');expect(JSON.parse(await advanced.inputValue())).toEqual({...profile,revision:5});
 await expect(mode.locator('option[value="all"]')).toBeDisabled();
 await page.getByRole('button',{name:'Отмена',exact:true}).click();
 await expect(input).toHaveValue(original);await open.click();
 let release;const hold=new Promise(resolve=>{release=resolve;});
 await page.route('**/control/route-check-profile',async route=>{await hold;await route.fulfill({json:{valid:true}});});
 const pending=page.waitForRequest('**/control/route-check-profile');
 await page.getByRole('button',{name:'Применить условия к черновику'}).click();await pending;
 const replacement=JSON.stringify(plan);
 await input.evaluate((field,value)=>{field.value=value;field.dispatchEvent(new Event('input',{bubbles:true}));},replacement);
 release();await expect(page.locator('#route-check-editor')).toBeEnabled();await expect(input).toHaveValue(replacement);
 await expect(advanced).toHaveValue('');
});
test('reserve probe cooldown requires explicit draft opt in and never publishes',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const box=page.locator('#route-reserve-cooldown'),input=page.locator('#plan');
 await expect(box).toBeDisabled();
 const fixture=structuredClone(plan);
 fixture.graph.profiles.reserve={sourceId:'source-a',profileId:'profile-b'};
 fixture.graph.balancers['internal']={type:'selector',members:['proxy','reserve'],default:'proxy',interruptExisting:false};
 fixture.network.routeFailover={selector:'internal',networkMode:'wifi',intent:'INTERNAL'};
 await input.fill(JSON.stringify(fixture,null,2));await expect(box).toBeEnabled();await expect(box).not.toBeChecked();
 await box.check();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldown).toBe(true);
 const rolloutId=page.locator('#route-rollout-id'),share=page.locator('#route-rollout-share');
 await rolloutId.fill('fixture-canary');await share.fill('12.34');await page.locator('#route-rollout-save').click();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldownRollout).toEqual({id:'fixture-canary',basisPoints:1234});
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await input.fill('{}');await page.locator('#open-draft').click();await expect(box).toBeChecked();
 await expect(rolloutId).toHaveValue('fixture-canary');await expect(share).toHaveValue('12.34');
 const control=page.locator('#route-rollout-control');
 await control.fill('10.25');await share.fill('100');await page.locator('#route-rollout-save').click();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldownRollout).toEqual({id:'fixture-canary',basisPoints:10000,controlBasisPoints:1025});
 const before=await input.inputValue();
 await control.fill('100.01');await page.locator('#route-rollout-save').click();
 expect(await input.inputValue()).toBe(before);await expect(control).toHaveValue('10.25');
 await share.fill('0');await page.locator('#route-rollout-save').click();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldownRollout.controlBasisPoints).toBe(1025);
 expect(JSON.parse(await input.inputValue()).network.routeFailover.probeCooldownRollout.basisPoints).toBe(0);
 await box.uncheck();const removed=JSON.parse(await input.inputValue()).network.routeFailover;
 expect(removed.probeCooldown).toBeUndefined();expect(removed.probeCooldownRollout).toBeUndefined();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('conservative failover and its cohort stay in the editable draft',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const selection=page.locator('#route-decision'),input=page.locator('#plan');
 await expect(selection).toBeDisabled();
 const fixture=structuredClone(plan);
 fixture.graph.profiles.reserve={sourceId:'source-a',profileId:'profile-b'};
 fixture.graph.balancers['internal']={type:'selector',members:['proxy','reserve'],default:'proxy',interruptExisting:false};
 fixture.network.routeFailover={selector:'internal',networkMode:'wifi',intent:'INTERNAL'};
 await input.fill(JSON.stringify(fixture));await expect(selection).toBeEnabled();
 await selection.selectOption('m4-confirmed-v1');
 const id=page.locator('#route-decision-id'),share=page.locator('#route-decision-share');
 const revision=page.locator('#program-revision'),count=page.locator('#program-confirmations'),interval=page.locator('#program-interval');
 await revision.fill('7');await count.fill('2');await interval.fill('87001');await page.locator('#program-save').click();
 expect(JSON.parse(await input.inputValue()).network.routeFailover.decisionProgram).toBeUndefined();
 await revision.fill('7');await count.fill('4');await interval.fill('87001');await page.locator('#program-save').click();
 await expect.poll(async()=>JSON.parse(await input.inputValue()).network.routeFailover.decisionProgram)
  .toEqual({revision:7,confirmations:4,minSwitchIntervalMs:87001});
 await id.fill('synthetic-algorithm');await share.fill('25.05');await page.locator('#route-decision-control').fill('8.75');await page.locator('#route-decision-save').click();
 await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toContainText('Версия черновика: 1');
 await input.fill('{}');await page.locator('#open-draft').click();await expect(selection).toHaveValue('m4-confirmed-v1');
 await expect(revision).toHaveValue('7');await expect(count).toHaveValue('4');await expect(interval).toHaveValue('87001');
 await expect(id).toHaveValue('synthetic-algorithm');await expect(share).toHaveValue('25.05');
 await expect(page.locator('#route-decision-control')).toHaveValue('8.75');
 expect(JSON.parse(await input.inputValue()).network.routeFailover.decisionRollout).toEqual({id:'synthetic-algorithm',basisPoints:2505,controlBasisPoints:875});
 await selection.selectOption('');
 const saved=JSON.parse(await input.inputValue()).network.routeFailover;
 expect(saved.decisionRevision).toBeUndefined();expect(saved.decisionRollout).toBeUndefined();expect(saved.decisionProgram).toBeUndefined();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('console safely renders source metadata and saves/reopens its private draft',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#sources-title');await expect(page.locator('#load-sources')).toBeEnabled();
 await page.locator('#owner').fill('synthetic-user');await page.locator('#load-sources').click();
 await expect(page.locator('#sources')).toContainText('<img src=x');expect(await page.evaluate(()=>window.injected)).toBeUndefined();expect(await page.locator('#sources img').count()).toBe(0);
 await page.getByRole('button',{name:'Показать профили'}).click();await expect(page.locator('#profiles')).toContainText('profile-a');await expect(page.locator('#source-details')).toContainText('snapshot-a');
 await page.locator('#more-sources').click();await expect(page.locator('#sources li')).toHaveCount(2);
 await page.getByRole('link',{name:'Черновики'}).click();
 await draft(page);await page.locator('#save-draft').click();await expect(page.locator('#draft-version')).toHaveText('Версия черновика: 1');
 await page.locator('#plan').fill('{}');await page.locator('#open-draft').click();await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan,null,2));
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);expect(state.calls).not.toContain('configuration.publish');
});
test('lost save response retries identical operation without another revision',async({page,request})=>{
 await reset(request,{failSave:true});await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);await page.locator('#save-draft').click();
 await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#plan')).toBeDisabled();await page.locator('#retry-save').click();
 await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#draft-version')).toHaveText('Версия черновика: 1');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);expect(state.drafts[0].revision).toBe(1);
});
test('invalid plan keeps edit available, revoked rights and logout clear private memory',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);await page.locator('#plan').fill('{"schemaVersion":1}');await page.locator('#save-draft').click();
 await expect(page.locator('#status')).toContainText('Проверьте поля');await expect(page.locator('#plan')).toBeEnabled();await expect(page.locator('#pending')).toBeHidden();
 await page.locator('#plan').fill(JSON.stringify(plan));await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#save-draft').click();
 await expect(page.locator('#status')).toContainText('Доступ отозван');await expect(page.locator('#plan')).toHaveValue('');await expect(page.locator('#save-draft')).toBeDisabled();
 await reset(request);await page.reload();await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);await page.locator('#logout').click();await expect(page.locator('#plan')).toHaveValue('');await expect(page.locator('#target-id')).toHaveValue('');
 expect(await page.evaluate(()=>localStorage.length)).toBe(0);expect(await page.evaluate(()=>sessionStorage.length)).toBe(0);
});
test('phone layout stays light and within viewport; expired session hides old data',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:360,height:800});await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);expect(await page.evaluate(()=>getComputedStyle(document.documentElement).colorScheme)).toBe('light');
 await request.post(origin+'/fixture/expire',{data:{}});await page.locator('#save-draft').click();await expect(page.locator('#status')).toContainText('Сессия завершена');await expect(page.locator('#plan')).toHaveValue('');
});

async function newSource(page){await page.locator('#owner').fill('synthetic-user');await page.locator('#new-source').click();await page.locator('#source-name').fill('Provider subscription');await page.locator('#source-secret-operation').selectOption('replace');await page.locator('#source-secret').fill(JSON.stringify({url:'https://provider.example.invalid/subscription'}));}
test('source editor saves metadata without exposing prior secrets and tracks sync job',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#sources-title');await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);const id=await page.locator('#source-id').inputValue();
 await page.locator('#save-source').click();await expect(page.locator('#source-version')).toContainText('Версия источника: 1');await expect(page.locator('#source-secret')).toHaveValue('');await expect(page.locator('#source-secret-operation')).toHaveValue('keep');
 await page.locator('#sync-source').click();await expect(page.locator('#job-status')).toContainText('queued');await page.locator('#source-job').click();await expect(page.locator('#job-status')).toContainText('succeeded');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.sources.find(s=>s.id===id).name).toBe('Provider subscription');expect(state.operations).toBe(2);expect(state.calls).not.toContain('configuration.publish');
 await page.locator('#load-sources').click();await page.locator('#sources li').filter({hasText:'Provider subscription'}).getByRole('button',{name:'Настроить источник'}).click();await expect(page.locator('#source-secret')).toHaveValue('');await expect(page.locator('#source-id')).toBeDisabled();
});
test('retiring a subscription clears abandoned secrets and sends only the removal',async({page,request})=>{
 await reset(request);await page.setViewportSize({width:390,height:820});await page.goto(origin+'/#sources-title');
 await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);
 await page.locator('#save-source').click();await expect(page.locator('#source-version')).toContainText('Версия источника: 1');
 const operation=page.locator('#source-secret-operation'), input=page.locator('#source-secret');
 await operation.selectOption('replace');await input.fill(JSON.stringify({url:'https://abandoned.example.invalid/'}));
 await operation.selectOption('keep');await expect(input).toHaveValue('');
 await operation.selectOption('replace');await expect(input).toHaveValue('');await input.fill('abandoned replacement');
 await operation.selectOption('delete');await expect(input).toHaveValue('');await expect(input).toBeDisabled();
 await expect(page.locator('#source-withdraw-hint')).toBeVisible();await expect(page.locator('#save-source')).toBeDisabled();
 await page.locator('#source-enabled').uncheck();await expect(page.locator('#save-source')).toBeEnabled();
 const outgoing=page.waitForRequest(r=>r.url().endsWith('/control/action')&&r.method()==='POST'&&r.postDataJSON()?.action==='source.put');
 await page.locator('#save-source').click();
 const sent=(await outgoing).postDataJSON();expect(sent.payload.secret).toEqual({operation:'delete'});expect(sent.payload.source.enabled).toBe(false);
 await expect(page.locator('#source-version')).toContainText('Версия источника: 2 · Источник отключён');
 await expect(page.locator('#source-secret-operation')).toHaveValue('keep');await expect(input).toHaveValue('');
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});
test('device subscription saves an immutable Wi-Fi binding without retaining the credential',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#sources-title');await expect(page.locator('#new-source')).toBeEnabled();
 await newSource(page);const id=await page.locator('#source-id').inputValue(),binding=page.locator('#source-device');
 await expect(binding).toBeHidden();
 await page.locator('#source-mode').selectOption('device');await expect(binding).toBeEnabled();
 await binding.fill('device-a');await page.locator('#source-modes').selectOption('cellular');
 await page.locator('#save-source').click();await expect(page.locator('#status')).toContainText('Проверьте');
 await page.locator('#source-modes').selectOption('wifi');await page.locator('#save-source').click();
 await expect(page.locator('#source-version')).toContainText('Версия источника: 1');
 await expect(binding).toHaveValue('device-a');await expect(binding).toBeDisabled();
 await expect(page.locator('#source-mode')).toBeDisabled();await expect(page.locator('#source-secret')).toHaveValue('');
 await page.locator('#sync-source').click();await expect(page.locator('#job-status')).toContainText('queued');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.sources.find(s=>s.id===id)).toMatchObject({mode:'device',fetchDeviceId:'device-a',networkModes:['wifi']});
 expect(state.calls.filter(call=>call==='source.put')).toHaveLength(1);
 expect(state.calls).not.toContain('configuration.publish');
 await page.locator('#logout').click();await expect(binding).toHaveValue('');await expect(binding).toBeHidden();
});
test('source mutation lost acknowledgment retries the same request and clears new secret on success',async({page,request})=>{
 await reset(request,{failSave:true});await page.goto(origin+'/#sources-title');await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);await page.locator('#save-source').click();await expect(page.locator('#pending')).toBeVisible();await expect(page.locator('#source-secret')).toBeDisabled();
 await page.locator('#retry-save').click();await expect(page.locator('#pending')).toBeHidden();await expect(page.locator('#source-version')).toContainText('Версия источника: 1');await expect(page.locator('#source-secret')).toHaveValue('');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.operations).toBe(1);expect(state.sources.filter(s=>s.name==='Provider subscription')).toHaveLength(1);
});
test('source permission withdrawal erases unsent credentials and disables mutation',async({page,request})=>{
 await reset(request);await page.goto(origin+'/#sources-title');await expect(page.locator('#new-source')).toBeEnabled();await newSource(page);await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#save-source').click();
 await expect(page.locator('#status')).toContainText('Доступ отозван');await expect(page.locator('#source-secret')).toHaveValue('');await expect(page.locator('#source-name')).toHaveValue('');await expect(page.locator('#save-source')).toBeDisabled();
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
});

test('desired device view keeps revision provenance and hostile content separate from activation',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#load-inventory')).toBeEnabled();
 await page.locator('#inventory-device').fill('device-a');await page.locator('#load-inventory').click();
 await expect(page.locator('#inventory-view')).toBeVisible();await expect(page.locator('#inventory-state')).toHaveText('Назначены · версия 7');
 await expect(page.locator('#inventory-meta')).toContainText('Желаемая версия7');await expect(page.locator('#inventory-meta')).toContainText('Версия выданной политики23');
 await expect(page.locator('#inventory-meta')).toContainText('Источник выданной политикиСоответствует желаемой');
 await expect(page.locator('#inventory-issued-algorithm')).toHaveText('Алгоритм m4-confirmed-v1');
 await expect(page.locator('#inventory-report')).toHaveText('Откат · политика 23');
 await expect(page.locator('#inventory-meta')).toContainText('Откат · политика 23');await expect(page.locator('#inventory-meta')).toContainText('Версия по отчёту21');
 await expect(page.locator('#inventory-meta')).toContainText('a'.repeat(64));
 await expect(page.locator('#inventory-layers')).toContainText('template-a');await expect(page.locator('#inventory-fields')).toContainText('/network/dnsStrategy');await expect(page.locator('#inventory-fields')).toContainText('template-a');
 await expect(page.locator('#inventory-restrictions')).toContainText('choice');await expect(page.locator('#inventory-effective')).toContainText('<img src=x');
 expect(await page.locator('#inventory-view img').count()).toBe(0);expect(await page.evaluate(()=>window.injected)).toBeUndefined();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();expect(state.calls).toContain('configuration.inventory.get');expect(state.calls).not.toContain('configuration.publish');expect(state.operations).toBe(0);
 await page.setViewportSize({width:360,height:800});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.locator('#logout').click();await expect(page.locator('#inventory-view')).toBeHidden();await expect(page.locator('#inventory-effective')).toHaveText('');
});

test('desired device view distinguishes unassigned expired and mismatched responses',async({page,request})=>{
 await reset(request);await page.goto(origin);await expect(page.locator('#load-inventory')).toBeEnabled();
 await page.locator('#inventory-device').fill('device-unassigned');await page.locator('#load-inventory').click();await expect(page.locator('#inventory-state')).toHaveText('Слои не назначены');await expect(page.locator('#inventory-effective')).toHaveText('Настройки из управляемых слоёв отсутствуют.');
 await page.getByText('Настройки выданной политики',{exact:true}).click();
 await expect(page.locator('#inventory-issued-config')).toBeVisible();
 await expect(page.locator('#inventory-issued-config')).toContainText('"routeFinal": "direct"');
 await expect(page.locator('#inventory-issued-algorithm')).toHaveText('Алгоритм m1-local-v1');
 await expect(page.locator('#layer-from-device')).toBeDisabled();
 await expect(page.locator('#inventory-meta')).toContainText('Ожидаем результат применения');
 await expect(page.locator('#inventory-meta')).toContainText('Источник не зафиксирован');
 await page.locator('#inventory-device').fill('device-expired');await page.locator('#load-inventory').click();await expect(page.locator('#inventory-state')).toHaveText('Срок назначения истёк · версия 7');
 await expect(page.locator('#inventory-meta')).toContainText('Откат · политика 22 · предыдущая или истёкшая выдача');
 await expect(page.locator('#inventory-meta')).toContainText('Выдана из другой ревизии');
 await expect(page.locator('#inventory-issued-algorithm')).toBeHidden();
 await expect(page.locator('#inventory-issued-algorithm')).toHaveText('');
 await page.locator('#inventory-device').fill('device-mismatch');await page.locator('#load-inventory').click();await expect(page.locator('#status')).toContainText('Проверьте поля');await expect(page.locator('#inventory-view')).toBeHidden();
 await page.locator('#inventory-device').fill('device-a');await page.locator('#load-inventory').click();await expect(page.locator('#inventory-view')).toBeVisible();
 await request.post(origin+'/fixture/revoke',{data:{}});await page.locator('#load-inventory').click();await expect(page.locator('#inventory-view')).toBeHidden();await expect(page.locator('#inventory-meta')).toHaveText('');
});


test('mobile inventory separates layer assignment from an issued policy and clears previous device details',async({page,request})=>{
 await reset(request);
 await page.setViewportSize({width:320,height:720});
 await page.goto(origin);
 const input=page.locator('#inventory-device'),note=page.locator('#inventory-assignment-note');
 async function select(device){
  await input.fill(device);
  await input.press('Enter');
 }
 await select('device-unassigned');
 await expect(page.getByRole('heading',{name:'Назначение управляемых слоёв'})).toBeVisible();
 await expect(note).toHaveText('Сервер выдал политику версии 3. Подробнее в разделе «Настройки выданной политики».');
 await expect(page.locator('#inventory-report')).toHaveText('Ожидаем результат применения');
 await page.getByText('Настройки выданной политики',{exact:true}).click();
 await expect(page.locator('#inventory-issued-config')).toContainText('m1-local-v1');
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await select('device-summary-only');
 await expect(note).toHaveText('Сервер выдал политику версии 3.');
 await expect(page.locator('#inventory-issued-settings')).toBeHidden();
 await expect(page.locator('#inventory-issued-config')).toHaveText('');
 await select('device-no-policy');
 await expect(page.locator('#inventory-issued')).toHaveText('Ещё не выдана');
 await expect(note).toBeHidden();
 await expect(note).toHaveText('');
 await select('device-unassigned');
 await expect(note).toBeVisible();
 await request.post(origin+'/fixture/revoke',{data:{}});
 await page.locator('#load-inventory').click();
 await expect(page.locator('#inventory-view')).toBeHidden();
 await expect(note).toHaveText('');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);
});

test('device workspace is private until sign in and opens a safe linked device',async({page,request})=>{
 await reset(request);
 await page.route('**/session',route=>route.fulfill({status:401,json:{}}));
 await page.goto(origin+'/#device=device-a');
 await expect(page.locator('#status')).toHaveText('Войдите с административной учётной записью.');
 await expect(page.locator('#login')).toBeEnabled();
 await expect(page.locator('#workspace')).toBeHidden();
 let state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls).not.toContain('configuration.inventory.get');
 await page.unroute('**/session');
 await page.reload();
 await expect(page.locator('#inventory-view')).toBeVisible();
 await expect(page.locator('#inventory-device')).toHaveValue('device-a');
 await expect(page.locator('#inventory-issued')).toHaveText('Версия 23');
 await expect(page.locator('#inventory-report-time')).toHaveAttribute('datetime',/^20/);
 expect(await page.evaluate(()=>localStorage.length+sessionStorage.length)).toBe(0);
 await page.goto(origin+'/#device=bad%2Fid');
 await page.reload();
 await expect(page.locator('#workspace')).toBeVisible();
 await expect(page.locator('#inventory-device')).toHaveValue('');
 await expect(page.locator('#inventory-view')).toBeHidden();
 state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls.filter(call=>call==='configuration.inventory.get')).toHaveLength(1);
 expect(state.operations).toBe(0);
});

test('mobile device form submits by keyboard and cannot keep a stale device selected',async({page,request})=>{
 await reset(request);
 await page.setViewportSize({width:360,height:800});
 await page.goto(origin+'/#draft-title');
 const input=page.locator('#inventory-device'),view=page.locator('#inventory-view');
 await expect(page.locator('#console-nav-toggle')).toBeVisible();
 await draft(page);
 await page.locator('#console-nav-toggle').click();
 await page.getByRole('link',{name:'Устройства'}).click();
 await expect(input).toBeEnabled();
 await input.fill('device-a');
 await input.press('Enter');
 await expect(view).toBeVisible();
 await expect(page.locator('#inventory-status')).toHaveText('Конфигурация загружена.');
 await expect(page.locator('#inventory-details')).not.toHaveAttribute('open','');
 await expect(page.locator('#layer-from-device')).toBeEnabled();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await input.fill('device-unassigned');
 await expect(view).toBeHidden();
 await expect(page.locator('#layer-from-device')).toBeDisabled();
 await expect(page.locator('#inventory-meta')).toHaveText('');
 await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan,null,2));
 await input.press('Enter');
 await expect(page.locator('#inventory-state')).toHaveText('Слои не назначены');
 await expect(page.locator('#layer-from-device')).toBeDisabled();
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls.filter(call=>call==='configuration.inventory.get')).toHaveLength(2);
 expect(state.operations).toBe(0);
});

async function rgbContrast(locator,background){
 return locator.evaluate((node,fallback)=>{
  const rgb=value=>value.match(/[0-9.]+/g).slice(0,3).map(Number);
  const luminance=channels=>channels.map(value=>value/255).map(value=>value<=0.04045?value/12.92:((value+0.055)/1.055)**2.4).reduce((total,value,index)=>total+value*[0.2126,0.7152,0.0722][index],0);
  const style=getComputedStyle(node),surface=style.backgroundColor==='rgba(0, 0, 0, 0)'?getComputedStyle(document.querySelector(fallback)).backgroundColor:style.backgroundColor;
  const values=[luminance(rgb(style.color)),luminance(rgb(surface))].sort((a,b)=>b-a);
  return (values[0]+0.05)/(values[1]+0.05);
 },background);
}

test('console shell keeps the active section and keyboard focus visible on desktop',async({page,request})=>{
 await reset(request);
 await page.setViewportSize({width:1440,height:960});
 await page.goto(origin+'/#device=device-a');
 const nav=page.getByRole('navigation',{name:'Разделы управления'});
 await expect(page.getByRole('heading',{level:1,name:'Устройства'})).toBeVisible();
 await expect(nav.getByRole('group',{name:'Главная'}).getByRole('link',{name:'Устройства'})).toHaveAttribute('aria-current','page');
 await expect(nav.getByRole('group',{name:'Конфигурация'}).getByRole('link')).toHaveCount(3);
 await expect(nav.getByRole('group',{name:'Наблюдение'}).getByRole('link',{name:'Телеметрия'})).toBeVisible();
 const toggle=page.locator('#desktop-nav-toggle');
 await expect(toggle).toHaveAttribute('aria-expanded','true');
 await toggle.press('Enter');
 await expect(toggle).toHaveAttribute('aria-expanded','false');
 await expect(nav).toBeHidden();
 await expect(page.locator('#inventory-view')).toBeVisible();
 await toggle.press('Enter');
 await expect(toggle).toHaveAttribute('aria-expanded','true');
 await expect(nav).toBeVisible();
 await expect(page.locator('#inventory-view')).toBeVisible();
 await expect(page.locator('#inventory-state')).toHaveAttribute('data-tone','success');
 await expect(page.locator('#inventory-issued')).toHaveAttribute('data-tone','info');
 await expect(page.locator('#inventory-report')).toHaveAttribute('data-tone','danger');
 for(const item of await nav.getByRole('link').all())expect(await rgbContrast(item,'#console-navigation')).toBeGreaterThanOrEqual(4.5);
 for(const heading of await nav.getByRole('heading').all())expect(await rgbContrast(heading,'#console-navigation')).toBeGreaterThanOrEqual(4.5);
 await expect(page.locator('#logout')).toBeEnabled();
 // PatternFly animates the disabled-to-enabled surface. Measure its settled
 // interactive state, retaining the same minimum contrast requirement.
 await expect.poll(()=>rgbContrast(page.locator('#logout'),'.masthead')).toBeGreaterThanOrEqual(4.5);
 await page.screenshot({path:'test-results/console-visual/desktop.png',animations:'disabled'});
 const skip=page.getByRole('link',{name:'К рабочей области'});
 await skip.focus();
 await skip.press('Enter');
 await expect(page.locator('#workspace')).toBeFocused();
 const sources=nav.getByRole('link',{name:'Источники'});
 await sources.focus();
 await sources.press('Enter');
 await expect(sources).toHaveAttribute('aria-current','page');
 await expect(nav.getByRole('link',{name:'Устройства'})).not.toHaveAttribute('aria-current','page');
 await expect(page.locator('#sources-title')).toBeFocused();
 await expect(page.locator('#inventory-title')).toBeHidden();
 await expect(page.locator('#workspace .workspace-page:visible')).toHaveCount(1);
 const geometry=await page.evaluate(()=>{
  const top=id=>document.getElementById(id).getBoundingClientRect().top;
  return {heading:top('sources-title'),banner:document.getElementById('status').getBoundingClientRect().bottom};
 });
 expect(geometry.heading).toBeGreaterThanOrEqual(geometry.banner);
 await page.goBack();
 await expect(nav.getByRole('link',{name:'Устройства'})).toHaveAttribute('aria-current','page');
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);
});

test('console shell fits a narrow screen and retains a keyboard scroll region',async({page,request})=>{
 page.setDefaultTimeout(8000);
 await reset(request);
 await page.setViewportSize({width:320,height:900});
 const hosts=new Set();
 page.on('request',request=>hosts.add(new URL(request.url()).origin));
 await page.goto(origin+'/#device=device-a');
 const nav=page.getByRole('navigation',{name:'Разделы управления'});
 await expect(page.locator('#inventory-view')).toBeVisible();
 const toggle=page.locator('#console-nav-toggle');
 await expect(toggle).toHaveAttribute('aria-expanded','false');
 await expect(nav).toBeHidden();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 const menu=await toggle.boundingBox();
 const menuIcon=await toggle.locator('svg.pf-v6-svg').boundingBox();
 const brand=await page.locator('.masthead .brand').boundingBox();
 const logout=await page.locator('#logout').boundingBox();
 const masthead=await page.locator('.masthead').boundingBox();
 expect(masthead.height).toBeLessThanOrEqual(72);
 expect(menu.width).toBeGreaterThanOrEqual(44);
 expect(Math.abs(menuIcon.y+menuIcon.height/2-menu.y-menu.height/2)).toBeLessThan(2);
 expect(menu.x+menu.width).toBeLessThanOrEqual(brand.x);
 expect(logout.x).toBeGreaterThan(brand.x+brand.width);
 expect(Math.abs(logout.y+logout.height/2-brand.y-brand.height/2)).toBeLessThan(4);
 const report=await page.locator('#inventory-report-time').boundingBox();
 expect(report.y+report.height).toBeLessThanOrEqual(900);
 await page.screenshot({path:'test-results/console-visual/mobile.png',animations:'disabled',timeout:8000});
 await toggle.press('Enter');
 await expect(toggle).toHaveAttribute('aria-expanded','true');
 await expect(nav.getByRole('link')).toHaveText(['Устройства','Приглашения','Источники','Черновики','Публикация','Телеметрия','Чат поддержки']);
 const telemetry=nav.getByRole('link',{name:'Телеметрия'});
 const target=await telemetry.boundingBox();
 expect(target.height).toBeGreaterThanOrEqual(44);
 await telemetry.focus();
 await telemetry.press('Escape');
 await expect(toggle).toBeFocused();
 await expect(nav).toBeHidden();
 await toggle.click();
 await telemetry.click();
 await expect(toggle).toHaveAttribute('aria-expanded','false');
 await expect(toggle).toHaveAccessibleName('Разделы: Телеметрия');
 await page.locator('#telemetry-hour').fill('2026-01-02T01:00');
 await page.locator('#load-telemetry').click();
 await expect(page.locator('#telemetry-rows').locator('tr')).toHaveCount(1);
 const table=page.getByRole('region',{name:'Таблица технической телеметрии'});
 await table.focus();
 await expect(table).toBeFocused();
 expect(await table.evaluate(el=>el.scrollWidth>el.clientWidth)).toBe(true);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 expect([...hosts]).toEqual([origin]);
});

test('console sign-in is the only entry when no session is present',async({page,request})=>{
 await reset(request);
 await request.post(origin+'/fixture/expire',{data:{}});
 await page.setViewportSize({width:390,height:844});
 await page.goto(origin+'/#device=device-a');
 const login=page.getByRole('button',{name:'Войти через Keycloak'});
 await expect(page.getByRole('heading',{level:1,name:'Вход в панель управления'})).toBeVisible();
 await expect(login).toBeEnabled();
 await expect(page.locator('#workspace')).toBeHidden();
 await expect(page.locator('#console-nav')).toBeHidden();
 await expect(page.getByRole('button',{name:'Выйти'})).toHaveCount(0);
 await page.keyboard.press('Tab');
 await expect(login).toBeFocused();
 await page.screenshot({path:'test-results/console-visual/signin.png',animations:'disabled'});
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.calls).toEqual([]);
});

test('PatternFly resources are same-origin and section history keeps an unsaved draft',async({page,request})=>{
 await reset(request);
 const assetResponses=new Map(),failures=[];
 page.on('response',response=>{
  const url=new URL(response.url());
  if(url.pathname.startsWith('/ui/'))assetResponses.set(url.href,response.status());
 });
 page.on('pageerror',error=>failures.push(error.message));
 page.on('console',message=>{if(message.type()==='error')failures.push(message.text());});
 await page.goto(origin+'/#draft-title');
 await expect(page.locator('header.pf-v6-c-masthead')).toBeVisible();
 await expect(page.locator('nav.pf-v6-c-nav')).toBeVisible();
 await expect(page.locator('#save-draft.pf-v6-c-button')).toBeEnabled();
 await expect(page.locator('#plan').locator('..')).toHaveClass(/pf-v6-c-form-control/);
 await draft(page);
 const nav=page.getByRole('navigation',{name:'Разделы управления'});
 await nav.getByRole('link',{name:'Источники'}).click();
 await expect(page.locator('#sources-title')).toBeFocused();
 await expect(page.locator('#draft-title')).toBeHidden();
 await expect(nav.getByRole('link',{name:'Источники'})).toHaveClass(/pf-m-current/);
 await page.goBack();
 await expect(page.locator('#draft-title')).toBeFocused();
 await expect(page.locator('#plan')).toHaveValue(JSON.stringify(plan,null,2));
 await page.goForward();
 await expect(page.locator('#sources-title')).toBeFocused();
 await page.evaluate(()=>document.fonts.ready.then(()=>true));
 expect(assetResponses.get(origin+'/ui/console.js')).toBe(200);
 expect(assetResponses.get(origin+'/ui/console.css')).toBe(200);
 expect([...assetResponses].some(([url,status])=>url.startsWith(origin+'/ui/')&&url.endsWith('.woff2')&&status===200)).toBe(true);
 expect([...assetResponses].every(([url,status])=>url.startsWith(origin+'/ui/')&&status===200)).toBe(true);
 expect(failures).toEqual([]);
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);
});


async function openCohortDraft(page,request){
 await reset(request);await page.setViewportSize({width:393,height:852});
 await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const fixture=structuredClone(plan);
 fixture.graph.profiles.reserve={sourceId:'source-a',profileId:'profile-b'};
 fixture.graph.balancers['internal']={type:'selector',members:['proxy','reserve'],default:'proxy',interruptExisting:false};
 fixture.network.routeFailover={selector:'internal',networkMode:'wifi',intent:'INTERNAL',probeCooldown:true,
  decisionRevision:'m4-confirmed-v1',decisionRollout:{id:'fixture-canary',basisPoints:2129,controlBasisPoints:2873},
  probeCooldownRollout:{id:'fixture-canary',basisPoints:2129,controlBasisPoints:2873}};
 await page.locator('#plan').fill(JSON.stringify(fixture,null,2));
 await expect(page.getByLabel('ID устройства для предпросмотра группы')).toBeVisible();
}
test('phone previews treatment baseline and permanent control from unsaved fields',async({page,request})=>{
 await openCohortDraft(page,request);
 const planBefore=await page.locator('#plan').inputValue(),requests=[];
 await page.route('**/control/rollout-preview',async route=>{
  const body=route.request().postDataJSON();requests.push(body);
  await route.fulfill({json:body.device==='synthetic-b'?{decision:'control',probeCooldown:'control'}:{decision:'treatment',probeCooldown:'baseline'}});
 });
 const device=page.getByLabel('ID устройства для предпросмотра группы'),run=page.getByRole('button',{name:'Проверить группу'}),result=page.locator('#cohort-result');
 await device.fill('synthetic-a');await run.click();
 await expect(result).toContainText('Алгоритм переключения - тестовая версия');
 await expect(result).toContainText('Пауза проверок резервного маршрута - базовая версия вне контрольной группы');
 await page.locator('#route-decision-share').fill('55.23');await expect(result).toBeEmpty();
 await device.fill('synthetic-b');await run.click();
 await expect(result.locator('li')).toHaveCount(2);
 await expect(result.locator('li').first()).toContainText('постоянная контрольная группа');
 await expect(result.locator('li').last()).toContainText('постоянная контрольная группа');
 expect(requests[1]).toEqual({device:'synthetic-b',decision:{id:'fixture-canary',basisPoints:5523,controlBasisPoints:2873},probeCooldown:{id:'fixture-canary',basisPoints:2129,controlBasisPoints:2873}});
 expect(await page.locator('#plan').inputValue()).toBe(planBefore);
 const state=await(await request.post(origin+'/fixture/state',{data:{}})).json();
 expect(state.operations).toBe(0);expect(state.calls).not.toContain('configuration.publish');
});
test('phone drops a late cohort preview after a change of target',async({page,request})=>{
 await openCohortDraft(page,request);
 let entered,release;const started=new Promise(ok=>entered=ok),gate=new Promise(ok=>release=ok);
 await page.route('**/control/rollout-preview',async route=>{
  entered();await gate;
  await route.fulfill({json:{decision:'treatment',probeCooldown:'control'}}).catch(()=>{});
 });
 await page.locator('#cohort-device').fill('synthetic-a');await page.locator('#cohort-run').click();await started;
 await page.locator('#target-id').fill('device-b');release();
 await expect(page.locator('#cohort-device')).toHaveValue('');await expect(page.locator('#cohort-result')).toBeEmpty();
 await expect(page.locator('#cohort-run')).toBeDisabled();
});

test('phone reads the issued NetBird network and distinguishes direct from emergency VLESS',async({page,request})=>{
 const binding={tag:'mesh',overlayId:'home',resourceId:'provider-a',networkId:'network-a'};
 await openIssuedPaths(page,request,{routeFinal:'mesh',outbounds:[{tag:'mesh',type:'netbird'}],netbird:{...binding,transport:'direct'}});
 const steps=page.locator('#issued-path-steps li');
 await expect(steps).toHaveCount(1);await expect(steps.first()).toContainText('транспорт по политике: прямое соединение');
 await expect(steps.first()).toContainText('сеть: network-a · ресурс: provider-a · подключение: home');
 await page.unroute('**/control/action');await page.goto('about:blank');
 await openIssuedPaths(page,request,{routeFinal:'mesh',outbounds:[{tag:'mesh',type:'netbird',detour:'entry'},{tag:'entry',type:'vless'}],netbird:{...binding,transport:'vless'}});
 await expect(steps).toHaveCount(2);await expect(steps.first()).toContainText('entry · VLESS');
 await expect(steps.last()).toContainText('транспорт по политике: через VLESS (entry)');
 await expect(steps.last()).not.toContainText(/подключено|relay|P2P/i);
});
test('phone keeps a historical NetBird summary unknown and ignores another overlay tag',async({page,request})=>{
 const legacy={routeFinal:'mesh',outbounds:[{tag:'mesh',type:'netbird'}]};
 for(const extra of [{},{netbird:{tag:'other-mesh',transport:'direct',networkId:'other-network',overlayId:'home',resourceId:'provider-a'}}]){
  await openIssuedPaths(page,request,{...legacy,...extra});
  const steps=page.locator('#issued-path-steps');
  await expect(steps).toContainText('транспорт не указан в сохранённой сводке');
  await expect(steps).not.toContainText(/прямое соединение|other-network/i);
  await page.unroute('**/control/action');await page.goto('about:blank');
 }
});

async function editHomeProof(page,request){
 await reset(request);await page.setViewportSize({width:393,height:852});
 await page.goto(origin+'/#draft-title');await expect(page.locator('#save-draft')).toBeEnabled();await draft(page);
 const adaptive={metadataB64:'synthetic',bindingsB64:'synthetic',groups:{work:'adaptive-work'}};
 const document={...structuredClone(plan),adaptive};
 await page.locator('#plan').fill(JSON.stringify(document));
 await expect(page.getByRole('group',{name:'Проверка домашнего Wi-Fi'})).toBeVisible();
 return document;
}
test('phone changes only the home TLS endpoint in an unpublished adaptive draft',async({page,request})=>{
 const original=await editHomeProof(page,request);
 const address=['10','61','1','4'].join('.'),hostname='proof.example.invalid',pin='A'.repeat(43);
 await page.getByLabel('Локальный IP-адрес').fill(address);
 await page.getByLabel('Имя узла в сертификате').fill(hostname);
 await page.getByLabel('Порт TLS').fill('8443');
 await page.getByLabel('Отпечаток ключа сертификата').fill(pin);
 await page.getByRole('button',{name:'Записать узел в черновик'}).click();
 await expect(page.locator('#home-feedback')).toHaveText('Узел записан в черновик.');
 const expected=structuredClone(original);expected.network.homeProof={address,hostname,port:8443,spkiSha256:pin};
 expect(JSON.parse(await page.locator('#plan').inputValue())).toEqual(expected);
 await page.getByRole('button',{name:'Удалить узел из черновика'}).click();
 expect(JSON.parse(await page.locator('#plan').inputValue())).toEqual(original);
 await expect(page.getByLabel('Имя узла в сертификате')).toHaveValue('');
 expect((await(await request.post(origin+'/fixture/state',{data:{}})).json()).operations).toBe(0);
});
test('phone rejects invalid home credentials and clears unsaved fields on a target change',async({page,request})=>{
 const original=await editHomeProof(page,request),raw=await page.locator('#plan').inputValue();
 const address=page.getByLabel('Локальный IP-адрес'),hostname=page.getByLabel('Имя узла в сертификате');
 const port=page.getByLabel('Порт TLS'),pin=page.getByLabel('Отпечаток ключа сертификата');
 const apply=page.getByRole('button',{name:'Записать узел в черновик'});
 await hostname.fill('proof.example.invalid');await port.fill('443');await pin.fill('A'.repeat(43));
 for(const invalid of ['127.0.0.1','2001:db8::1','fd13::1%wlan0','0x0a000001']){
  await address.fill(invalid);await apply.click();await expect(address).toBeFocused();await expect(page.locator('#plan')).toHaveValue(raw);
 }
 await address.fill('fd13::2');await pin.fill('A'.repeat(42)+'B');await apply.click();
 await expect(pin).toBeFocused();await expect(page.locator('#plan')).toHaveValue(raw);
 await page.locator('#target-id').fill('other-synthetic-device');
 await expect(pin).toHaveValue('');await expect(address).toHaveValue('');await expect(hostname).toHaveValue('');
 const regular=structuredClone(original);delete regular.adaptive;
 await page.locator('#plan').fill(JSON.stringify(regular));await expect(page.locator('#home-proof')).toBeHidden();
 expect((await(await request.post(origin+'/fixture/state',{data:{}})).json()).operations).toBe(0);
});

test('phone assigns a preferred mode and bounded temporary permission in the local draft',async({page,request})=>{
 const original=await editHomeProof(page,request);
 await page.getByLabel('Режим по умолчанию').selectOption('WIFI');
 await page.locator('#mode-allow-WIFI').check();
 await page.getByLabel('Максимальный срок выбора в минутах').fill('45');
 await page.getByRole('button',{name:'Записать режим в черновик'}).click();
 const expected=structuredClone(original);
 expected.network.modeSelection={preferredMode:'WIFI',userModes:['WIFI'],maxOverrideMinutes:45};
 expect(JSON.parse(await page.locator('#plan').inputValue())).toEqual(expected);
 await page.locator('#mode-allow-WIFI').uncheck();
 await expect(page.locator('#mode-minutes')).toBeDisabled();
 await page.locator('#mode-apply').click();
 expected.network.modeSelection={preferredMode:'WIFI',userModes:[],maxOverrideMinutes:0};
 expect(JSON.parse(await page.locator('#plan').inputValue())).toEqual(expected);
 await page.getByRole('button',{name:'Убрать назначение режима'}).click();
 expect(JSON.parse(await page.locator('#plan').inputValue())).toEqual(original);
 expect((await(await request.post(origin+'/fixture/state',{data:{}})).json()).operations).toBe(0);
});
test('phone rejects unverified home selection and drops stale mode edits when the recipient changes',async({page,request})=>{
 await editHomeProof(page,request);
 const raw=await page.locator('#plan').inputValue();
 await page.locator('#mode-allow-HOME_WIFI').check();
 await page.locator('#mode-apply').click();
 await expect(page.locator('#mode-feedback')).toContainText('Сначала укажите узел');
 await expect(page.locator('#plan')).toHaveValue(raw);
 await page.locator('#mode-allow-HOME_WIFI').uncheck();
 await page.locator('#mode-allow-WIFI').check();await page.locator('#mode-minutes').fill('1441');
 await page.locator('#mode-apply').click();await expect(page.locator('#mode-minutes')).toBeFocused();
 await expect(page.locator('#plan')).toHaveValue(raw);
 await page.locator('#target-id').fill('other-synthetic-device');
 await expect(page.locator('#mode-allow-WIFI')).not.toBeChecked();
 await expect(page.locator('#mode-minutes')).toBeDisabled();
 expect((await(await request.post(origin+'/fixture/state',{data:{}})).json()).operations).toBe(0);
});
