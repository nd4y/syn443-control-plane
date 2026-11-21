import {Button, PageSection, TextInput, Title} from '@patternfly/react-core';
import qrcode from 'qrcode-generator';

export function Invitations() {
  return <PageSection hasBodyWrapper={false} className="workspace-page" aria-labelledby="invites-title" hidden>
    <Title headingLevel="h1" size="2xl" id="invites-title" tabIndex={-1}>Приглашения</Title>
    <form id="invite-issue-form" autoComplete="off">
      <fieldset id="invite-issue-fields"><legend>Привязать новое устройство</legend>
        <label htmlFor="invite-owner">ID получателя</label>
        <TextInput id="invite-owner" maxLength={43} isRequired />
        <label htmlFor="invite-grant">Отпечаток назначения получателя</label>
        <TextInput id="invite-grant" maxLength={43} isRequired />
        <label htmlFor="invite-service">Сервис привязки</label>
        <TextInput id="invite-service" maxLength={64} isRequired />
        <label htmlFor="invite-revision">Версия описания сервиса</label>
        <input id="invite-revision" type="number" min="1" step="1" required />
        <label htmlFor="invite-ttl">Срок ссылки, минут</label>
        <input id="invite-ttl" type="number" min="1" max="10" step="1" defaultValue="10" required />
        <Button type="submit" variant="primary">Выпустить приглашение</Button>
      </fieldset>
    </form>
    <div id="invite-delivery" hidden>
      <p id="invite-expiry" />
      <canvas id="invite-qr" role="img" aria-label="QR для привязки устройства" />
      <p id="invite-qr-notice" hidden>Ссылка слишком длинная для одного QR. Передайте её получателю целиком.</p>
      <label htmlFor="invite-link">Одноразовая ссылка</label>
      <textarea id="invite-link" rows={3} readOnly autoComplete="off" spellCheck={false} />
      <Button id="invite-conceal" type="button" variant="link">Скрыть ссылку и QR</Button>
    </div>
    <form id="invite-read-form" autoComplete="off">
      <label htmlFor="invite-id">ID приглашения</label>
      <TextInput id="invite-id" maxLength={43} isRequired />
      <Button id="invite-inspect" type="submit" variant="secondary">Проверить состояние</Button>
    </form>
    <div id="invite-view" hidden>
      <p id="invite-detail" />
      <div id="invite-pair" hidden>
        <label htmlFor="invite-pair-code">Код с экрана нового устройства</label>
        <TextInput id="invite-pair-code" autoComplete="off" inputMode="numeric" maxLength={6} />
        <Button id="invite-approve" type="button" variant="primary">Подтвердить привязку</Button>
      </div>
      <Button id="invite-revoke" type="button" variant="secondary">Отозвать приглашение</Button>
    </div>
    <div id="invite-confirm" hidden>
      <p id="invite-confirm-text" />
      <Button id="invite-confirm-yes" type="button" variant="primary">Подтвердить действие</Button>
      <Button id="invite-confirm-no" type="button" variant="link">Отмена</Button>
    </div>
    <div id="invite-pending" hidden>
      <p>Ответ не получен. Повтор использует тот же запрос.</p>
      <Button id="invite-retry" type="button" variant="secondary">Повторить запрос</Button>
    </div>
    <p id="invite-status" role="status" aria-live="polite" />
  </PageSection>;
}

const opaque = /^[A-Za-z0-9_-]{43}$/;
const states = {issued:'Ожидает открытия на телефоне',pending_approval:'Ожидает подтверждения кода',
  provisioning:'Конфигурация готовится',ready:'Конфигурация готова',completed:'Привязка завершена',
  expired:'Истёк срок',revoked:'Приглашение отозвано'};

function drawQR(canvas,link) {
  // Four modules of quiet zone on all sides. No request or data URL carries the link.
  for(const level of ['M','L']){
    const qr=qrcode(0,level);
    try{qr.addData(link,'Byte');qr.make();}catch{continue;}
    const modules=qr.getModuleCount(),scale=4;
    canvas.width=canvas.height=(modules+8)*scale;
    const ctx=canvas.getContext('2d');
    if(!ctx)return false;
    ctx.fillStyle='white';ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle='black';
    for(let row=0;row<modules;row++)for(let col=0;col<modules;col++)
      if(qr.isDark(row,col))ctx.fillRect((col+4)*scale,(row+4)*scale,scale,scale);
    return true;
  }
  return false;
}

function validLink(value,service) {
  if(typeof value!=='string'||value.length>8192||!/^[!-~]+$/.test(value)||!value.startsWith('syn443://enroll/v1?'))return false;
  try{
    const u=new URL(value),p=u.searchParams;
    if(u.hash||[...p.keys()].sort().join(',')!=='bootstrap,code,origin,service'||p.get('service')!==service||
      !opaque.test(p.get('code'))||!p.get('bootstrap'))return false;
    const origin=new URL(p.get('origin'));
    return origin.protocol==='https:'&&!origin.username&&!origin.password&&origin.origin===p.get('origin');
  }catch{return false;}
}

export function connectInvitations(send) {
  const $=name=>document.getElementById('invite-'+name);
  const section=$('status').closest('.workspace-page'),workspace=document.getElementById('workspace');
  const visible=()=>!document.hidden&&!section.hidden&&!workspace.hidden;
  const now=()=>Math.floor(Date.now()/1000);
  let epoch=0,active=null,pending=null,confirm=null,view=null,expiry=null,wasVisible=visible();
  function message(text){$('status').textContent=text;}
  function conceal(){
    clearTimeout(expiry);expiry=null;$('link').value='';$('expiry').textContent='';
    $('qr').width=$('qr').height=0;$('delivery').hidden=true;
  }
  function controls(){
    const locked=!!(active||pending||confirm);
    $('issue-fields').disabled=locked;$('id').disabled=locked;$('inspect').disabled=locked;
    $('pair-code').disabled=locked;$('revoke').disabled=locked;
    $('approve').disabled=locked||!view||!/^\d{6}$/.test($('pair-code').value);
    $('pending').hidden=!pending||!!active;$('confirm').hidden=!confirm;
  }
  function clearView(){view=null;$('detail').textContent='';$('pair-code').value='';$('view').hidden=true;}
  function reset(keepIssue=false){
    const retry=keepIssue&&pending?.action==='invite.issue'&&pending.payload.expires>now()?pending:null;
    const rememberedId=keepIssue&&opaque.test($('id').value)?$('id').value:'';
    epoch++;active?.abort();active=null;pending=retry;confirm=null;clearView();conceal();
    $('confirm-text').textContent='';$('issue-form').reset();$('read-form').reset();message('');controls();
    $('id').value=rememberedId;
  }
  function sync(){
    const next=visible();if(wasVisible&&!next)reset(!workspace.hidden);
    if(next&&pending?.action==='invite.issue'&&pending.payload.expires<=now()){pending=null;controls();}
    wasVisible=next;
  }
  const observer=new MutationObserver(sync);
  for(const element of [workspace,section])observer.observe(element,{attributes:true,attributeFilter:['hidden']});
  document.addEventListener('visibilitychange',sync);
  window.addEventListener('syn443-console-session-ended',()=>reset());
  window.addEventListener('pagehide',event=>reset(event.persisted&&!workspace.hidden));
  window.addEventListener('pageshow',sync);
  function showView(result,id){
    if(result?.id!==id||!opaque.test(result.owner)||!Number.isSafeInteger(result.version)||result.version<1||
      !Number.isSafeInteger(result.expires)||!Object.hasOwn(states,result.state))throw Error('invalid_reply');
    const canPair=result.state==='pending_approval'&&result.expires>now();
    if(canPair&&(!opaque.test(result.thumbprint)||!/^\d{6}$/.test(result.pairCode)))throw Error('invalid_reply');
    view={id,version:result.version,state:result.state,expires:result.expires,owner:result.owner,
      thumbprint:canPair?result.thumbprint:'',pairCode:canPair?result.pairCode:''};
    $('view').hidden=false;$('pair').hidden=!canPair;$('pair-code').value='';
    $('detail').textContent=states[result.state]+' · Получатель '+result.owner+(canPair?' · Отпечаток устройства '+result.thumbprint:'');
    $('revoke').hidden=!['issued','pending_approval','provisioning','ready'].includes(result.state)||result.expires<=now();
    if(result.state!=='issued')conceal();
  }
  function showIssued(result,body){
    const input=body.payload;
    if(!opaque.test(result?.id)||result.version!==1||result.expires!==input.expires||result.expires<=now()||
      !validLink(result.link,input.serviceId))throw Error('invalid_reply');
    clearView();conceal();$('id').value=result.id;
    $('link').value=result.link;$('qr').hidden=!drawQR($('qr'),result.link);$('qr-notice').hidden=!$('qr').hidden;
    $('expiry').textContent='Одно устройство. Ссылка действует до '+new Date(result.expires*1000).toLocaleTimeString('ru-RU')+'.';
    $('delivery').hidden=false;expiry=setTimeout(conceal,Math.max(0,result.expires*1000-Date.now()));
  }
  function body(action,payload){return {version:1,action:'invite.'+action,requestId:crypto.randomUUID(),payload};}
  async function perform(operation){
    if(!visible()||active)return;
    if(operation.action==='invite.issue'&&operation.payload.expires<=now()){
      pending=null;confirm=null;message('Срок запроса истёк. Выпустите новое приглашение.');controls();return;
    }
    const own=new AbortController(),start=epoch,mutation=operation.action!=='invite.get';
    active=own;confirm=null;if(mutation)pending=operation;controls();
    try{
      const result=await send(JSON.stringify(operation),own.signal);
      if(start!==epoch||!visible()||own.signal.aborted)return;
      if(operation.action==='invite.issue')showIssued(result,operation);
      else showView(result,operation.payload.id);
      pending=null;message(operation.action==='invite.issue'?'Приглашение выпущено.':'Состояние обновлено.');
    }catch(error){
      if(start!==epoch||!visible()||own.signal.aborted)return;
      const uncertain=['network','timeout','invalid_reply','reauth'].includes(error.message)||error instanceof TypeError||error instanceof SyntaxError;
      if(!uncertain)pending=null;
      clearView();conceal();
      message(({reauth:'Подтвердите вход и повторите запрос.',denied:'Недостаточно прав.',scope:'Недостаточно прав.',
        conflict:'Состояние изменилось. Запросите его ещё раз.',invalid:'Проверьте поля приглашения.'})[error.message]||
        'Операция не подтверждена. Проверьте состояние приглашения.');
    }finally{if(start===epoch){active=null;controls();}}
  }
  function ask(operation,text){
    if(!visible()||active||pending||confirm)return;
    confirm=operation;$('confirm-text').textContent=text;controls();$('confirm-yes').focus();
  }
  $('issue-form').onsubmit=event=>{
    event.preventDefault();
    const owner=$('owner').value,grantHash=$('grant').value,serviceId=$('service').value,
      ttl=$('ttl').valueAsNumber,bootstrapRevision=$('revision').valueAsNumber;
    if(!opaque.test(owner)||!opaque.test(grantHash)||!/^[A-Za-z0-9_-]{1,64}$/.test(serviceId)||
      !Number.isSafeInteger(bootstrapRevision)||bootstrapRevision<1||!Number.isInteger(ttl)||ttl<1||ttl>10){
      message('Проверьте получателя, назначение, сервис и срок.');return;
    }
    ask(body('issue',{owner,grantHash,serviceId,bootstrapRevision,expires:now()+ttl*60}),
      'Выпустить ссылку на '+ttl+' мин. для получателя '+owner+'?');
  };
  $('issue-form').oninput=()=>{clearView();conceal();message('');controls();};
  $('read-form').onsubmit=event=>{
    event.preventDefault();if(active||pending||confirm)return;
    const id=$('id').value;if(!opaque.test(id)){message('Введите ID приглашения.');return;}
    clearView();void perform(body('get',{id,version:0}));
  };
  $('id').oninput=()=>{clearView();conceal();controls();};
  $('pair-code').oninput=controls;
  $('approve').onclick=()=>{
    if(!view||view.state!=='pending_approval'||view.expires<=now()||$('pair-code').value!==view.pairCode){
      message('Сверьте код на новом устройстве и обновите состояние.');return;
    }
    ask(body('approve',{id:view.id,version:view.version,thumbprint:view.thumbprint,pairCode:$('pair-code').value}),
      'Привязать новое устройство к получателю '+view.owner+'?');
  };
  $('revoke').onclick=()=>{if(view&&!$('revoke').hidden)ask(body('revoke',{id:view.id,version:view.version}),'Отозвать приглашение '+view.id+'?');};
  $('confirm-yes').onclick=()=>{if(confirm)void perform(confirm);};
  $('confirm-no').onclick=()=>{confirm=null;$('confirm-text').textContent='';controls();};
  $('retry').onclick=()=>{if(pending)void perform(pending);};
  $('conceal').onclick=conceal;controls();
}
