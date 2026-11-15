import {Button,Card,CardBody,CardTitle,PageSection,TextArea,Title} from '@patternfly/react-core';
import {mountSupportChat} from '../internal/chatweb/assets/support-controller.js';

export function Support() {
  return <PageSection hasBodyWrapper={false} className="workspace-page" aria-labelledby="support-title" hidden>
    <Title headingLevel="h1" size="2xl" id="support-title" tabIndex={-1}>Чат поддержки</Title>
    <p id="support-status" role="status" aria-atomic="true">Выберите диалог для переписки.</p>
    <Button id="support-retry" variant="secondary">Обновить чат</Button>
    <Button id="support-login" hidden isDisabled>Войти через Keycloak</Button>
    <Button id="support-logout" hidden isDisabled>Выйти</Button>
    <div className="support-grid">
      <Card isCompact>
        <CardTitle component="h2">Диалоги</CardTitle>
        <CardBody>
          <ul id="support-inbox" className="support-inbox" aria-label="Диалоги поддержки" />
          <p id="support-empty" hidden>Диалогов пока нет.</p>
          <Button id="support-more" variant="secondary" isDisabled>Ещё диалоги</Button>
        </CardBody>
      </Card>
      <Card isCompact>
        <CardTitle component="h2" id="support-thread-title">Выберите диалог</CardTitle>
        <CardBody>
          <Button id="support-older" variant="secondary" isDisabled>Предыдущие сообщения</Button>
          <ol id="support-messages" className="support-messages" aria-label="Сообщения поддержки" aria-live="polite" />
          <form id="support-compose" className="support-compose">
            <label htmlFor="support-text">Сообщение</label>
            <TextArea id="support-text" rows={3} maxLength={8192} isDisabled />
            <label htmlFor="support-file">Файлы до 25 МБ каждый, до 4 файлов</label>
            <input id="support-file" type="file" multiple disabled />
            <p id="support-attachment" />
            <progress id="support-progress" max="100" value="0" aria-label="Передача файла" hidden />
            <div className="support-actions">
              <Button id="support-send" type="submit" variant="primary" isDisabled>Отправить</Button>
              <Button id="support-discard" type="button" variant="secondary" isDisabled>Удалить локальную попытку</Button>
            </div>
          </form>
          <p id="support-download-ready" aria-live="polite" />
          <p className="support-notice">Сообщения и файлы хранятся на сервере и доступны администраторам сервиса. Веб-интерфейс отправляет исходные файлы; фото и видео сжимаются в Android-приложении.</p>
        </CardBody>
      </Card>
    </div>
  </PageSection>;
}

// The existing console controller owns authorization and navigation. This bridge
// observes their visible state; every network operation still requires the BFF.
export function connectSupportChat() {
  const workspace=document.getElementById('workspace');
  const section=document.getElementById('support-title').closest('.workspace-page');
  const visible=()=>!document.hidden&&!workspace.hidden&&!section.hidden;
  const chat=mountSupportChat({prefix:'support-',embedded:true,visible});
  let signedIn=!workspace.hidden,shown=visible();
  const sync=()=>{
    const nextSignedIn=!workspace.hidden,nextShown=visible();
    if(signedIn&&!nextSignedIn)chat.clear();
    if(shown&&!nextShown)chat.suspend();
    signedIn=nextSignedIn;shown=nextShown;
    if(shown)chat.resume();
  };
  const observer=new MutationObserver(sync);
  for(const target of [workspace,section])observer.observe(target,{attributes:true,attributeFilter:['hidden']});
  sync();
  window.addEventListener('pagehide',event=>{
    if(event.persisted)chat.suspend();
    else{observer.disconnect();chat.dispose();}
  });
  window.addEventListener('pageshow',event=>{if(event.persisted)sync();});
}
