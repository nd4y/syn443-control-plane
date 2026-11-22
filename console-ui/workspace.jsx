import {
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardTitle,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  PageSection,
  TextArea,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { CaretDownIcon } from '@patternfly/react-icons';
import { Support } from './support.jsx';
import { Invitations } from './invitations.jsx';

// The controller writes the native value when it loads or clears a draft.
function Select(props) {
  return (
    <span className="pf-v6-c-form-control">
      <select {...props} />
      <span className="pf-v6-c-form-control__utilities" aria-hidden="true">
        <span className="pf-v6-c-form-control__toggle-icon">
          <CaretDownIcon />
        </span>
      </span>
    </span>
  );
}

export function Workspace() {
  return (
    <main id="workspace" tabIndex={-1} hidden>
      <div className="workspace-heading">
        <Breadcrumb aria-label="Расположение в панели">
          <BreadcrumbItem>Администрирование</BreadcrumbItem>
          <BreadcrumbItem isActive>
            <span id="section-context">Устройства</span>
          </BreadcrumbItem>
        </Breadcrumb>
      </div>
      <Reauthentication />
      <PendingOperation />
      <Devices />
      <Invitations />
      <Sources />
      <Drafts />
      <Publication />
      <Telemetry />
      <Support />
    </main>
  );
}

function Reauthentication() {
  return (
    <Card id="reauthentication" isCompact role="region" aria-labelledby="reauthentication-title" hidden>
      <CardTitle component="h2" id="reauthentication-title" tabIndex={-1}>Подтверждение входа</CardTitle>
      <CardBody>
        <p id="reauthentication-status">Для этой операции подтвердите вход в Keycloak. Правки в этой вкладке сохранятся.</p>
        <p id="reauthentication-unavailable" hidden>Подтверждение входа недоступно. Обратитесь к администратору; правки остаются в этой вкладке.</p>
        <div className="reauthentication-actions">
          <Button id="reauthentication-start" variant="primary" isDisabled>Подтвердить вход в Keycloak</Button>
          <Button id="reauthentication-check" variant="secondary" isDisabled>Проверить вход</Button>
        </div>
      </CardBody>
    </Card>
  );
}

function PendingOperation() {
  return (
    <div id="pending" hidden>
      <p>Изменение не подтверждено. Повтор использует ту же операцию.</p>
      <Button id="retry-save" variant="secondary">
        Повторить операцию
      </Button>
      <Button id="discard-save" variant="secondary">
        Отменить повтор и проверить версию на сервере
      </Button>
    </div>
  );
}

function Devices() {
  return (
    <PageSection
      hasBodyWrapper={false}
      className="workspace-page"
      aria-labelledby="inventory-title"
      hidden
    >
      <Title headingLevel="h1" size="2xl" id="inventory-title" tabIndex={-1}>
        Устройства
      </Title>
      <p id="inventory-help">
        Откройте доступное устройство или введите его ID из приложения.
      </p>
      <details id="devices-disclosure" open>
      <summary>Доступные устройства</summary>
      <Button id="refresh-devices" variant="secondary" isDisabled>
        Обновить список
      </Button>
      <div id="device-filters" className="device-filters" hidden>
        <div>
          <label htmlFor="device-search">Поиск по загруженным ID</label>
          <TextInput id="device-search" type="search" maxLength={64} autoComplete="off" spellCheck={false} />
        </div>
        <div>
          <label htmlFor="device-filter">Показать</label>
          <Select id="device-filter" defaultValue="all">
            <option value="all">Все устройства</option>
            <option value="attention">Проблемы применения</option>
            <option value="favorites">Избранные в этой вкладке</option>
          </Select>
        </div>
        <Button id="search-all-devices" type="button" variant="secondary" isDisabled>
          Найти по началу ID во всей базе
        </Button>
        <Button id="clear-device-prefix" type="button" variant="link" hidden>
          Сбросить поиск по базе
        </Button>
      </div>
      <p id="devices-status" role="status" aria-atomic="true"></p>
      <div id="devices-region" className="device-list-scroll" role="region" aria-label="Доступные устройства" tabIndex={0} hidden>
        <table className="pf-v6-c-table pf-m-compact">
          <caption>Доступные устройства. Отчёт об активации не подтверждает текущее подключение.</caption>
          <thead><tr><th scope="col">Устройство</th><th scope="col">Версия управляемых слоёв</th><th scope="col">Выданная политика</th><th scope="col">Последний отчёт</th><th scope="col">Получен сервером</th></tr></thead>
          <tbody id="device-rows"></tbody>
        </table>
      </div>
      <Button id="more-devices" variant="secondary" isDisabled hidden>
        Ещё устройства
      </Button>
      </details>
      <form id="inventory-form" className="inventory-form">
        <div>
          <label htmlFor="inventory-device">ID устройства</label>
          <TextInput
            id="inventory-device"
            autoComplete="off"
            maxLength={64}
            pattern={'[A-Za-z0-9_\\-]{1,64}'}
            spellCheck={false}
            aria-describedby="inventory-help"
            isRequired
          />
        </div>
        <Button id="load-inventory" variant="primary" type="submit" isDisabled>
          Открыть карточку
        </Button>
      </form>
      <p id="inventory-status" role="status" aria-atomic="true"></p>
      <div id="inventory-view" role="region" aria-label="Конфигурация выбранного устройства" tabIndex={-1} hidden>
        <div
          className="inventory-summary"
          role="group"
          aria-label={'Состояние устройства'}
        >
          <Card isCompact>
            <CardTitle component="h3">Состояние клиента</CardTitle>
            <CardBody>
              <p id="inventory-runtime"></p>
              <small id="inventory-runtime-detail"></small>
              <time id="inventory-runtime-time" hidden></time>
            </CardBody>
          </Card>
          <Card isCompact>
            <CardTitle component="h3">Назначение управляемых слоёв</CardTitle>
            <CardBody>
              <p id="inventory-state"></p>
              <p id="inventory-assignment-note" hidden></p>
            </CardBody>
          </Card>
          <Card isCompact>
            <CardTitle component="h3">Выданная политика</CardTitle>
            <CardBody>
              <p id="inventory-issued"></p>
              <p id="inventory-issued-algorithm" hidden></p>
            </CardBody>
          </Card>
          <Card isCompact>
            <CardTitle component="h3">Последний отчёт Android</CardTitle>
            <CardBody>
              <p id="inventory-report"></p>
              <time id="inventory-report-time" hidden></time>
            </CardBody>
          </Card>
        </div>
        <div className="device-actions">
          <a href="#layer-title" className="pf-v6-c-button pf-m-link">
            Открыть публикацию
          </a>
          <Button id="refresh-runtime" variant="secondary" isDisabled>Обновить состояние</Button>
        </div>
        <details id="inventory-issued-settings" hidden>
          <summary>Настройки выданной политики</summary>
          <p>Последняя политика, подписанная сервером. Учётные данные и адреса проверок скрыты.</p>
          <section id="issued-path" aria-labelledby="issued-path-heading" hidden>
            <h3 id="issued-path-heading">Маршрут по выданной политике</h3>
            <label htmlFor="issued-path-select">Выход для просмотра</label>
            <Select id="issued-path-select"></Select>
            <p id="issued-path-note"></p>
            <ol id="issued-path-steps" aria-label="Порядок соединения"></ol>
          </section>
          <pre id="inventory-issued-config"></pre>
        </details>
        <details id="inventory-details">
          <summary>Технические данные</summary>
          <dl id="inventory-meta"></dl>
          <h3>Наследованные слои</h3>
          <ul id="inventory-layers"></ul>
          <h3>Действующие переносимые настройки</h3>
          <pre id="inventory-effective"></pre>
          <h3>Источники полей</h3>
          <ul id="inventory-fields"></ul>
          <h3>Ограничения</h3>
          <ul id="inventory-restrictions"></ul>
        </details>
      </div>
    </PageSection>
  );
}

function Sources() {
  return (
    <PageSection
      hasBodyWrapper={false}
      aria-labelledby="sources-title"
      hidden
      className="workspace-page"
    >
      <Title headingLevel="h1" size="2xl" id="sources-title" tabIndex={-1}>
        Источники
      </Title>
      <label htmlFor="owner">ID пользователя</label>
      <TextInput id="owner" autoComplete="off" maxLength={128} />
      <Button id="load-sources" variant="secondary" isDisabled>
        Загрузить источники
      </Button>
      <ul id="sources"></ul>
      <Button id="more-sources" variant="secondary" isDisabled>
        Следующая страница
      </Button>
      <h3>Профили источника</h3>
      <ul id="profiles"></ul>
      <section id="source-details" hidden aria-labelledby="source-details-title">
        <h3 id="source-details-title">Версия и трафик подписки</h3>
        <DescriptionList>
          {[
            ['source-snapshot-name','Источник и версия'],['source-snapshot-modes','Режимы сети'],
            ['source-snapshot-time','Версия получена'],['source-snapshot-until','Версия пригодна до'],
            ['source-traffic-time','Данные о трафике от провайдера'],['source-traffic-used','Использовано'],
            ['source-traffic-limit','Лимит'],['source-traffic-left','Осталось'],
            ['source-traffic-expiry','Подписка у провайдера действует до'],
          ].map(([id, label]) => <DescriptionListGroup key={id}>
            <DescriptionListTerm>{label}</DescriptionListTerm>
            <DescriptionListDescription>{['source-snapshot-time','source-snapshot-until','source-traffic-time','source-traffic-expiry'].includes(id)
              ? <time id={id}></time> : <span id={id}></span>}</DescriptionListDescription>
          </DescriptionListGroup>)}
        </DescriptionList>
      </section>
      <h3>Настройки источника</h3>
      <Button id="new-source" variant="secondary" isDisabled>
        Новый источник
      </Button>
      <p id="source-version">Источник не выбран</p>
      <section id="source-dependencies" hidden aria-labelledby="source-dependencies-title">
        <h3 id="source-dependencies-title">Профили в маршрутах</h3>
        <p id="source-dependencies-summary" role="status"></p>
        <ul id="source-dependencies-profiles" hidden></ul>
        <Button id="source-dependencies-more" variant="link" hidden>Показать ещё профили</Button>
        <Button id="source-dependencies-refresh" variant="link" isDisabled>Обновить зависимости</Button>
      </section>
      <section id="source-review" hidden aria-labelledby="source-review-title">
        <h3 id="source-review-title">Обновление в карантине</h3>
        <Button id="source-review-load" variant="secondary" isDisabled>Сравнить версии</Button>
        <div id="source-review-comparison" hidden>
          <p id="source-review-summary" role="status"></p>
          <ul id="source-review-changes"></ul>
          <Button id="source-review-more" variant="link" hidden>Показать ещё изменения</Button>
          <label><input id="source-review-confirm" type="checkbox" disabled /> Я проверил изменения в подписке</label>
          <Button id="source-review-approve" variant="primary" isDisabled>Принять версию</Button>
          <Button id="source-review-reject" variant="secondary" isDisabled>Отклонить версию</Button>
        </div>
      </section>
      <form id="source-form">
        <label htmlFor="source-id">ID источника</label>
        <TextInput
          id="source-id"
          autoComplete="off"
          maxLength={48}
          isRequired
        />
        <label htmlFor="source-owner">ID владельца</label>
        <TextInput
          id="source-owner"
          autoComplete="off"
          maxLength={128}
          isRequired
        />
        <label htmlFor="source-name">Название</label>
        <TextInput
          id="source-name"
          autoComplete="off"
          maxLength={256}
          isRequired
        />
        <label htmlFor="source-mode">Получение профилей</label>
        <Select id="source-mode">
          <option value="server">{'HTTPS на сервере'}</option>
          <option value="device">{'HTTPS на устройстве по Wi-Fi'}</option>
          <option value="manual">{'Ручной импорт'}</option>
          <option value="resource">{'Remnawave API'}</option>
        </Select>
        <div id="source-device-settings" hidden>
          <label htmlFor="source-device">ID устройства для загрузки</label>
          <TextInput id="source-device" autoComplete="off" maxLength={128} />
          <p>
            После привязки изменить устройство нельзя. Для загрузки устройство
            должно быть онлайн по Wi-Fi и запустить SYN443.
          </p>
        </div>
        <label htmlFor="source-format">Формат</label>
        <Select id="source-format">
          <option value="uri">{'URI'}</option>
          <option value="base64">{'Base64'}</option>
          <option value="singbox">{'sing-box'}</option>
          <option value="xray">{'Xray'}</option>
          <option value="mihomo">{'Mihomo'}</option>
        </Select>
        <div id="provider-settings" hidden>
          <label htmlFor="source-resource">ID ресурса Remnawave</label>
          <TextInput id="source-resource" autoComplete="off" maxLength={48} />
          <Button id="inspect-provider" type="button" variant="secondary" isDisabled>
            Посмотреть ресурс
          </Button>
          <div role="status" aria-live="polite"><dl id="provider-details" /></div>
          <details id="provider-editor" hidden>
            <summary>Изменить ресурс Remnawave</summary>
            <label htmlFor="provider-edit-name">Название ресурса</label>
            <TextInput id="provider-edit-name" autoComplete="off" maxLength={256} />
            <label><input id="provider-edit-enabled" type="checkbox" /> Разрешить синхронизацию</label>
            <div id="provider-impact" hidden>
              <p id="provider-impact-text" aria-live="polite" />
              <label><input id="provider-impact-confirm" type="checkbox" /> Подтверждаю изменение синхронизации</label>
            </div>
            <Button id="provider-edit-save" type="button" variant="secondary" isDisabled>Сохранить ресурс</Button>
          </details>
          <label htmlFor="source-external">ID пользователя в Remnawave</label>
          <TextInput id="source-external" autoComplete="off" maxLength={15} />
        </div>
        <label htmlFor="source-until">Разрешён до</label>
        <input id="source-until" type="datetime-local" required />
        <label htmlFor="source-refresh">Интервал обновления, секунды</label>
        <input
          id="source-refresh"
          type="number"
          min="60"
          max="86400"
          defaultValue="3600"
          required
        />
        <label htmlFor="source-stale">
          Допустимый возраст профилей, секунды
        </label>
        <input
          id="source-stale"
          type="number"
          min="300"
          max="604800"
          defaultValue="86400"
          required
        />
        <label htmlFor="source-modes">Режимы сети</label>
        <select id="source-modes" multiple size={4} defaultValue={['wifi']}>
          <option value="home_wifi">Домашний Wi-Fi</option>
          <option value="wifi">Wi-Fi</option>
          <option value="cellular_restricted">LTE с ограничениями</option>
          <option value="cellular">LTE</option>
        </select>
        <label>
          <input id="source-enabled" type="checkbox" defaultChecked /> Включён
        </label>
        <label htmlFor="source-secret-operation">Учётные данные</label>
        <Select id="source-secret-operation">
          <option value="keep">{'Сохранить прежние'}</option>
          <option value="replace">{'Заменить'}</option>
          <option value="delete">{'Удалить'}</option>
        </Select>
        <p id="source-withdraw-hint" hidden role="status">
          Для удаления учётных данных отключите источник. Чтобы снова включить загрузку,
          выберите «Заменить» и укажите действующие данные.
        </p>
        <label htmlFor="source-secret">Новые параметры HTTPS, JSON</label>
        <TextArea
          resizeOrientation="vertical"
          id="source-secret"
          rows={5}
          maxLength={65536}
          autoComplete="off"
          spellCheck={false}
        ></TextArea>
        <p>
          Для HTTPS: объект с полем url и при необходимости headers, rootCa,
          allowedNetworks. Прежние значения не отображаются. Изменение секрета
          требует свежей MFA.
        </p>
        <Button id="save-source" variant="primary" type="submit" isDisabled>
          Сохранить источник
        </Button>
      </form>
      <Button id="sync-source" variant="secondary" isDisabled>
        Обновить профили
      </Button>
      <Button id="source-job" variant="secondary" isDisabled>
        Проверить задание
      </Button>
      <pre id="job-status"></pre>
      <label htmlFor="source-import-file">Файл подписки до 10 МиБ</label>
      <input id="source-import-file" type="file" disabled />
      <Button id="source-import" variant="secondary" isDisabled>
        Импортировать в ручной источник
      </Button>
      <h3>История заданий источника</h3>
      <Button id="source-history" variant="secondary" isDisabled>
        Загрузить историю
      </Button>
      <Button id="source-history-more" variant="secondary" isDisabled>
        Более ранние задания
      </Button>
      <p id="source-history-status" role="status"></p>
      <ul id="source-history-list"></ul>
      <h3>Получатели источника</h3>
      <Button id="source-shares-load" variant="secondary" isDisabled>
        Загрузить получателей
      </Button>
      <p id="source-shares-revision"></p>
      <ul id="source-shares-list"></ul>
      <label htmlFor="source-shares-kind">Тип получателя</label>
      <Select id="source-shares-kind" disabled>
        <option value="user">{'Пользователь'}</option>
        <option value="device">{'Устройство'}</option>
        <option value="group">{'Группа'}</option>
      </Select>
      <label htmlFor="source-shares-id">ID получателя</label>
      <TextInput
        id="source-shares-id"
        maxLength={128}
        autoComplete="off"
        isDisabled
      />
      <Button id="source-shares-add" variant="secondary" isDisabled>
        Добавить получателя
      </Button>
      <label>
        <input id="source-shares-confirm" type="checkbox" disabled />
        Подтверждаю новый список. Сервер проверит права и свежую MFA.
      </label>
      <Button id="source-shares-save" variant="secondary" isDisabled>
        Сохранить получателей
      </Button>
    </PageSection>
  );
}

function Drafts() {
  return (
    <PageSection
      hasBodyWrapper={false}
      aria-labelledby="draft-title"
      hidden
      className="workspace-page"
    >
      <Title headingLevel="h1" size="2xl" id="draft-title" tabIndex={-1}>
        Личный черновик конфигурации
      </Title>
      <p>
        Сохранение черновика не меняет VPN на устройствах. Для публикации нужны
        отдельные проверка и подтверждение.
      </p>
      <label htmlFor="draft-id">ID черновика</label>
      <TextInput id="draft-id" autoComplete="off" maxLength={128} />
      <Button id="open-draft" variant="secondary" isDisabled>
        Открыть черновик
      </Button>
      <Button id="new-draft" variant="secondary" isDisabled>
        Новый черновик
      </Button>
      <form id="draft-form">
        <label htmlFor="target-kind">Область правки</label>
        <Select id="target-kind">
          <option value="device">{'Устройство'}</option>
          <option value="user">{'Пользователь'}</option>
          <option value="group">{'Группа'}</option>
          <option value="template">{'Шаблон'}</option>
        </Select>
        <label htmlFor="target-id">ID адресата</label>
        <TextInput
          id="target-id"
          autoComplete="off"
          maxLength={128}
          isRequired
        />
        <p id="draft-version">Новый черновик</p>
        <label htmlFor="base-revision">Исходная версия конфигурации</label>
        <input
          id="base-revision"
          type="number"
          min="0"
          max="9007199254740991"
          defaultValue="0"
          required
        />
        <label htmlFor="base-hash">
          SHA-256 исходной версии (для версии 0 оставьте пустым)
        </label>
        <TextInput id="base-hash" autoComplete="off" maxLength={64} />
        <label htmlFor="plan">План сети, JSON</label>
        <TextArea
          resizeOrientation="vertical"
          id="plan"
          rows={22}
          maxLength={262144}
          spellCheck={false}
          autoComplete="off"
          isRequired
        ></TextArea>
        <fieldset id="home-proof" hidden disabled>
          <legend>Проверка домашнего Wi-Fi</legend>
          <p>Укажите TLS-узел, доступный только в домашней сети. Телефон проверяет сертификат через текущую Wi-Fi-сеть.</p>
          <label htmlFor="home-address">Локальный IP-адрес</label>
          <TextInput id="home-address" autoComplete="off" maxLength={45} />
          <label htmlFor="home-hostname">Имя узла в сертификате</label>
          <TextInput id="home-hostname" autoComplete="off" maxLength={253} />
          <label htmlFor="home-port">Порт TLS</label>
          <TextInput id="home-port" inputMode="numeric" autoComplete="off" maxLength={5} />
          <label htmlFor="home-pin">Отпечаток ключа сертификата (SHA-256, base64url)</label>
          <TextInput id="home-pin" autoComplete="off" maxLength={43} />
          <Button id="home-apply" type="button" variant="secondary">Записать узел в черновик</Button>
          <Button id="home-remove" type="button" variant="link">Удалить узел из черновика</Button>
          <div id="home-feedback" role="status" aria-live="polite"></div>
        </fieldset>
        <fieldset id="mode-selection" hidden disabled>
          <legend>Выбор режима сети</legend>
          <label htmlFor="mode-preferred">Режим по умолчанию</label>
          <Select id="mode-preferred">
            <option value="AUTO">Определять автоматически</option>
            <option value="HOME_WIFI">Домашний Wi-Fi</option>
            <option value="WIFI">Обычный Wi-Fi</option>
            <option value="CELLULAR_RESTRICTED">Мобильная сеть с белым списком</option>
            <option value="CELLULAR">Мобильная сеть</option>
          </Select>
          <fieldset>
            <legend>Пользователь может временно выбрать</legend>
            <label><input type="checkbox" id="mode-allow-HOME_WIFI" /> Домашний Wi-Fi</label>
            <label><input type="checkbox" id="mode-allow-WIFI" /> Обычный Wi-Fi</label>
            <label><input type="checkbox" id="mode-allow-CELLULAR_RESTRICTED" /> Мобильная сеть с белым списком</label>
            <label><input type="checkbox" id="mode-allow-CELLULAR" /> Мобильная сеть</label>
          </fieldset>
          <label htmlFor="mode-minutes">Максимальный срок выбора в минутах</label>
          <TextInput id="mode-minutes" inputMode="numeric" maxLength={4} />
          <Button id="mode-apply" type="button" variant="secondary">Записать режим в черновик</Button>
          <Button id="mode-remove" type="button" variant="link">Убрать назначение режима</Button>
          <div id="mode-feedback" role="status" aria-live="polite"></div>
        </fieldset>
        <div id="route-bounds" hidden>
          <Button id="route-bounds-preview" type="button" variant="secondary">
            Оценить число цепочек
          </Button>
          <div id="route-bounds-result" role="status" aria-live="polite"></div>
        </div>
        <fieldset id="route-check-editor" disabled>
          <legend>Проверки маршрутов</legend>
          <label htmlFor="route-check-path">Выход</label>
          <Select id="route-check-path"></Select>
          <label>
            <input id="route-check-required" type="checkbox" /> Обязательная
            проверка при применении
          </label>
          <label htmlFor="route-check-method">Способ проверки</label>
          <Select id="route-check-method">
            <option value="tcp">{'TCP'}</option>
            <option value="tls">{'TLS'}</option>
            <option value="https_204">{'HTTPS 204'}</option>
            <option value="https_status">{'Код ответа HTTPS'}</option>
            <option value="ssh_banner">{'SSH banner'}</option>
            <option value="https_exit_ip">{'IP выхода по HTTPS'}</option>
            <option value="https_exit_country">Страна выхода по HTTPS</option>
          </Select>
          <label htmlFor="route-check-target">Адрес проверки</label>
          <TextInput
            id="route-check-target"
            type="text"
            maxLength={2048}
            autoComplete="off"
            placeholder={'host:port или https://…'}
          />
          <div id="route-check-exit" hidden>
            <label htmlFor="route-check-ip">Ожидаемый IP выхода</label>
            <TextInput
              id="route-check-ip"
              type="text"
              maxLength={45}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <div id="route-check-http" hidden>
            <label htmlFor="route-check-verb">Метод HTTP</label>
            <Select id="route-check-verb" defaultValue="HEAD">
              <option value="HEAD">HEAD</option>
              <option value="GET">GET</option>
            </Select>
            <label htmlFor="route-check-status">Ожидаемый код ответа</label>
            <TextInput id="route-check-status" type="number" min={200} max={599} step={1} defaultValue="200" />
          </div>
          <div id="route-check-country" hidden>
            <label htmlFor="route-check-country-class">Расположение выхода</label>
            <Select id="route-check-country-class" defaultValue="">
              <option value="">Выберите расположение</option>
              <option value="RU">Россия</option>
              <option value="NON_RU">За пределами России</option>
            </Select>
            <p>Укажите корневой HTTPS-адрес сервиса, который возвращает IP и страну текущего подключения в JSON.</p>
          </div>
          <p id="route-profile-note" hidden>Этот маршрут использует профиль проверок.</p>
          <Button id="route-check-add" type="button" variant="secondary">
            Добавить проверку
          </Button>
          <ul id="route-check-list"></ul>
          <Button id="route-profile-open" type="button" variant="secondary" disabled>
            Настроить условия проверок
          </Button>
          <fieldset id="route-profile-editor" hidden>
            <legend>Условия выбранного выхода</legend>
            <label htmlFor="route-profile-mode">Как объединить проверки</label>
            <Select id="route-profile-mode">
              <option value="sequence">Последовательно по этапам</option>
              <option value="all">Все должны пройти</option>
              <option value="any">Достаточно одной</option>
              <option value="quorum">Минимум успешных проверок</option>
              <option value="custom">Свои условия в JSON</option>
            </Select>
            <div id="route-profile-threshold" hidden>
              <label htmlFor="route-profile-count">Минимум успешных</label>
              <input id="route-profile-count" type="number" min="1" max="4" step="1" defaultValue="1" />
            </div>
            <div id="route-profile-timing">
              <label htmlFor="route-profile-deadline">Общий тайм-аут, мс</label>
              <input id="route-profile-deadline" type="number" min="1" max="12000" />
              <p>Проверки TLS, IP и страны выхода обязательны при любом сочетании условий.</p>
            </div>
            <div id="route-profile-advanced" hidden>
              <label htmlFor="route-profile-json">Профиль проверок, JSON</label>
              <TextArea id="route-profile-json" rows={8} maxLength={24000} spellCheck={false} autoComplete="off" />
            </div>
            <Button id="route-profile-apply" type="button" variant="primary">
              Применить условия к черновику
            </Button>
            <Button id="route-profile-cancel" type="button" variant="link">Отмена</Button>
          </fieldset>
          <label>
            <input id="route-reserve-cooldown" type="checkbox" disabled />{' '}
            Откладывать фоновые проверки резервов после подтверждённых сбоев
          </label>
          <p>
            Настройка доступна для внутреннего маршрута по Wi-Fi. Без указания
            доли она действует для всех выбранных устройств, если все её
            поддерживают.
          </p>
          <div id="route-cooldown-rollout" hidden>
            <label htmlFor="route-rollout-id">Идентификатор раскатки</label>
            <TextInput
              id="route-rollout-id"
              autoComplete="off"
              maxLength={48}
            />
            <label htmlFor="route-rollout-share">
              Доля устройств вне контрольной группы, %
            </label>
            <input
              id="route-rollout-share"
              type="number"
              min="0"
              max="100"
              step={'0.01'}
            />
            <label htmlFor="route-rollout-control">
              Постоянная контрольная группа, %
            </label>
            <input
              id="route-rollout-control"
              type="number"
              min="0"
              max="100"
              step={'0.01'}
              aria-describedby="route-rollout-control-help"
            />
            <p id="route-rollout-control-help">
              Эта доля совместимых устройств останется на базовой версии даже при полной раскатке.
              Для общей контрольной группы укажите одинаковые идентификатор и долю.
            </p>
            <Button id="route-rollout-save" type="button" variant="secondary">
              Применить долю к черновику
            </Button>
            <p>
              Сохраняйте идентификатор при изменении доли, чтобы не менять
              состав группы. 0% возвращает прежнее поведение после публикации
              новой версии.
            </p>
          </div>
          <label htmlFor="route-decision">Алгоритм переключения</label>
          <Select id="route-decision" disabled>
            <option value={''}>
              {'Базовый (2 подтверждения, интервал 30 с)'}
            </option>
            <option value="m4-confirmed-v1">
              {'Консервативный (3 подтверждения, интервал 60 с)'}
            </option>
          </Select>
          <div id="route-decision-rollout" hidden>
            <label htmlFor="program-revision">Версия правил переключения</label>
            <TextInput id="program-revision" type="number" min={1} max={Number.MAX_SAFE_INTEGER}
              aria-describedby="program-help" />
            <p id="program-help">Оставьте версию пустой, чтобы использовать встроенные пороги.</p>
            <label htmlFor="program-confirmations">Сколько проверок должны подтвердить сбой (3-6)</label>
            <TextInput id="program-confirmations" type="number" min={3} max={6} />
            <label htmlFor="program-interval">Минимальный интервал между переключениями, мс (60000-300000)</label>
            <TextInput id="program-interval" type="number" min={60000} max={300000} />
            <Button id="program-save" type="button" variant="secondary">Применить пороги к черновику</Button>
            <label htmlFor="route-decision-id">
              Идентификатор раскатки алгоритма
            </label>
            <TextInput
              id="route-decision-id"
              autoComplete="off"
              maxLength={48}
            />
            <label htmlFor="route-decision-share">
              Доля устройств вне контрольной группы, %
            </label>
            <input
              id="route-decision-share"
              type="number"
              min="0"
              max="100"
              step={'0.01'}
            />
            <label htmlFor="route-decision-control">
              Постоянная контрольная группа, %
            </label>
            <input
              id="route-decision-control"
              type="number"
              min="0"
              max="100"
              step={'0.01'}
              aria-describedby="route-decision-control-help"
            />
            <p id="route-decision-control-help">
              Эта доля совместимых устройств останется на базовой версии даже при полной раскатке.
              Для общей контрольной группы укажите одинаковые идентификатор и долю.
            </p>
            <Button id="route-decision-save" type="button" variant="secondary">
              Применить долю для алгоритма к черновику
            </Button>
          </div>
          <div id="cohort-preview" hidden>
            <label htmlFor="cohort-device">ID устройства для предпросмотра группы</label>
            <TextInput id="cohort-device" autoComplete="off" maxLength={128}
              aria-describedby="cohort-help" />
            <p id="cohort-help">
              Расчёт по введённым долям для совместимого устройства. Выданную
              версию можно посмотреть в карточке устройства.
            </p>
            <Button id="cohort-run" type="button" variant="secondary">Проверить группу</Button>
            <div id="cohort-result" role="status" aria-live="polite" />
          </div>
        </fieldset>
        <p>
          Профили задаются ссылками sourceId/profileId. Ключи, пароли и
          состояние NetBird сюда не переносятся.
        </p>
        <Button id="save-draft" variant="primary" type="submit" isDisabled>
          Сохранить черновик
        </Button>
      </form>
      <details id="route-explanation" hidden>
        <summary>Как сработают правила черновика</summary>
        <p>Введите домен, IP-адрес или пакет приложения. Панель проверит правила без сетевого соединения с адресатом. История запросов не сохраняется.</p>
        <form id="route-explanation-form" autoComplete="off">
          <label htmlFor="explain-domain">Домен</label>
          <TextInput id="explain-domain" maxLength={254} spellCheck={false} autoCapitalize="none" autoComplete="off" />
          <label htmlFor="explain-address">IP-адрес назначения</label>
          <TextInput id="explain-address" maxLength={45} spellCheck={false} autoCapitalize="none" autoComplete="off" />
          <label htmlFor="explain-application">Пакет приложения</label>
          <TextInput id="explain-application" maxLength={255} spellCheck={false} autoCapitalize="none" autoComplete="off" />
          <label htmlFor="explain-network">Транспорт</label>
          <Select id="explain-network"><option value="">Не указан</option><option value="tcp">TCP</option><option value="udp">UDP</option></Select>
          <label htmlFor="explain-port">Порт назначения</label>
          <TextInput id="explain-port" type="number" min={1} max={65535} />
          <label htmlFor="explain-dnsType">Тип DNS-запроса</label>
          <Select id="explain-dnsType">
            <option value="">Не указан</option>
            {['A','AAAA','CNAME','MX','TXT','PTR','SRV','HTTPS','SVCB','NS','SOA'].map(type => <option key={type} value={type}>{type}</option>)}
          </Select>
          <Button id="explain-run" variant="secondary" type="submit" isDisabled>Проверить правила</Button>
        </form>
        <div id="explain-result" role="status" aria-live="polite" />
      </details>
      <details id="route-replay">
        <summary>Симуляция выбора маршрута</summary>
        <p>
          Сравните исходное и пробное время действия измерений на одинаковых данных.
          Оставьте поле файла пустым для встроенных сценариев или выберите свой JSON-массив измерений.
        </p>
        <label htmlFor="route-replay-ttl">Пробное время действия измерения, мс</label>
        <input id="route-replay-ttl" type="number" min="1" max="600000" step="1" defaultValue="60000" />
        <label htmlFor="route-replay-file">Файл сценария (до 64 кадров, 255 КиБ)</label>
        <input id="route-replay-file" type="file" accept=".json,application/json" />
        <Button id="route-replay-run" type="button" variant="secondary" isDisabled>Сравнить решения</Button>
        <div id="route-replay-result" role="status" aria-live="polite"></div>
      </details>
    </PageSection>
  );
}

function Publication() {
  return (
    <PageSection
      hasBodyWrapper={false}
      className="workspace-page"
      aria-labelledby="layer-title"
      hidden
    >
      <Title headingLevel="h1" size="2xl" id="layer-title" tabIndex={-1}>
        Редактирование и публикация слоёв
      </Title>
      <p>
        Начните с конфигурации выбранного устройства или откройте сохранённый
        черновик. Предложение содержит все наследованные слои; меняйте только
        разрешённую область. Сервер проверяет ограничения, актуальность исходных
        версий и полный список затронутых устройств.
      </p>
      <div id="layer-first-device" hidden>
        <p>Для первой конфигурации подготовьте переносимый план в разделе «Черновики». Здесь можно скопировать его в новый личный черновик слоёв.</p>
        <a href="#draft-title">Открыть планы</a>
        <label htmlFor="layer-first-mode">Режим первой конфигурации</label>
        <Select id="layer-first-mode" defaultValue="wifi">
          <option value="home_wifi">Домашний Wi-Fi</option>
          <option value="wifi">Любой Wi-Fi</option>
          <option value="cellular_restricted">Ограниченная сотовая сеть</option>
          <option value="cellular">Сотовая сеть</option>
        </Select>
        <Button id="layer-first-from-plan" variant="secondary" isDisabled>
          Создать первый черновик из плана
        </Button>
      </div>
      <Button id="layer-from-device" variant="secondary" isDisabled>
        Править слой выбранного устройства
      </Button>
      <Button id="layer-list" variant="secondary" isDisabled>
        Сохранённые черновики текущего адресата
      </Button>
      <label htmlFor="layer-saved">Сохранённая копия</label>
      <Select id="layer-saved" disabled></Select>
      <Button id="layer-open-saved" variant="secondary" isDisabled>
        Открыть выбранный черновик
      </Button>
      <p id="layer-list-status"></p>
      <label htmlFor="layer-id">ID личного черновика слоёв</label>
      <TextInput id="layer-id" maxLength={64} autoComplete="off" />
      <Button id="layer-load" variant="secondary" isDisabled>
        Открыть черновик слоёв
      </Button>
      <p id="layer-version">Черновик слоёв не открыт</p>
      <label htmlFor="layer-proposal">Переносимое предложение, JSON</label>
      <TextArea
        resizeOrientation="vertical"
        id="layer-proposal"
        rows={24}
        maxLength={262144}
        autoComplete="off"
        spellCheck={false}
      ></TextArea>
      <p>
        Нативные конфиги, ключи и пароли сюда не добавляйте. Сохранение не
        меняет устройства. Предварительная проверка компилирует маршруты на
        сервере, но не проверяет доступность сети с телефона.
      </p>
      <label>
        <input id="layer-discard-confirm" type="checkbox" disabled />{' '}
        Подтверждаю удаление сохранённого черновика. Несохранённый текст
        останется в редакторе.
      </label>
      <Button id="layer-discard" variant="danger" isDisabled>
        Удалить сохранённый черновик
      </Button>
      <Button id="layer-save" variant="primary" isDisabled>
        Сохранить черновик слоёв
      </Button>
      <Button id="layer-preview" variant="secondary" isDisabled>
        Проверить предложение на сервере
      </Button>
      <Button id="layer-poll" variant="secondary" isDisabled>
        Проверить задание конфигурации
      </Button>
      <pre id="layer-job"></pre>
      <div id="layer-review" hidden>
        <h3>Проверенное предложение</h3>
        <div id="layer-impact" className="pf-v6-c-content"></div>
        <label>
          <input id="layer-confirm" type="checkbox" /> Проверил изменения и
          список затронутых устройств
        </label>
        <Button id="layer-publish" variant="primary" isDisabled>
          Опубликовать желаемую конфигурацию
        </Button>
      </div>
      <Button id="layer-compare" variant="secondary" isDisabled>
        Сравнить с текущей версией устройства
      </Button>
      <div id="layer-comparison" hidden>
        <h3>Исходная, локальная и текущая конфигурации</h3>
        <pre id="layer-diff"></pre>
        <ul id="layer-conflicts"></ul>
        <Button id="layer-merge" variant="secondary" isDisabled>
          Перенести результат сравнения в редактор
        </Button>
      </div>
      <p id="layer-result">
        Результат публикации не является подтверждением активации Android.
      </p>
    </PageSection>
  );
}

function Telemetry() {
  return (
    <PageSection
      hasBodyWrapper={false}
      className="workspace-page"
      aria-labelledby="telemetry-title"
      hidden
    >
      <Title headingLevel="h1" size="2xl" id="telemetry-title" tabIndex={-1}>
        Техническая телеметрия
      </Title>
      <p>
        Почасовая сводка по типу события, результату и режиму сети. Доступ
        выдаётся отдельно.
      </p>
      <form id="telemetry-form">
        <label htmlFor="telemetry-hour">Начало часа (UTC)</label>
        <input
          id="telemetry-hour"
          type="datetime-local"
          step="3600"
          required
          disabled
        />
        <Button id="load-telemetry" variant="primary" type="submit" isDisabled>
          Загрузить сводку
        </Button>
      </form>
      <p id="telemetry-status" role="status"></p>
      <div id="telemetry-view" hidden>
        <div
          className="table-scroll"
          role="region"
          aria-label={'Таблица технической телеметрии'}
          tabIndex={0}
        >
          <table>
            <thead>
              <tr>
                <th scope="col">Событие</th>
                <th scope="col">Результат</th>
                <th scope="col">Режим</th>
                <th scope="col">Число событий</th>
                <th scope="col">Среднее время</th>
                <th scope="col">Переключения по алгоритмам</th>
              </tr>
            </thead>
            <tbody id="telemetry-rows"></tbody>
          </table>
        </div>
        <p>
          Счётчики показывают только полученные события переключения. Количество
          устройств и доля успешных подключений здесь не измеряются.
        </p>
      </div>
    </PageSection>
  );
}
