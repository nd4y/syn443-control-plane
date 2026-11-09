import {
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardTitle,
  PageSection,
  TextArea,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { CaretDownIcon } from '@patternfly/react-icons';

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
      <PendingOperation />
      <Devices />
      <Sources />
      <Drafts />
      <Publication />
      <Telemetry />
    </main>
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
        Введите ID из приложения, чтобы открыть карточку устройства.
      </p>
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
      <div id="inventory-view" hidden>
        <div
          className="inventory-summary"
          role="group"
          aria-label={'Состояние устройства'}
        >
          <Card isCompact>
            <CardTitle component="h3">Желаемая конфигурация</CardTitle>
            <CardBody>
              <p id="inventory-state"></p>
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
        </div>
        <details id="inventory-issued-settings" hidden>
          <summary>Настройки выданной политики</summary>
          <p>Последняя политика, подписанная сервером. Учётные данные и адреса проверок скрыты.</p>
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
      <pre id="source-details"></pre>
      <h3>Настройки источника</h3>
      <Button id="new-source" variant="secondary" isDisabled>
        Новый источник
      </Button>
      <p id="source-version">Источник не выбран</p>
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
        <label htmlFor="source-resource">Ресурс (для Remnawave API)</label>
        <TextInput id="source-resource" autoComplete="off" maxLength={48} />
        <label htmlFor="source-external">ID пользователя в Remnawave</label>
        <TextInput id="source-external" autoComplete="off" maxLength={15} />
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
            <option value="ssh_banner">{'SSH banner'}</option>
            <option value="https_exit_ip">{'IP выхода по HTTPS'}</option>
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
          <Button id="route-check-add" type="button" variant="secondary">
            Добавить проверку
          </Button>
          <ul id="route-check-list"></ul>
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
              Доля совместимых устройств, %
            </label>
            <input
              id="route-rollout-share"
              type="number"
              min="0"
              max="100"
              step={'0.01'}
            />
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
            <label htmlFor="route-decision-id">
              Идентификатор раскатки алгоритма
            </label>
            <TextInput
              id="route-decision-id"
              autoComplete="off"
              maxLength={48}
            />
            <label htmlFor="route-decision-share">
              Доля совместимых устройств для алгоритма, %
            </label>
            <input
              id="route-decision-share"
              type="number"
              min="0"
              max="100"
              step={'0.01'}
            />
            <Button id="route-decision-save" type="button" variant="secondary">
              Применить долю для алгоритма к черновику
            </Button>
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
        <pre id="layer-impact"></pre>
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
