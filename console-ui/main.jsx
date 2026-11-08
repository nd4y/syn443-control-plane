import { useSyncExternalStore } from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import {
  Button,
  Card,
  CardBody,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
  MastheadToggle,
  Nav,
  NavGroup,
  NavItem,
  PageToggleButton,
  Title,
} from '@patternfly/react-core';
import { BarsIcon, ShieldAltIcon } from '@patternfly/react-icons';
import '@patternfly/react-core/dist/styles/base.css';
import { Workspace } from './workspace.jsx';

const groups = [
  { title: 'Главная', sections: [['inventory-title', 'Устройства']] },
  {
    title: 'Конфигурация',
    sections: [
      ['sources-title', 'Источники'],
      ['draft-title', 'Черновики'],
      ['layer-title', 'Публикация'],
    ],
  },
  { title: 'Наблюдение', sections: [['telemetry-title', 'Телеметрия']] },
];

function Brand() {
  return (
    <MastheadBrand className="brand">
      <svg
        className="brand-mark"
        aria-hidden="true"
        viewBox="0 0 32 32"
        width="32"
        height="32"
      >
        <rect width="32" height="32" rx="5" fill="currentColor" />
        <path
          d="M8 22l6-12 4 8 3-6 3 6M7 24h18"
          fill="none"
          stroke="white"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <strong>SYN443</strong>
      <span className="brand-product">Control Plane</span>
    </MastheadBrand>
  );
}

function Header() {
  return (
    <Masthead className="masthead pf-v6-theme-dark">
      <MastheadMain>
        <MastheadToggle>
          <PageToggleButton
            id="desktop-nav-toggle"
            aria-label="Разделы управления"
            aria-expanded="true"
            aria-controls="console-navigation"
            hidden
          >
            <BarsIcon />
          </PageToggleButton>
        </MastheadToggle>
        <Brand />
      </MastheadMain>
      <MastheadContent>
        <nav className="account-nav" aria-label="Учётная запись">
          <Button id="logout" variant="secondary" hidden isDisabled>
            Выйти
          </Button>
        </nav>
      </MastheadContent>
    </Masthead>
  );
}

function subscribeToSection(listener) {
  window.addEventListener('hashchange', listener);
  return () => window.removeEventListener('hashchange', listener);
}

function currentSection() {
  const id = location.hash.slice(1);
  return groups.some(({ sections }) =>
    sections.some(([section]) => section === id),
  )
    ? id
    : 'inventory-title';
}

function Navigation() {
  const section = useSyncExternalStore(subscribeToSection, currentSection);
  return (
    <aside
      id="console-navigation"
      className="console-navigation pf-v6-theme-dark"
      hidden
    >
      <Button
        id="console-nav-toggle"
        className="console-nav-toggle"
        variant="plain"
        aria-expanded="false"
        aria-controls="console-nav"
      >
        <span>Разделы</span>
        <span id="console-nav-current">Устройства</span>
      </Button>
      <Nav
        id="console-nav"
        className="console-nav"
        aria-label="Разделы управления"
      >
        <div className="console-perspective">
          <ShieldAltIcon aria-hidden="true" />
          <span>Администрирование</span>
        </div>
        {groups.map(({ title, sections }) => (
          <NavGroup key={title} role="group" title={title}>
            {sections.map(([id, label]) => (
              <NavItem key={id} to={'#' + id} isActive={section === id}>
                {label}
              </NavItem>
            ))}
          </NavGroup>
        ))}
      </Nav>
    </aside>
  );
}

function SignIn() {
  return (
    <Card
      component="section"
      className="signin-panel"
      id="signin"
      aria-labelledby="signin-title"
    >
      <CardBody>
        <p className="section-label">SYN443 Control Plane</p>
        <Title headingLevel="h1" size="2xl" id="signin-title">
          Вход в панель управления
        </Title>
        <p>
          Доступ к устройствам, конфигурации и отчётам определяется правами
          вашей учётной записи.
        </p>
        <Button id="login" variant="primary">
          Войти через Keycloak
        </Button>
      </CardBody>
    </Card>
  );
}

function Console() {
  return (
    <>
      <a className="skip-link" href="#workspace" id="skip-workspace" hidden>
        К рабочей области
      </a>
      <Header />
      <div id="console-shell" className="console-shell">
        <Navigation />
        <div className="console-content">
          <SignIn />
          <p
            id="status"
            className="console-status"
            role="status"
            aria-atomic="true"
          >
            Войдите с административной учётной записью.
          </p>
          <Workspace />
        </div>
      </div>
    </>
  );
}

// The controller owns transient form and authorization state across workspace navigation.
const root = createRoot(document.getElementById('console-root'));
flushSync(() => root.render(<Console />));
await import('/app.js');
