import {
  Bell, ChevronDown, ClipboardList, KeyRound, Languages, Layers3, LayoutDashboard, Radio,
  ListChecks, Menu, Monitor, Moon, Package, Rocket, Settings2, Sun, Users, type LucideIcon,
} from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import type { Language, Session } from './api'
import { EmptyState, LoadingSkeleton, PageHeader, SearchInput } from './design'
import { Dialog } from './components/ui/dialog'
import { Dropdown } from './components/ui/dropdown'
import { FleetActivity, useFleetSummary } from './dashboard'
import { roleLabels, type Translate } from './ui'

export const sections = {
  dashboard: ['Дашборд', 'Dashboard', LayoutDashboard],
  devices: ['Устройства', 'Devices', Monitor],
  software: ['Программы', 'Software', Package],
  agent: ['Установка агента', 'Agent installation', Rocket],
  agents: ['Агенты Windows', 'Windows agents', Radio],
  jobs: ['Задания', 'Jobs', ListChecks],
  inventory: ['Инвентаризация', 'Inventory', ClipboardList],
  users: ['Пользователи', 'Users', Users],
  audit: ['Журнал событий', 'Audit log', ClipboardList],
  settings: ['Настройки', 'Settings', Settings2],
  licenses: ['Лицензия', 'License', KeyRound],
} satisfies Record<string, [string, string, LucideIcon]>

export type Section = keyof typeof sections
export type DeviceStatusFilter = 'all' | 'online' | 'offline' | 'revoked'
export type JobScope = 'all' | 'active' | 'problem'
export interface ConsoleRoute {
  section: Section
  device?: string
  search?: string
  status?: DeviceStatusFilter
  jobScope?: JobScope
  job?: string
  targetDevice?: string
  agentVersion?: string
}

export function canOpen(section: Section, role: Session['user']['role']) {
  if (section === 'users' || section === 'audit') return role === 'super_admin'
  return section !== 'agent' || role !== 'viewer'
}

function readUUID(value: string | null) {
  return value && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value) ? value : undefined
}

function readRoute(): ConsoleRoute {
  const [path, query] = window.location.hash.slice(1).split('?', 2)
  const [section, device] = path.split('/')
  const params = new URLSearchParams(query)
  const status = params.get('status')
  return {
    section: Object.hasOwn(sections, section) ? section as Section : 'dashboard',
    device: device && /^[0-9a-f-]{36}$/i.test(device) ? device : undefined,
    search: params.get('q')?.slice(0, 120),
    status: status === 'online' || status === 'offline' || status === 'revoked' ? status : undefined,
    jobScope: params.get('scope') === 'active' ? 'active' : params.get('scope') === 'problem' ? 'problem' : undefined,
    job: readUUID(params.get('job')),
    targetDevice: readUUID(params.get('target')),
    agentVersion: params.get('version')?.slice(0, 64) || undefined,
  }
}

export function useConsoleRoute(role: Session['user']['role']) {
  const [route, setRoute] = useState(readRoute)
  useEffect(() => {
    const update = () => setRoute(readRoute())
    window.addEventListener('hashchange', update)
    return () => window.removeEventListener('hashchange', update)
  }, [])

  function navigate(next: ConsoleRoute) {
    const params = new URLSearchParams()
    if (next.search) params.set('q', next.search)
    if (next.status && next.status !== 'all') params.set('status', next.status)
    if (next.jobScope && next.jobScope !== 'all') params.set('scope', next.jobScope)
    if (next.job) params.set('job', next.job)
    if (next.targetDevice) params.set('target', next.targetDevice)
    if (next.agentVersion) params.set('version', next.agentVersion)
    const query = params.toString()
    window.location.hash = next.section + (next.device ? '/' + next.device : '') + (query ? '?' + query : '')
  }

  return { route: canOpen(route.section, role) ? route : { section: 'dashboard' as const }, navigate }
}

const navigationGroups: Section[][] = [
  ['dashboard', 'devices', 'inventory'],
  ['software', 'jobs', 'agents', 'agent'],
  ['users', 'audit', 'settings', 'licenses'],
]

function Sidebar({ role, active, select, t }: {
  role: Session['user']['role']; active: Section; select: (section: Section) => void; t: Translate
}) {
  const names = [t('Инфраструктура', 'Infrastructure'), t('Операции', 'Operations'), t('Администрирование', 'Administration')]
  return <nav aria-label={t('Разделы панели', 'Console sections')} className="grid gap-4">
    {navigationGroups.map((group, index) => <div className="grid gap-1" key={names[index]}>
      <p className="px-3 pb-1 text-[0.66rem] font-semibold tracking-[0.12em] text-slate-400 uppercase">{names[index]}</p>
      {group.filter(id => canOpen(id, role)).map(id => {
        const [ru, en, Icon] = sections[id]
        return <button key={id} type="button" aria-current={active === id ? 'page' : undefined} onClick={() => select(id)}
          className="flex min-h-9 items-center gap-2.5 rounded-lg px-3 py-1.5 text-left text-[0.82rem] font-medium transition-colors">
          <Icon className="size-4 shrink-0" aria-hidden /><span className="min-w-0 grow">{t(ru, en)}</span>
        </button>
      })}
    </div>)}
  </nav>
}

function Topbar({ navigate, session, t, language, changeLanguage, logout, loggingOut, openMenu }: {
  navigate: (next: ConsoleRoute) => void; session: Session; t: Translate; logout: () => void
  loggingOut: boolean; openMenu: () => void
  language: Language; changeLanguage: (language: Language) => void
}) {
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme === 'light' ? 'light' : 'dark')
  const [search, setSearch] = useState('')
  const searchInput = useRef<HTMLInputElement>(null)
  const fleet = useFleetSummary()
  const warnings = fleet.data?.errors ?? []

  useEffect(() => {
    function focusSearch(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && !document.querySelector('dialog[open]')) {
        event.preventDefault()
        searchInput.current?.focus()
      }
    }
    window.addEventListener('keydown', focusSearch)
    return () => window.removeEventListener('keydown', focusSearch)
  }, [])

  function changeTheme() {
    const next = theme === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    setTheme(next)
    try { localStorage.setItem('deploycore-theme', next) } catch { /* theme still applies to this page */ }
  }

  function findDevice(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    navigate({ section: 'devices', search: search.trim() })
  }

  return <header className="sticky top-0 z-10 border-b border-border bg-background">
    <div className="flex min-h-16 items-center gap-2 px-3 sm:gap-4 sm:px-6 xl:px-7">
      <button type="button" className="rounded-lg p-2 hover:bg-muted lg:hidden" aria-label={t('Открыть меню', 'Open navigation')} onClick={openMenu}>
        <Menu className="size-5" aria-hidden />
      </button>
      <SearchInput inputRef={searchInput} value={search} onChange={setSearch} onSearch={findDevice}
        label={t('Поиск устройств', 'Search devices')} submitLabel={t('Найти устройство', 'Find device')}
        placeholder={t('Поиск…', 'Search…')} />
      <Dropdown header label={t('Уведомления', 'Notifications')} trigger={<span className="relative">
        <Bell className="size-5" aria-hidden />
        {warnings.length > 0 && <span className="absolute -top-0.5 -right-0.5 size-2 rounded-full bg-danger-graph" aria-hidden />}
      </span>}>{() => <div className="p-2">
        <h2 className="mb-2 text-sm font-semibold">{t('Последние предупреждения', 'Recent warnings')}</h2>
        {fleet.isError ? <p className="text-sm text-danger">{t('Не удалось загрузить уведомления.', 'Could not load notifications.')}</p>
          : fleet.isPending ? <LoadingSkeleton label={t('Загрузка уведомлений', 'Loading notifications')} rows={2} />
          : warnings.length ? <FleetActivity items={warnings.slice(0, 4)} t={t} warning />
          : <EmptyState icon={Bell} title={t('Предупреждений нет', 'No warnings')} />}
      </div>}</Dropdown>
      <Dropdown header label={t('Профиль', 'Profile')} trigger={<>
        <span className="grid size-8 shrink-0 place-items-center rounded-full bg-primary-soft text-sm font-bold text-primary">{session.user.username.slice(0, 1).toUpperCase()}</span>
        <span className="hidden max-w-36 truncate text-sm font-semibold sm:block">{session.user.username}</span>
        <ChevronDown className="hidden size-4 text-muted-foreground sm:block" aria-hidden />
      </>}>{close => <>
        <div className="border-b border-border px-2 py-2 text-sm">
          <p className="break-all font-semibold">{session.user.username}</p>
          <p className="text-muted-foreground">{roleLabels[session.user.role]}</p>
        </div>
        <button className="mt-1 flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm hover:bg-muted" type="button" onClick={changeTheme}>
          {theme === 'dark' ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
          {theme === 'dark' ? t('Светлая тема', 'Light theme') : t('Тёмная тема', 'Dark theme')}
        </button>
        <button className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-sm hover:bg-muted" type="button"
          onClick={() => { changeLanguage(language === 'ru' ? 'en' : 'ru'); close() }}>
          <Languages className="size-4" aria-hidden />{language === 'ru' ? 'English' : 'Русский'}
        </button>
        <a className="block rounded-lg px-2 py-2 text-sm hover:bg-muted" href="/api/docs">{t('Документация API', 'API documentation')}</a>
        <button className="w-full rounded-lg px-2 py-2 text-left text-sm text-danger hover:bg-danger-soft" type="button"
          disabled={loggingOut} onClick={() => { close(); logout() }}>{t('Выйти', 'Sign out')}</button>
      </>}</Dropdown>
    </div>
  </header>
}

export function AppShell({ route, navigate, session, organization, t, language, changeLanguage, logout, loggingOut, children }: {
  route: ConsoleRoute; navigate: (next: ConsoleRoute) => void; session: Session; organization?: string
  t: Translate; logout: () => void; loggingOut: boolean; children: ReactNode
  language: Language; changeLanguage: (language: Language) => void
}) {
  const [mobileMenu, setMobileMenu] = useState(false)
  const [ru, en] = sections[route.section]
  const navigation = <Sidebar role={session.user.role} active={route.section} t={t} select={section => {
    navigate({ section })
    setMobileMenu(false)
  }} />
  return <div className="min-h-dvh lg:pl-[260px]">
    <aside className="console-sidebar fixed inset-y-0 left-0 z-20 hidden w-[260px] min-w-0 border-r border-border lg:flex lg:flex-col">
      <div className="flex min-h-16 items-center gap-3 border-b border-border px-5 text-white">
        <Layers3 className="size-9 shrink-0 rounded-xl bg-accent p-2" aria-hidden />
        <span className="text-lg font-semibold tracking-tight">DeployCore</span>
      </div>
      <div className="min-h-0 grow overflow-y-auto px-3 py-4">{navigation}</div>
      {organization && <p className="truncate border-t border-border px-5 py-4 text-xs" title={organization}>{organization}</p>}
    </aside>
    <Topbar navigate={navigate} session={session} t={t} language={language} changeLanguage={changeLanguage} logout={logout} loggingOut={loggingOut} openMenu={() => setMobileMenu(true)} />
    {mobileMenu && <Dialog title="DeployCore" close={() => setMobileMenu(false)} closeLabel={t('Закрыть', 'Close')} drawer>
      <div className="console-sidebar">{navigation}</div>
    </Dialog>}
    <main className="min-w-0 px-3 py-5 sm:px-6 sm:py-6 xl:px-7">
      <PageHeader title={t(ru, en)} />
      {children}
    </main>
  </div>
}
