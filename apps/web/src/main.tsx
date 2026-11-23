import { MutationCache, QueryCache, QueryClient, QueryClientProvider, useMutation, useQuery } from '@tanstack/react-query'
import { Database, Layers3, Server } from 'lucide-react'
import { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { AuditPage, SettingsPage, UsersPage } from './admin'
import { api, ApiError, type Language, type Session, type Settings, type SetupStatus } from './api'
import { AppShell, useConsoleRoute } from './console-shell'
import { Dashboard } from './dashboard'
import { AgentInstallPage, DevicesPage } from './devices'
import { LoadingSkeleton, StatusBadge } from './design'
import { DeploymentsPage, type DeploymentPreset } from './deployments'
import { LicensesPage } from './licenses'
import { PackageCatalog } from './packages'
import { Login, SetupWizard } from './setup'
import { Action, FormError, errorMessage, Panel, translator, type Translate } from './ui'
import '@fontsource-variable/inter'
import './style.css'

function expireSession(error: unknown) {
  if (error instanceof ApiError && error.status === 401 && error.code.startsWith('session_')) {
    clearSession()
  }
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
  queryCache: new QueryCache({ onError: expireSession }),
  mutationCache: new MutationCache({ onError: expireSession }),
})

async function fetchHealth(kind: 'live' | 'ready', signal: AbortSignal) {
  const response = await fetch(`/api/health/${kind}`, { signal, cache: 'no-store' })
  if (kind === 'ready' && response.status === 503) return 'unavailable'
  if (!response.ok) throw new Error()
  const body: unknown = await response.json()
  if (typeof body === 'object' && body !== null && 'status' in body && body.status === 'ok') return 'ok'
  throw new Error()
}

function HealthCard({ kind, t }: { kind: 'live' | 'ready'; t: Translate }) {
  const query = useQuery({
    queryKey: ['health', kind], queryFn: ({ signal }) => fetchHealth(kind, signal), refetchInterval: 15_000,
  })
  const live = kind === 'live'
  const Icon = live ? Server : Database
  const healthy = !query.isError && query.data === 'ok'
  const status = query.isPending ? t('Проверка…', 'Checking…')
    : query.isError ? t('Нет ответа', 'No response')
    : healthy ? t('Доступен', 'Available') : t('Недоступен', 'Unavailable')

  return <div className="flex min-w-0 items-center justify-between gap-2 rounded-xl border border-border bg-card px-3 py-2.5">
    <span className="flex min-w-0 items-center gap-2 text-sm font-medium"><Icon className="size-4 shrink-0 text-info" aria-hidden />
      {live ? t('Сервер API', 'API server') : 'PostgreSQL'}
    </span>
    <div role="status"><StatusBadge tone={query.isPending ? 'neutral' : healthy ? 'success' : 'danger'}>{status}</StatusBadge></div>
  </div>
}

function ShellHeader({ t, children }: { t: Translate; children?: React.ReactNode }) {
  return <header className="border-b border-border bg-background">
    <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-5 py-4">
      <Layers3 aria-hidden="true" className="size-8 rounded-lg bg-accent p-1.5 text-primary-foreground" />
      <span className="text-lg font-semibold">DeployCore</span>
      <div className="ml-auto flex flex-wrap items-center gap-3">
        <a className="text-sm font-medium text-primary hover:underline" href="/api/docs">{t('Документация API', 'API documentation')}</a>
        {children}
      </div>
    </div>
  </header>
}

function clearSession() {
  queryClient.removeQueries({ predicate: query => !['setup', 'session'].includes(String(query.queryKey[0])) })
  queryClient.setQueryData(['session'], null)
}

function Console({ session, initialLanguage }: { session: Session; initialLanguage: SetupStatus['language'] }) {
  const [expiry, setExpiry] = useState(session.expires_at)
  useEffect(() => {
    function extend(event: Event) {
      const deadline = (event as CustomEvent<string>).detail
      setExpiry(current => Date.parse(deadline) > Date.parse(current) ? deadline : current)
    }
    window.addEventListener('deploycore:session-expiry', extend)
    return () => window.removeEventListener('deploycore:session-expiry', extend)
  }, [])
  useEffect(() => {
    const timer = window.setTimeout(clearSession, Math.max(0, Date.parse(expiry) - Date.now()))
    return () => window.clearTimeout(timer)
  }, [expiry])
  const settings = useQuery({ queryKey: ['settings'], queryFn: () => api<Settings>('/settings'), staleTime: 60_000 })
  const [locale, setLocale] = useState<Language | undefined>(() => {
    try {
      const value = localStorage.getItem('deploycore-language')
      return value === 'ru' || value === 'en' ? value : undefined
    } catch { return undefined }
  })
  function changeLanguage(value: Language) {
    setLocale(value)
    try { localStorage.setItem('deploycore-language', value) } catch { /* Session state still applies. */ }
  }
  const instanceLanguage = settings.data?.language ?? initialLanguage
  const language = locale ?? instanceLanguage
  const t = translator(language)
  const logout = useMutation({
    mutationFn: () => api<void>('/auth/logout', { method: 'POST', csrf: session.csrf_token }),
    onSuccess: () => { clearSession(); void queryClient.invalidateQueries({ queryKey: ['setup'] }) },
  })
  const { route, navigate } = useConsoleRoute(session.user.role)
  useEffect(() => {
    document.documentElement.lang = language
    queryClient.setQueryData<SetupStatus>(['setup'], status => status ? { ...status, language: instanceLanguage } : status)
  }, [language, instanceLanguage])

  const openInstaller = () => navigate({ section: 'agent' })
  const [deploymentPreset, setDeploymentPreset] = useState<DeploymentPreset>()
  function openDeployment(preset?: DeploymentPreset) {
    setDeploymentPreset(preset)
    navigate({ section: 'jobs' })
  }
  const section = route.section
  const deviceSection = section === 'devices' || section === 'inventory' || section === 'agents'
  return <AppShell route={route} navigate={navigate} session={session} t={t} language={language} changeLanguage={changeLanguage}
    organization={settings.data?.organization} logout={() => logout.mutate()} loggingOut={logout.isPending}>
    <FormError message={logout.error && errorMessage(logout.error, t)} />
    {section === 'dashboard' && <Dashboard t={t}
      openInstaller={session.user.role !== 'viewer' ? openInstaller : undefined}
      openDevices={status => navigate({ section: 'devices', status })}
      openInventory={() => navigate({ section: 'inventory' })}
      openJobs={(jobScope, job) => navigate({ section: 'jobs', jobScope, job })}
      openAgents={agentVersion => navigate({ section: 'agents', agentVersion })}
      health={<footer className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
        <HealthCard kind="live" t={t} /><HealthCard kind="ready" t={t} />
        <div className="flex items-center justify-between gap-2 rounded-xl border border-border bg-card px-3 py-2.5 text-sm">
          <span>{t('Версия сервера', 'Server version')}</span><span className="font-mono text-info">{settings.data?.version ?? '—'}</span>
        </div>
      </footer>} />}
    {deviceSection && <DevicesPage key={`${section}:${route.search ?? ''}:${route.status ?? ''}:${route.agentVersion ?? ''}`}
      session={session} t={t} openInstaller={openInstaller}
      initialSearch={route.search} initialStatus={route.status}
      selected={route.device} onSelect={device => navigate({ ...route, device })}
      onFilter={(search, status, agentVersion) => navigate({ section, search, status, agentVersion })}
      monitoring={section === 'agents'} agentVersion={route.agentVersion}
      openHistory={targetDevice => navigate({ section: 'jobs', targetDevice })}
      inventory={section === 'inventory'} onSoftware={(deviceId, deviceName) => openDeployment({ deviceId, deviceName })} />}
    {section === 'jobs' && <DeploymentsPage session={session} t={t} preset={deploymentPreset} clearPreset={() => setDeploymentPreset(undefined)}
      scope={route.jobScope} targetDevice={route.targetDevice} selected={route.job}
      onScope={jobScope => navigate({ ...route, jobScope })}
      onSelect={job => navigate({ ...route, job })}
      clearDevice={() => navigate({ ...route, targetDevice: undefined })} />}
    {section === 'software' && <PackageCatalog session={session} t={t} deploy={openDeployment} />}
    {section === 'agent' && <AgentInstallPage session={session} t={t} server={settings.data?.agent_url ?? window.location.origin} configuredAddress={!!settings.data?.agent_url} />}
    {section === 'settings' && (settings.data
      ? <SettingsPage settings={settings.data} session={session} t={t} health={<HealthCard kind="ready" t={t} />} />
      : settings.error ? <FormError message={errorMessage(settings.error, t)} /> : <LoadingSkeleton label={t('Загрузка…', 'Loading…')} />)}
    {section === 'licenses' && <LicensesPage session={session} t={t} />}
    {section === 'users' && <UsersPage session={session} t={t} />}
    {section === 'audit' && <AuditPage t={t} />}
  </AppShell>
}

function App() {
  const setup = useQuery({ queryKey: ['setup'], queryFn: () => api<SetupStatus>('/setup'), staleTime: Infinity })
  const session = useQuery({
    queryKey: ['session'], enabled: setup.data?.configured === true, staleTime: Infinity,
    queryFn: () => api<Session>('/auth/session').catch(error => {
      if (error instanceof ApiError && error.status === 401) return null
      throw error
    }),
  })
  const language = setup.data?.language ?? 'ru'
  const t = translator(language)
  useEffect(() => { document.documentElement.lang = language }, [language])

  if (setup.data?.configured && session.data) return <Console session={session.data} initialLanguage={language} />
  const problem = setup.error ?? session.error
  return <>
    <ShellHeader t={t} />
    <main className="mx-auto w-full max-w-5xl px-4 py-8 sm:py-14">
      {problem ? <div className="mx-auto grid max-w-md gap-4">
        <FormError message={errorMessage(problem, t)} />
        <Action onClick={() => void (setup.error ? setup.refetch() : session.refetch())}>{t('Повторить', 'Retry')}</Action>
      </div> : !setup.data || (setup.data.configured && session.isPending)
        ? <LoadingSkeleton label={t('Загрузка…', 'Loading…')} />
        : setup.data.configured
          ? <Login t={t} complete={result => queryClient.setQueryData(['session'], result)} />
          : <SetupWizard status={setup.data} t={t} complete={result => {
            if (result) queryClient.setQueryData(['setup'], result)
            else void setup.refetch()
          }} />}
    </main>
  </>
}

try {
  document.documentElement.dataset.theme = localStorage.getItem('deploycore-theme') === 'light' ? 'light' : 'dark'
} catch { /* the CSS default is dark */ }

createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={queryClient}><App /></QueryClientProvider>,
)
