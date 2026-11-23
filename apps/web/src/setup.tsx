import { Check, KeyRound } from 'lucide-react'
import { PageHeader, SectionTitle } from './design'
import { useState, type FormEvent } from 'react'
import { api, ApiError, type SetupStatus } from './api'
import { Action, Field, FormError, Panel, errorMessage, type Translate } from './ui'

export function SetupWizard({ status, complete, t }: { status: SetupStatus; complete: (status?: SetupStatus) => void; t: Translate }) {
  const [step, setStep] = useState(0)
  const [organization, setOrganization] = useState('')
  const [instanceName, setInstanceName] = useState('DeployCore')
  const [agentAddress, setAgentAddress] = useState(window.location.protocol === 'https:' ? window.location.origin : '')
  function agentOrigin() {
    const address = agentAddress.trim()
    if (/^[A-Za-z0-9.-]+$/.test(address) && window.location.port) return `https://${address}:${window.location.port}`
    return address.includes('://') ? address : `https://${address}`
  }
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [secret, setSecret] = useState('')
  const [problem, setProblem] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const names = [t('Проверка', 'Checks'), t('Организация', 'Organization'), t('Администратор', 'Administrator'), t('Подтверждение', 'Review')]

  async function advance(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setProblem(null)
    if (step === 0) {
      setBusy(true)
      try {
        const readiness = await fetch('/api/health/ready', { cache: 'no-store' })
        if (!readiness.ok) throw new Error()
        setStep(1)
      } catch {
        setProblem(t('PostgreSQL недоступен. Повторите проверку.', 'PostgreSQL is unavailable. Try again.'))
      } finally {
        setBusy(false)
      }
      return
    }
    if (step === 1) {
      try {
        const url = new URL(agentOrigin())
        if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error()
      } catch {
        setProblem(t('Укажите HTTPS-адрес сервера без пути и параметров.', 'Enter an HTTPS server address without a path or query.'))
        return
      }
    }
    if (step === 2 && password !== confirmation) {
      setProblem(t('Пароли не совпадают.', 'Passwords do not match.'))
      return
    }
    if (step < 3) {
      setStep(step + 1)
      return
    }
    setBusy(true)
    try {
      const result = await api<SetupStatus>('/setup', {
        method: 'POST', body: { organization, instance_name: instanceName, agent_url: agentOrigin(), username, password, setup_token: secret },
      })
      complete(result)
    } catch (error) {
      if (error instanceof ApiError && error.code === 'already_configured') complete()
      else setProblem(errorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  return <div className="mx-auto max-w-4xl">
    <PageHeader title={t('Первоначальная настройка', 'Initial setup')} />
    <div className="grid items-start gap-4 sm:grid-cols-[minmax(11rem,1fr)_minmax(0,3fr)]">
    <Panel><ol className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-1">
      {names.map((name, index) => <li key={name} aria-current={step === index ? 'step' : undefined}
        className={`flex items-center gap-2 rounded-lg border px-2 py-2 ${step === index ? 'border-ring bg-primary-soft text-primary' : 'border-transparent text-muted-foreground'}`}>
        <span className="grid size-6 shrink-0 place-items-center rounded-full bg-muted text-xs">{index < step ? <Check className="size-3" aria-hidden /> : index + 1}</span>
        <span className="break-words">{name}</span>
      </li>)}
    </ol></Panel>
    <Panel>
      <SectionTitle title={names[step]} />
      <form className="grid gap-4" onSubmit={advance}>
        {step === 0 && <>
          <p className="text-foreground">{t('Проверим подключение к PostgreSQL. Для завершения настройки понадобится секрет, заданный при запуске сервера.', 'We will check the PostgreSQL connection. You will need the setup secret configured on the server.')}</p>
          {!status.token_configured && <FormError message={t('Секрет настройки отсутствует. Задайте DEPLOYCORE_SETUP_TOKEN на сервере и обновите страницу.', 'Set DEPLOYCORE_SETUP_TOKEN on the server and reload this page.')} />}
        </>}
        {step === 1 && <>
          <Field label={t('Название организации', 'Organization name')} required maxLength={120} value={organization} onChange={e => setOrganization(e.target.value)} />
          <Field label={t('IP или DNS-имя сервера для агентов', 'Server IP or DNS name for agents')} required maxLength={512}
            value={agentAddress} onChange={e => setAgentAddress(e.target.value)}
            hint={t('Укажите адрес, доступный с компьютеров Windows, например https://192.168.1.10:8444. Сертификат должен содержать этот IP или DNS-имя.',
              'Enter the address Windows computers can reach, for example https://192.168.1.10:8444. The certificate must cover this IP or DNS name.')} />
          <Field label={t('Имя экземпляра', 'Instance name')} required maxLength={120} value={instanceName} onChange={e => setInstanceName(e.target.value)} />
        </>}
        {step === 2 && <>
          <Field label={t('Имя пользователя', 'Username')} required minLength={3} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._@\x2D]*" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} />
          <Field label={t('Пароль', 'Password')} hint={t('От 12 до 128 символов.', '12–128 characters.')} type="password" required minLength={12} maxLength={128} autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} />
          <Field label={t('Подтверждение пароля', 'Confirm password')} type="password" required autoComplete="new-password" value={confirmation} onChange={e => setConfirmation(e.target.value)} />
          <Field label={t('Секрет установки', 'Setup secret')} type="password" required maxLength={256} autoComplete="off" value={secret} onChange={e => setSecret(e.target.value)} />
        </>}
        {step === 3 && <dl className="grid gap-3 break-words">
          <div><dt className="text-sm text-muted-foreground">{t('Организация', 'Organization')}</dt><dd>{organization}</dd></div>
          <div><dt className="text-sm text-muted-foreground">{t('Имя экземпляра', 'Instance name')}</dt><dd>{instanceName}</dd></div>
          <div><dt className="text-sm text-muted-foreground">{t('Адрес для агентов', 'Agent address')}</dt><dd>{agentOrigin()}</dd></div>
          <div><dt className="text-sm text-muted-foreground">Super Admin</dt><dd>{username}</dd></div>
        </dl>}
        <FormError message={problem} />
        <div className="flex flex-wrap gap-3">
          {step > 0 && <Action type="button" secondary disabled={busy} onClick={() => { setStep(step - 1); setProblem(null) }}>{t('Назад', 'Back')}</Action>}
          <Action type="submit" disabled={busy || (step === 0 && !status.token_configured)}>
            {busy ? t('Подождите…', 'Please wait…') : step === 0 ? t('Проверить и продолжить', 'Check and continue') : step === 3 ? t('Завершить настройку', 'Finish setup') : t('Продолжить', 'Continue')}
          </Action>
        </div>
      </form>
    </Panel>
    </div>
  </div>
}

export function Login({ complete, t }: { complete: (session: import('./api').Session) => void; t: Translate }) {
  const [problem, setProblem] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setProblem(null)
    setBusy(true)
    try {
      complete(await api<import('./api').Session>('/auth/login', {
        method: 'POST', body: { username: fields.get('username'), password: fields.get('password') },
      }))
    } catch (error) {
      setProblem(errorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  return <div className="mx-auto max-w-md">
    <Panel>
    <div className="mb-4 grid size-10 place-items-center rounded-xl bg-primary-soft text-primary"><KeyRound className="size-5" aria-hidden /></div>
    <PageHeader title={t('Вход в DeployCore', 'Sign in to DeployCore')} />
    <form className="grid gap-4" onSubmit={submit}>
      <Field label={t('Имя пользователя', 'Username')} name="username" required maxLength={64} autoComplete="username" />
      <Field label={t('Пароль', 'Password')} name="password" type="password" required maxLength={128} autoComplete="current-password" />
      <FormError message={problem} />
      <Action type="submit" className="w-full" disabled={busy}>{busy ? t('Вход…', 'Signing in…') : t('Войти', 'Sign in')}</Action>
    </form></Panel>
  </div>
}
