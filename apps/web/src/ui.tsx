import { useId, type ButtonHTMLAttributes, type InputHTMLAttributes, type PropsWithChildren } from 'react'
import { Button } from './components/ui/button'
import { ApiError, type Language, type Role } from './api'

export type Translate = (ru: string, en: string) => string
export const translator = (language: Language): Translate => (ru, en) => language === 'ru' ? ru : en

export const roleLabels: Record<Role, string> = {
  super_admin: 'Super Admin', administrator: 'Administrator', viewer: 'Viewer',
}

export function errorMessage(error: unknown, t: Translate) {
  if (!(error instanceof ApiError)) return t('Не удалось связаться с сервером.', 'Could not reach the server.')
  const messages: Record<string, string> = {
    already_configured: t('Первичная настройка уже завершена.', 'Setup is already complete.'),
    setup_token_missing: t('Задайте DEPLOYCORE_SETUP_TOKEN на сервере.', 'Set DEPLOYCORE_SETUP_TOKEN on the server.'),
    setup_token_invalid: t('Секрет настройки неверен.', 'The setup secret is incorrect.'),
    invalid_credentials: t('Неверное имя пользователя или пароль.', 'Incorrect username or password.'),
    login_limited: t('Слишком много попыток. Повторите вход через 10 минут.', 'Too many attempts. Try again in 10 minutes.'),
    permission_denied: t('Недостаточно прав для этой операции.', 'You do not have permission for this action.'),
    last_super_admin: t('У экземпляра должен остаться хотя бы один Super Admin.', 'The instance must retain at least one Super Admin.'),
    username_exists: t('Это имя пользователя уже занято.', 'This username is already taken.'),
    package_duplicate: t('Запись с таким названием или версией уже существует.', 'A package or version with this identity already exists.'),
    package_artifact_immutable: t('Файл уже сохранён. Для замены создайте версию.', 'This file is already stored. Create a version to replace it.'),
    package_signature_required: t('Для утверждения нужна проверенная подпись Authenticode.', 'Approval requires a verified Authenticode signature.'),
    package_manual_approval_unavailable: t('Ручное утверждение доступно для загруженного файла с неподтверждённой подписью.', 'Manual approval requires an uploaded file with an unverified signature.'),
    package_approval_hash_mismatch: t('SHA-256 не совпадает с текущим файлом. Обновите карточку и проверьте файл.', 'The SHA-256 differs from the current file. Refresh the version and check the file.'),
    package_architecture_mismatch: t('Архитектура файла отличается от указанной.', 'The installer architecture does not match.'),
    package_invalid_format: t('Файл не соответствует формату MSI или EXE.', 'The file does not match the MSI or EXE format.'),
    package_too_large: t('Файл превышает допустимый размер.', 'The file exceeds the size limit.'),
    package_storage_full: t('Недостаточно свободного места в хранилище.', 'The artifact volume has insufficient free space.'),
    package_upload_busy: t('Идёт другая загрузка. Повторите позже.', 'Another upload is in progress. Try again later.'),
    package_verifier_unavailable: t('Проверка установщиков недоступна.', 'The installer verifier is unavailable.'),
    deployment_devices_unavailable: t('Часть выбранных устройств недоступна для заданий.', 'Some devices are unavailable for deployments.'),
    deployment_version_unavailable: t('Для задания выберите утверждённую версию с установщиком.', 'Select an approved version with an installer.'),
    deployment_uninstall_unavailable: t('Для этой версии удаление не разрешено.', 'Removal is unavailable for this version.'),
    deployment_execution_disabled: t('Запуск программ отключён политикой сервера.', 'Program execution is disabled by server policy.'),
    deployment_agent_incompatible: t('Для выбранных устройств нужен Agent 0.3.4 или новее.', 'Selected devices require Agent 0.3.4 or later.'),
    deployment_manifest_invalid: t('Манифест содержит неподдерживаемые параметры для этой операции.', 'The manifest contains unsupported options for this operation.'),
    deployment_request_conflict: t('Состав задания изменился. Создайте новое задание.', 'The submission changed. Create a new job.'),
    csrf_invalid: t('Проверка запроса не пройдена. Обновите страницу.', 'Request verification failed. Reload the page.'),
  }
  if (error.status === 422) return t('Проверьте формат и допустимые значения полей.', 'Check field formats and allowed values.')
  return messages[error.code] ?? t('Не удалось выполнить запрос.', 'The request could not be completed.')
}

export function Panel({ children }: PropsWithChildren) {
  return <section className="min-w-0 rounded-2xl border border-border bg-card p-3.5 sm:p-4">{children}</section>
}

export function Field({ label, hint, id, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const generated = useId()
  const inputId = id ?? generated
  const hintId = hint ? `${inputId}-hint` : undefined
  const description = [props['aria-describedby'], hintId].filter(Boolean).join(' ') || undefined
  return <div className="grid min-w-0 gap-2 text-sm">
    <label htmlFor={inputId} className="font-medium text-foreground">{label}</label>
    <input {...props} id={inputId} aria-describedby={description} className="input" />
    {hint && <span id={hintId} className="text-muted-foreground">{hint}</span>}
  </div>
}

export function Action({ secondary, className, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { secondary?: boolean }) {
  return <Button {...props} className={className} variant={secondary ? 'outline' : 'default'} />
}

export function FormError({ message }: { message?: string | null }) {
  return message && <p role="alert" className="rounded-lg border border-danger-line bg-danger-soft p-3 text-sm text-danger">{message}</p>
}
