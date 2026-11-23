# DeployCore

DeployCore размещён в `apps/`, `packages/` и `deploy/`. Это отдельный Compose-проект. Версия 0.3.1 добавляет MSI и мастер настройки Windows Agent, автоматическую проверку HTTPS, сводку по компьютерам и расширенную инвентаризацию. Интерфейс по умолчанию русскоязычный. См. [архитектуру](docs/architecture/overview.md), [API](docs/api/overview.md), [дорожную карту](docs/roadmap.md) и [CHANGELOG](CHANGELOG.md).

### Разработка 0.4.0

Подэтап A обновляет интерфейс, навигацию и карточки устройств. [Отчёт по подэтапу A](docs/releases/0.4.0-phase-a.md) содержит список изменений и команды проверки. [Дорожная карта](docs/roadmap.md) описывает порядок A–D.

Полный редизайн интерфейса описан в [отчёте по дизайн-системе](docs/releases/enterprise-ui.md). В новой сборке тёмная тема включена по умолчанию, светлую можно выбрать в профиле.

### DeployCore 0.5.0 · каталог ПО

[Аудит и отчёт этапа A](docs/releases/0.5.0-stage-a.md) описывают REST API, параметры хранилища и проверку Authenticode. Для локальной проверки запустите `deploy/scripts/smoke.sh` из корня проекта. Каталог сохраняет файлы MSI/EXE в отдельном Docker-томе.

[Протокол и отчёт этапа B](docs/releases/0.5.0-stage-b.md) описывают очередь, повторную доставку, восстановление и тестовый обмен с Windows Agent без запуска установщиков.

[Исполнение MSI/EXE и обновление агента](docs/releases/0.5.0-stage-c.md) описаны в отчёте этапа C. Включение выполнения выполняется настройкой `DEPLOYCORE_ENABLE_EXECUTION=1`.

### Локальный запуск

Нужны Docker Engine с Compose v2 и OpenSSL. Выполните из корня каталога. Команды создают новый файл конфигурации только при его отсутствии.

```bash
if [ ! -e deploy/.env ]; then
  (umask 077; sed \
    -e "s/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" \
    -e "s/^DEPLOYCORE_SETUP_TOKEN=$/DEPLOYCORE_SETUP_TOKEN=$(openssl rand -hex 32)/" \
    deploy/.env.example > deploy/.env)
fi
mkdir -p deploy/tls
if [ ! -e deploy/tls/fullchain.pem ] && [ ! -e deploy/tls/privkey.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout deploy/tls/privkey.pem -out deploy/tls/fullchain.pem
fi
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build --wait
curl --cacert deploy/tls/fullchain.pem https://localhost:8443/api/health/ready
```

Панель открывается по адресу `https://localhost:8443`. Для проверки в браузере доверьте локальному тестовому сертификату. При первом открытии заполните мастер и введите секрет из `DEPLOYCORE_SETUP_TOKEN` в `deploy/.env`. После создания первого Super Admin секрет можно удалить из файла. Для применения изменений переменных окружения пересоздайте контейнер командой `docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --wait server`.

### Обновление с этапа 1

Сохраните резервную копию базы и текущую конфигурацию DeployCore. Добавьте новый случайный `DEPLOYCORE_SETUP_TOKEN` длиной 32–256 символов в существующий `deploy/.env`. Сохраните существующие параметры PostgreSQL, TLS и порт 8443. Выполните ту же команду `up -d --build --wait`. Сервер применит Alembic к существующему тому перед запуском FastAPI. Затем завершите настройку в браузере. OpenAPI доступен по `/api/openapi.json`, Swagger UI по `/api/docs` и работает с локальными ресурсами.

### Настройка для локальной сети

В `deploy/.env` укажите `DEPLOYCORE_HTTPS_BIND` (адрес интерфейса), `DEPLOYCORE_HTTPS_PORT` и при необходимости `DEPLOYCORE_TLS_DIR` (абсолютный путь или путь относительно `deploy/`). В каталоге TLS разместите `fullchain.pem` и `privkey.pem` для имени сервера. Сертификат должен быть доверен клиентами. После замены файлов выполните `docker compose --env-file deploy/.env -f deploy/compose.yaml restart web`.

`POSTGRES_USER`, `POSTGRES_DB` и `POSTGRES_PASSWORD` задают параметры создания БД при первом запуске. В существующем томе пароль меняется в PostgreSQL и затем в конфигурации. Обычный `down` оставляет том БД. PostgreSQL и FastAPI не публикуют порты на хосте.

Readiness выполняет запрос к БД, liveness проверяет только ответ API. Nginx проверяет отдачу страницы и проксирование liveness. Внутренний probe Nginx проверяет доступность, а проверку доверия и имени TLS выполняет внешний smoke-тест.

### Проверки

```bash
(cd apps/server && python3.12 -m venv .venv && .venv/bin/pip install -r requirements-test.txt && .venv/bin/python -m pytest -q)
(cd apps/web && npm ci && npm run build)
deploy/scripts/smoke.sh
```

Smoke-тест создаёт изолированный Compose-проект с отдельным томом и временным TLS-сертификатом. По умолчанию использует порт 18443, другой порт можно задать через `SMOKE_PORT`. Нужны также curl, sha256sum и Python 3. CI запускает pytest и сквозной сценарий, включая проверку Alembic, гонку первичной настройки, права, CSRF, аудит, истечение сессий, регистрации устройств, инвентаризацию и восстановление после остановки PostgreSQL.

### Перенос на новый сервер

Для нового экземпляра достаточно каталога проекта, Docker Compose и настроек в `deploy/.env`. Задайте новый случайный пароль PostgreSQL и секрет первичной настройки, адрес интерфейса, свободный HTTPS-порт и каталог TLS. При внешнем доступе используйте сертификат, SAN которого соответствует фактическому имени или IP. Дайте клиентам доверие к выдающему CA. После `docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build --wait` пройдите мастер в браузере. Если имя для агентов отличается от адреса браузера, укажите его в настройках панели. Не редактируйте Dockerfile, Nginx или исходный код для изменения адреса, порта или TLS.

### Windows Agent

При обновлении с 0.2.0 команда `up -d --build --wait` применяет миграцию `0002_devices` к существующему тому DeployCore. Используйте текущий `deploy/.env`, параметры TLS и HTTPS-порт 8443.

Войдите как Super Admin или Administrator и откройте «Установка агента». Скачайте MSI и SHA-256, создайте токен и запустите мастер из меню «Пуск». Альтернативно скачайте EXE и запустите его двойным щелчком или используйте отдельные команды из панели. Карточка появляется в разделе «Компьютеры». Подробности есть в [инструкции по агенту](apps/agent/README.md) и [сценарии приёмки и GPO](docs/windows-agent-rollout.md).
