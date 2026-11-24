# DeployCore Server 1.0 Beta

## Установка на Ubuntu 22.04 или 24.04

Поддерживаемая архитектура — x86_64. Используйте отдельный клиентский Linux-хост с доступом к Ubuntu, Docker Hub и GitHub. Для установки нужны права sudo.

```bash
command -v curl >/dev/null || (sudo apt-get update && sudo apt-get install -y curl ca-certificates)
version=1.0.0-beta.3
base="https://github.com/komissar0vka/DeployCore-Releases/releases/download/v${version}"
mkdir deploycore-server && cd deploycore-server
curl -fLO "$base/deploycore-server-${version}.tar.gz"
curl -fLO "$base/SHA256SUMS"
curl -fLO "$base/deploycore-cloud-ca.pem"
sha256sum -c SHA256SUMS
tar -xzf "deploycore-server-${version}.tar.gz"
sudo bash install.sh
```

Введите DNS-имя или IPv4-адрес, доступный агентам, и HTTPS-порт. Укажите каталог с доверенным сертификатом и ключом либо используйте самоподписанный сертификат установщика. Для самоподписанного варианта добавьте `deploy/tls/fullchain.pem` в доверенные сертификаты Windows и браузера. Установщик выводит адрес панели. Откройте мастер и получите первоначальный секрет командой `sudo sed -n 's/^DEPLOYCORE_SETUP_TOKEN=//p' deploy/.env`. Мастер создаёт первого Super Admin. Free предоставляет 5 мест сразу.

## Подключение к Cloud

Администратор Cloud создаёт организацию, выдаёт Business или Enterprise и передаёт токен активации по защищённому каналу. Возьмите у него два публичных ключа Ed25519. Если Cloud использует собственный CA или сертификат, получите PEM по доверенному каналу и сверьте отпечаток перед использованием.

```bash
sudo python3 deploy/scripts/connect-cloud.py https://153.80.178.28:8444 LICENSE_PUBLIC_KEY RELEASE_PUBLIC_KEY --ca deploycore-cloud-ca.pem
```

Вставьте токен в скрытый запрос. В разделе «Лицензия» отобразится редакция, квота и срок текущей выдачи. Server проверяет лицензию каждые пять минут. При потере связи подписанная выдача действует до указанного срока, затем начинается 14-дневный льготный период. После него применяется Free. Cloud получает UUID, публичный ключ и версию экземпляра. Данные компьютеров, программ и заданий остаются в клиентской сети.

## Обновление Server

Раздел «Лицензия» показывает подписанный каталог Stable или Beta. Запускайте обновление на хосте в согласованное окно обслуживания.

```bash
sudo python3 deploy/scripts/update-server.py beta НОВАЯ_ВЕРСИЯ
```

Команда проверяет подпись каталога, канал, срок, версию, URL, размер и SHA-256 архива. Перед заменой контейнеров она сохраняет конфигурацию, БД и тома пакетов и идентичности, проверяет восстановление БД и сохраняет прежние образы. При ошибке запуска восстанавливает БД и прежние образы. Архивы остаются в `deploy/.updater`. Автоматическое применение рассчитано на релизы с той же Compose-конфигурацией. Изменение топологии требует отдельной миграции.
