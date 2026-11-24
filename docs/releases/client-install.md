# DeployCore Server 1.0 Beta

## Установка на Ubuntu 22.04 или 24.04

Поддерживаемая архитектура — x86_64. Используйте отдельный клиентский Linux-хост с доступом к Ubuntu, Docker Hub и GitHub. Для установки нужны права sudo.

```bash
command -v curl >/dev/null || (sudo apt-get update && sudo apt-get install -y curl ca-certificates)
version=1.0.0-beta.4
base="https://github.com/komissar0vka/DeployCore-Releases/releases/download/v${version}"
mkdir deploycore-server && cd deploycore-server
curl -fLO "$base/deploycore-server-${version}.tar.gz"
curl -fLO "$base/SHA256SUMS"
curl -fLO "$base/deploycore-cloud-ca.pem"
curl -fLO "$base/upgrade-beta3.py"
sha256sum -c SHA256SUMS
tar -xzf "deploycore-server-${version}.tar.gz"
sudo bash install.sh
```

Установщик использует образы GHCR по digest или готовые образы из того же архива при недоступности реестра.

Введите DNS-имя или IPv4-адрес, доступный агентам, и HTTPS-порт. Укажите каталог с доверенным сертификатом и ключом либо используйте самоподписанный сертификат установщика. Для самоподписанного варианта добавьте `deploy/tls/fullchain.pem` в доверенные сертификаты Windows и браузера. Установщик выводит адрес панели. Откройте мастер и получите первоначальный секрет командой `sudo sed -n 's/^DEPLOYCORE_SETUP_TOKEN=//p' deploy/.env`. Мастер создаёт первого Super Admin. Free предоставляет 5 мест сразу.

## Подключение к Cloud

Администратор Cloud создаёт организацию, выдаёт Business или Enterprise и передаёт токен активации по защищённому каналу. Возьмите у него два публичных ключа Ed25519. Если Cloud использует собственный CA или сертификат, получите PEM по доверенному каналу и сверьте отпечаток перед использованием.

```bash
sudo python3 deploy/scripts/connect-cloud.py https://153.80.178.28:8444 LICENSE_PUBLIC_KEY RELEASE_PUBLIC_KEY --ca deploycore-cloud-ca.pem
```

Вставьте токен в скрытый запрос. В разделе «Лицензия» отобразится редакция, квота и срок текущей выдачи. Server проверяет лицензию каждые пять минут. При потере связи подписанная выдача действует до указанного срока, затем начинается 14-дневный льготный период. После него применяется Free. Cloud получает UUID, публичный ключ и версию экземпляра. Данные компьютеров, программ и заданий остаются в клиентской сети.

## Переход с beta.3

Для существующего Server с настроенным Cloud запусти команду из его каталога. Скрипт проверяет подписанный релиз и применяет готовые образы. Перед переключением он проверяет восстановление БД в отдельной базе. HTTPS, учётные записи, пакеты, устройства и идентичность экземпляра сохраняются.

```bash
root="$PWD"
temp=$(mktemp -d)
(
  set -e
  cd "$temp"
  base=https://github.com/komissar0vka/DeployCore-Releases/releases/download/v1.0.0-beta.4
  curl -fsSLO "$base/upgrade-beta3.py"
  curl -fsSLO "$base/SHA256SUMS"
  awk '$2=="upgrade-beta3.py"' SHA256SUMS | sha256sum -c -
  sudo python3 upgrade-beta3.py "$root"
)
```

На Ubuntu с systemd установка включает локальную службу операций хоста. В разделе «Настройки» суперадминистратор создаёт и скачивает копии. В разделе «Лицензия» он проверяет каналы, выбирает подходящий выпуск и подтверждает обновление. После переключения панель покажет завершение или ошибку и ход отката. Копии перед обновлением остаются в `deploy/.updater`.

Пакеты резервных копий содержат локальную конфигурацию, TLS и идентичность экземпляра. Храни их с доступом, предназначенным для суперадминистраторов. Сценарий агента доступен в комплекте обновления на странице «Установка агента».
