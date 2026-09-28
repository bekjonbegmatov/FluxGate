# Эксплуатация FluxGate

## Установка с нуля

На чистом Ubuntu/Debian выполните команду из README. `install.sh` ставит Docker Engine и Compose из официального apt-репозитория при необходимости, клонирует `bekjonbegmatov/FluxGate` в `/opt/fluxgate`, создаёт `.env` с криптографически случайными токеном и master key, запускает два контейнера и печатает URL/токен. Повторный запуск сохраняет `.env` и том, обновляет код fast-forward и пересобирает контейнеры. Требуются свободные TCP 443 и 9389, достаточное место для сборки. При отсутствии swap и свободных 4 GiB диска установщик создаёт swap 2 GiB. Укажите `FLUXGATE_DOMAIN=example.com`, если основной домен должен отличаться от `cubeland.top`.

Контейнеры: `haproxy` публикует 443/9389 и читает `/data/haproxy.cfg`; `panel` разделяет его network namespace, создаёт конфиг и данные в общем томе. Для диагностики: `cd /opt/fluxgate && docker compose -p fluxgate ps && docker compose -p fluxgate logs --tail=100`. Секреты — `/opt/fluxgate/.env` с режимом 0600. Данные — Docker volume `fluxgate_panel-data`. Не публикуйте `.env` и архивы.

На текущем VPS дополнительно существует нативная установка в `/root/haproxy-panel`, `/usr/local/bin/fluxgate-panel`, `/opt/fluxgate/web`, `/var/lib/fluxgate`, `/etc/fluxgate/fluxgate.env`. Службы: `fluxgate-panel.service`, `fluxgate-haproxy.service`. Публичный URL определяется IP сервера и портом 9389. Нативный и Docker варианты нельзя одновременно запускать на одних 443/9389.

## Конфигурация

| Переменная | Значение |
| --- | --- |
| `PANEL_DATA` | SQLite, сертификаты, HAProxy config, staging восстановления |
| `PANEL_WEB` | Собранный React |
| `PANEL_LISTEN` | Панель, стандартно `0.0.0.0:9389` |
| `PANEL_SECRET_PATH` | Стандартно `admin`; для иного пути нужно пересобрать Vite |
| `PANEL_DOMAIN` | Начальный fallback домен, затем значение из SQLite |
| `PANEL_TIMEZONE` | Часовой пояс квот и аренды, после restore значение из SQLite |
| `PANEL_FLUSH_INTERVAL` | Интервал пакетного сохранения трафика: `5s`, допустимо `1s`–`1m` |
| `PANEL_TOKEN` | Токен входа, минимум 24 символа |
| `PANEL_MASTER_KEY` | Шифрование Telegram token и подпись сессий, минимум 24 символа |

`PANEL_TOKEN` новой установки остаётся действующим после загрузки backup. Нельзя менять `PANEL_MASTER_KEY` произвольно в работающей установке: зашифрованный токен Telegram перестанет читаться. При переносе через архив backup токен Telegram перешифровывается автоматически.

## Backup и восстановление

В «Настройках» скачайте ZIP. Он включает данные и чувствительный Telegram token; храните его вне публичного HTTP каталога. Установите FluxGate на новом VPS, войдите с **новым** токеном, загрузите ZIP в «Настройках». Панель проверит архив, ответит 202 и перезапустится. Подождите несколько секунд и откройте тот же URL. Для нативного процесса проверьте `systemctl is-active fluxgate-panel fluxgate-haproxy`; для Docker — `docker compose -p fluxgate ps`. Прежние файлы автоматически сохраняются в `PANEL_DATA/before-restore-*` для ручного отката.

Для ручного отката: остановите оба сервиса/контейнера, сохраните текущие `panel.db`, `panel.db-wal`, `panel.db-shm`, `certs`, верните соответствующие файлы из `before-restore-*` и запустите сервисы. Не копируйте открытую SQLite базу без WAL; для обычных резервных копий используйте ZIP из панели.

## Обновление

Для Docker-установки из README:

```bash
curl -fsSL https://raw.githubusercontent.com/bekjonbegmatov/FluxGate/main/update.sh -o /tmp/fluxgate-update.sh && sudo bash /tmp/fluxgate-update.sh
```

`update.sh` блокирует параллельные обновления, проверяет чистоту checkout, скачивает выбранный ref (по умолчанию main) и собирает код во временной папке. `deploy/update-docker.sh` сохраняет ссылки на прежние образы и resolved Compose-конфигурацию, выполняет сборку, затем получает согласованный ZIP через локальный авторизованный API и проверяет целостность архива. В `/var/backups/fluxgate/<дата>` остаются ZIP, `.env`, прежний commit и `rollback.compose.json` (права 0700/0600). Прежние образы сохраняются под тегами `fluxgate-rollback-*`. Секреты не передаются аргументами команд и не печатаются.

После fast-forward обновления checkout пересоздаются **оба** контейнера: панель разделяет network namespace HAProxy и не должна оставаться привязанной к удалённому контейнеру. Проверяются Docker healthcheck, авторизованный API и HTTPS fallback через SNI на 443. При ошибке переключения автоматически запускаются прежние образы. База остаётся текущей — автоматический откат не заменяет её устаревшим backup. В этом обновлении миграции только добавляют индексы и совместимы со старой версией. Checkout при откате может остаться на новом commit; работающие контейнеры используют сохранённые образы.

Ручной откат образов: `sudo docker compose -p fluxgate -f /var/backups/fluxgate/НУЖНАЯ-ДАТА/rollback.compose.json up -d --no-build --pull never --force-recreate`. Восстановление данных из ZIP — отдельная операция через панель. Backup и образы не удаляются автоматически: после проверки установки ненужные старые копии можно удалить вручную.

Обновление предусматривает короткий перерыв и переподключение активных соединений. Параметры: `FLUXGATE_DIR` (checkout), `FLUXGATE_PROJECT` (Compose-проект), `FLUXGATE_REF` (ветка или commit), `FLUXGATE_BACKUP_DIR`. Скрипт рассчитан на стандартный `compose.yaml` из установщика; при неизвестном наборе Compose-файлов в labels контейнеров он останавливается до сборки и переключения. При своих override-файлах/портах сделайте backup и сборку вручную, затем пересоздайте оба сервиса с вашими Compose-параметрами. Нативно: из checkout запустите `sudo bash deploy/install-native.sh`; файл `/etc/fluxgate/fluxgate.env` сохраняется, backup предварительно скачивается через панель.

Статистика запросов собирается с момента её включения, трафик и HTTP-сэмплы старше 90 дней удаляются. После изменения `PANEL_FLUSH_INTERVAL` в `.env` примените среду через `docker compose -p fluxgate up -d --no-deps panel` из checkout; простой `restart` не перечитывает `.env`.

## Проверки

Дополнительно к базовым проверкам: `go test -race ./...`, `python3 deploy/test-update.py`, `python3 deploy/test-integration.py --seconds 60`. Последняя команда создаёт отдельный Docker-проект `fluxgate-integration-test`, слушает только loopback на 19389/19443 и удаляет только его тестовые контейнеры/том. Не запускайте нагрузочный тест одновременно с реальным трафиком на маленьком VPS.

`curl -fsS http://127.0.0.1:9389/healthz` проверяет SQLite и локальные listeners/сокет HAProxy. В Docker: `docker compose -p fluxgate exec -T panel /usr/local/bin/panel --healthcheck`. При статусе unhealthy сначала смотрите журналы: Docker сам по себе не перезапускает контейнер исключительно по unhealthy; перезапуск настроен на выход процесса. Watcher завершается при падении master, поэтому его автоматически перезапускает Docker/systemd. Оба образа явно используют `STOPSIGNAL SIGTERM`, чтобы панель сохраняла данные при остановке.

Авторизованный `/admin/api/system` показывает `goroutines`, `heap_bytes`, `relay_connections`, `db_wait_count`, `db_wait_seconds`. Сравнивайте их во время нагрузки и после её окончания. `PANEL_FLUSH_INTERVAL` меняет частоту записи, но не точность оперативной квоты или частоту расчёта скорости. На диске остаются только успешно сохранённые данные; продолжительный отказ хранилища увеличивает возможные потери при аварии процесса.

Разработка: `go test ./...`, `go vet ./...`, `npm --prefix web ci`, `npm --prefix web run build`, `bash -n install.sh`. Панель должна отвечать 200 на `/admin/`, а без cookie — 401 на `/admin/api/backup`. С cookie проверьте `/admin/api/routes`, `/admin/api/request-stats`, `/admin/api/backup`. Публичный proxy: `curl -sk --resolve cubeland.top:443:127.0.0.1 https://cubeland.top/`. Проверка `ss -lntp` должна показывать 443 и 9389 на публичных интерфейсах. У облачного провайдера может быть отдельный firewall; разрешите TCP 443/9389 там.

## Инциденты

- Панель не стартует: проверьте журналы, размер свободного диска, переменные и marker `restore.pending`. Не удаляйте marker/стейджинг без сохранения копии.
- HAProxy не принимает конфиг: `haproxy -c -f PANEL_DATA/haproxy.cfg`, затем проверьте сертификаты и права stats socket. Watcher не применяет невалидный конфиг.
- После restore нет Telegram: проверьте настройки Telegram и `PANEL_TIMEZONE`; archive содержит bot token, который импортируется под новым master key.
- Счётчики запросов нулевые сразу после запуска: первый опрос только фиксирует baseline; подождите 10–20 секунд и создайте запрос к конкретному SNI.
- Браузер предупреждает о TLS: сертификаты для 443 самоподписанные. Админка на 9389 всегда HTTP.
