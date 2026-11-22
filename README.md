# Seal Installer (Node.js)

Сервер для подписи и установки IPA на iOS. Чистый Node.js ≥ 18.13, **без зависимостей** (`npm install` не нужен).

## Запуск (Termux)

```bash
pkg install nodejs
cd Seal-Installer-main
cp .env.example .env            # отредактируйте PUBLIC_URL, SIGNER
# положите свой cert.p12, cert.mobileprovision, password.txt в certs/
set -a; . ./.env; set +a
node server.js
```

Откройте `http://localhost:8080`, выберите `.ipa` → «Подписать и установить».

## Бэкенды подписи (`SIGNER`)
- `js` — **встроенная подпись на чистом JS (по умолчанию)**: Mach-O (arm64, fat), CodeDirectory SHA-1 + SHA-256, CMS, `CodeResources`, entitlements из профиля, вложенные фреймворки/dylib/appex, смена bundle id под профиль. Нужны ваши `certs/cert.p12` + `certs/cert.mobileprovision` (+ `password.txt`). Для чтения `.p12` нужен `openssl` (`pkg install openssl-tool`); можно вместо него положить `certs/identity.pem` (ключ + сертификат + цепочка Apple WWDR). Только RSA-ключи, IPA до 4 ГБ, целиком в памяти.
- `zsign` — локально, нужен бинарник [zsign](https://github.com/zhlynn/zsign) в PATH (или `ZSIGN_BIN`).
- `api` — внешний сервис (`SIGN_API_URL`), как в оригинальном проекте.

## Автозагрузка сертификатов из вашего API
Задайте `CERT_API_URL` (и `CERT_API_AUTH`, если API закрыт). При старте и каждые 30 минут сервер запрашивает `CERT_API_PATH`
(по умолчанию `/api/certificates/list/signed/5`), берёт первый не отозванный сертификат, скачивает `p12` и `mobileprovision`,
проверяет срок действия и пароль и только после этого заменяет файлы в `certs/`. При ошибке остаётся прежний сертификат.
Поля ищутся по именам (`*p12*`, `*provision*`, `*pass*`; значения — URL, относительный путь или base64), список — в корне, `certificates`, `data`, `items` или `results`.
Статус синхронизации виден в `GET /api/config`.

## Важно
- Установка через `itms-services` работает **только по HTTPS** с валидным сертификатом. Для телефона: туннель (cloudflared / ngrok), его адрес — в `PUBLIC_URL`.
- Сертификаты лежат на сервере и в браузер не отдаются. Для защиты API задайте `ACCESS_TOKEN`.
- Старый сертификат из репозитория (GLOBAL TAKEOFF, INC, истёк 2026-06-26) не используется; оригинальные файлы лежат в `legacy/`. Используйте только свой сертификат.

## API
- `POST /api/sign` — тело: сырой IPA (`application/octet-stream`), заголовок `X-Token` при включённом токене.
- `GET /manifest/<id>.plist`, `GET /files/<id>.ipa`, `GET /api/config`.

## Тесты
`npm test` (нужны python3 и openssl). Тесты проверяют структуру подписи и CMS через `openssl cms -verify`; **принятие подписи самим iOS на устройстве тесты не проверяют**.
