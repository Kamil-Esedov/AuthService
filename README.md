# AuthService

Сервис аутентификации на Go с HTTP- и gRPC-интерфейсами. Сервис поддерживает
регистрацию и вход пользователей, JWT access/refresh-токены, завершение сессий
и получение данных текущего пользователя.

## Возможности

- регистрация пользователя и проверка email/пароля;
- вход с выдачей access- и refresh-токенов;
- обновление и отзыв refresh-токенов;
- получение профиля текущего пользователя;
- хранение пользователей и refresh-сессий в PostgreSQL;
- bcrypt-хеширование паролей;
- HTTP API и gRPC API.

## Стек

- Go 1.26;
- PostgreSQL 16;
- Docker Compose;
- chi для HTTP-маршрутизации;
- gRPC и Protocol Buffers;
- JWT и bcrypt;
- zap logger.

## Быстрый запуск

Требования: Go, Docker с Docker Compose и `protoc` с Go-плагинами (плагины
нужны только для генерации gRPC-кода).

1. Создайте файл `.env` на основе `.env.example`:

   ```bash
   cp .env.example .env
   ```

2. Задайте в `.env` непредсказуемое значение `JWT_SECRET`.

3. Запустите PostgreSQL, миграции и приложение:

   ```bash
   docker compose up --build
   ```

После запуска:

- HTTP API доступен на `http://localhost:8080`;
- gRPC API доступен на `localhost:50051`.

Остановить контейнеры можно командой:

```bash
docker compose down
```

Для удаления данных PostgreSQL вместе с контейнерами используйте `docker compose
down -v`.

## Конфигурация

Приложение загружает `.env.local`, затем `.env`. Обязательные переменные:
`JWT_SECRET`, `POSTGRES_DB`, `POSTGRES_PASSWORD`, `POSTGRES_USER` и
`POSTGRES_HOST`.

| Переменная          | По умолчанию | Описание                            |
| ------------------- | ------------ | ----------------------------------- |
| `APP_PORT`          | `8080`       | Порт HTTP-сервера                   |
| `GRPC_PORT`         | `50051`      | Порт gRPC-сервера                   |
| `HASH_COST`         | `10`         | Стоимость bcrypt                    |
| `ACCESS_TOKEN_TTL`  | `15`         | Время жизни access-токена в минутах |
| `REFRESH_TOKEN_TTL` | `720`        | Время жизни refresh-токена в часах  |
| `POSTGRES_HOST`     | —            | Хост PostgreSQL                     |
| `POSTGRES_PORT`     | `5432`       | Порт PostgreSQL                     |
| `POSTGRES_DB`       | —            | Имя базы данных                     |
| `POSTGRES_USER`     | —            | Пользователь PostgreSQL             |
| `POSTGRES_PASSWORD` | —            | Пароль PostgreSQL                   |
| `JWT_SECRET`        | —            | Секрет подписи JWT                  |

## HTTP API

### Регистрация

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123"}'
```

Ответ содержит идентификатор созданного пользователя:

```json
{ "id": "<user-id>" }
```

### Вход

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123"}'
```

Ответ:

```json
{
  "access_token": "<access-token>",
  "refresh_token": "<refresh-token>"
}
```

### Получение текущего пользователя

Передайте access-токен в заголовке `Authorization`:

```bash
curl http://localhost:8080/api/users/me \
  -H "Authorization: Bearer <access-token>"
```

### Обновление токенов

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh-token>"}'
```

### Выход

```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh-token>"}'
```

Пароль при регистрации должен содержать от 8 до 72 символов. Формат
запросов и protobuf-контракт описаны в
[`proto/auth/v1/auth.proto`](./proto/auth/v1/auth.proto).

## Локальная разработка

Для запуска приложения без Docker укажите `POSTGRES_HOST=localhost` и
подключитесь к локальному PostgreSQL, затем примените миграции из каталога
[`migrations`](./migrations):

```bash
go run ./cmd/auth
```

## gRPC API

gRPC-сервер доступен на `localhost:50051`. Описание сервиса находится в
[`proto/auth/v1/auth.proto`](./proto/auth/v1/auth.proto), сгенерированные Go-типы
и клиент — в [`gen/auth/v1`](./gen/auth/v1).

Сервис `AuthService` предоставляет следующие методы:

| Метод      | Запрос            | Ответ                   | Авторизация            |
| ---------- | ----------------- | ----------------------- | ---------------------- |
| `Register` | `RegisterRequest` | `RegisterResponse`      | не требуется           |
| `Login`    | `LoginRequest`    | `TokenPair`             | не требуется           |
| `Refresh`  | `RefreshRequest`  | `TokenPair`             | не требуется           |
| `Logout`   | `LogoutRequest`   | `google.protobuf.Empty` | не требуется           |
| `GetMe`    | `GetMeRequest`    | `User`                  | требуется access-токен |

Для `GetMe` передайте access-токен в gRPC metadata:

```text
authorization: Bearer <access-token>
```

Для `Login` и `Refresh` сервер также использует metadata `user-agent` и
информацию о клиентском адресе для создания refresh-сессии.

Основные сообщения:

- `RegisterRequest` и `LoginRequest` содержат `email` и `password`;
- `RegisterResponse` возвращает `user_id`;
- `RefreshRequest` и `LogoutRequest` содержат `refresh_token`;
- `TokenPair` возвращает `access_token` и `refresh_token`;
- `User` содержит `id`, `email`, `role`, `is_verified`, `created_at` и
  `updated_at`;
- значения `Role`: `ROLE_USER` и `ROLE_ADMIN`.

Для вызовов из grpcurl можно использовать reflection-клиент или скомпилировать
описание из `.proto` с подключением стандартных protobuf-файлов. Пример
регистрации:

```bash
grpcurl -plaintext \
  -d '{"email":"user@example.com","password":"password123"}' \
  localhost:50051 auth.v1.AuthService/Register
```

Пример получения текущего пользователя:

```bash
grpcurl -plaintext \
  -H 'authorization: Bearer <access-token>' \
  -d '{}' \
  localhost:50051 auth.v1.AuthService/GetMe
```
