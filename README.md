# Сервис аутентификации

## Как запустить

Для запуска нужно в терминале в корне проекта ввести:

```docker-compose -f docker-compose.yml up -d```

Swagger UI после запуска будет доступен на:

http://localhost:8080/swagger/index.html

## Токены

Access JWT token с подписью SHA512.

Refresh token генерируется как base64 представление 32 случайных байтов.

## Переменные окружения
Переменные хранятся в [.env](.env) файле.
+ ```DATABASE_PORT``` - порт базы данных
+ ```DATABASE_USER``` - имя пользователя бд
+ ```DATABASE_PASSWORD``` - пароль пользователя бд
+  ```DATABASE_NAME``` - имя базы данных
+  ```DATABASE_HOST``` - имя хоста базы данных
+  ```SECRET_KEY``` - секрет для генерации подписей JWT токенов
+  ```SERVER_IP``` - IP сервера
+  ```SERVER_PORT``` - порт сервера
+  ```WEBHOOK_URL``` - url куда отправляются вебхуки при смене IP пользователя

## Деплой
[Dockerfile](Dockerfile) для сервера, сервер и бд развертываются в [docker-compose.yml](docker-compose.yml).

## Документация
Документация в [docs.go](docs/docs.go), [swagger.json](docs/swagger.json) and [swagger.yaml](docs/swagger.yaml).

## Маршрути
+ /create - создать пару access и refresh токенов
+ /refresh - обновить пару токенов
+ /logout - деавторизация пользователя, блокирует все токены по guid
+ /me - получение GUID текущего пользователя

При несовпадении User Agent в refresh маршруте все токены блокируются по guid, как и при деавторизации пользователя.

В маршрутах /logout и /me проверяется access токен, в том числе на статус не "blocked" в бд по id.

В маршруте /refresh также проверяется статус на не "blocked" и не "used" по id.

## База данных
База данных хранит:
+ id токена (одинаковый для access и refresh токенов)
+ guid пользователя
+ bcrypt хэш refresh токена
+ status (used, unused, blocked)