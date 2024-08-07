# Проект переехал во внутренний гитлаб, тут больше не поддерживается и скоро будет удален


# IAM middleware

Пакет для подключения аутентификации и авторизации на бэкенде через SAPI IAM.

## Общий принцип работы:
* пакет подключается на бэкенде как middleware
* все запросы, проходящие через эту middleware, проверяются на наличие служебных кук (см. ниже)
* если кука есть, токен и его права проверяются в сервисе IAM
* если куки нет или токен протух, пользователя перекидывает на страницу аутентификации в Keycloak (ссылка генерится в IAM)
* после успешной аутентификации пользователь возвращается обратно, после чего middleware сохраняет в **secure** куки информацию:
  * **UserEmail** - емыл пользователя
  * **UserName** - имя-фамилию пользователя
  * **iam_token_id** - id токена (**HTTP-only**)
* также либа кладет в контекст массив пермишенов, получить его можно из функции **GetPermissions(ctx)**

## Подключение

### Nginx

Пакет работает с использованием **secure** и **http-only** кук, поэтому фронт и бэк должны висеть на одном HTTPS-домене.
Если запросы на бэк проксируются с помощью **proxy_pass**, важно передать на бэк заголовок **Host**, а также **X-Original-Request-URI** - это
URL оригинального внешнего запроса, чтобы либа смогла вернуть пользователья на этот URL.

````nginx configuration
location /api/admin/ {
        proxy_pass                                  http://backend:9000/api/;
        proxy_set_header Host                       $host;
        proxy_set_header X-Original-Request-URI     $request_uri;
    }
````

### Примеры использования 

См. в директории examples
