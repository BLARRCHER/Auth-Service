Приложение авторизации для онлайн кинотеатра.
* Функции регистрации, авторизации, смена пароля и т.д
* Поддерживает JWT(access token + refresh token)
* Хранение невалидных токенов через Redis
* Просмотр истории входов
* Возможность ограничивать контент через выданные роли
* Swagger

# Инструкция:

Для запуска приложения:

1. Заполнить поля настроек, если потребуется, в файле `.env-dev` -> удалить суффикс `example`
2. Установить Docker и создать нужные образы с помощью команды `docker-compose -f docker-compose.yml up --build`.
3. Ознакомиться с документацией http://127.0.0.1/apidoc/swagger

Для запуска автотестов:
1. Установить зависимости из `auth_service/tests/functional/requirements-dev.txt`
2. Перейти в папку тестов `cd auth_service/tests/functional/src`
3. Запустить `pytest -v`