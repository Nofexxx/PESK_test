# Flask Auth API with JWT, Redis, Docker

## Описание
Проект представляет собой систему авторизации и аутентификации с использованием Flask, JWT и Redis, реализующую:
- Белый и чёрный список токенов
- Разграничение доступа по ролям
- Docker-контейнеризацию
- Автотесты (Pytest)

Выбран подход REST API — он прост в использовании, хорошо поддерживается во Flask и позволяет использовать JWT-токены для авторизации через стандартный заголовок `Authorization`.

## Угрозы безопасности и защита

- Возможные утечки: XSS, MITM, кража токена при компрометации устройства.
- Реализован белый и чёрный список токенов:
  - Белый — содержит валидные токены (только они допускаются к использованию).
  - Чёрный — токены, отозванные через logout.
- Ограниченное время жизни access-токена.
- Refresh токен имеет отдельный срок и может быть дополнительно защищён.

Таким образом, токен может быть принудительно отозван (например, через logout), а его срок действия ограничен.

## Как запустить

### Создание .env
Файл `.env`:
```env
SECRET_KEY=your_secret_key
JWT_SECRET_KEY=your_jwt_secret_key
REDIS_HOST=redis
REDIS_PORT=6379
```

### Запуск с Docker Compose
```bash
cd src
docker-compose up --build
```

API будет доступен на: [http://localhost:5000](http://localhost:5000)

## Тесты

Запуск тестов:

```bash
docker exec -it <container_name> pytest
```

## Роли и доступ
| Роль   | Эндпоинты                     |
|--------|-------------------------------|
| Viewer | `/shared-content`             |
| Admin  | `/shared-content`, `/admin-only` |

## Стек технологий
- Flask
- Flask-JWT-Extended
- Redis
- SQLAlchemy (SQLite)
- Pytest
- Docker / Docker Compose


