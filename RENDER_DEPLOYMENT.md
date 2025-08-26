# 🚀 Развертывание HomeCloud Server на Render.com

## 📋 Требования

- GitHub репозиторий с кодом
- Аккаунт на [Render.com](https://render.com)

## 🔧 Настройка Render.com

### 1. Создание нового Web Service

1. Войдите в [Render Dashboard](https://dashboard.render.com)
2. Нажмите "New +" → "Web Service"
3. Подключите ваш GitHub репозиторий

### 2. Настройка сервиса

- **Name**: `homecloud-server`
- **Environment**: `Java`
- **Region**: Выберите ближайший к вам
- **Branch**: `main` (или ваша основная ветка)
- **Build Command**: `mvn clean package -DskipTests`
- **Start Command**: `java -jar target/*.jar`

### 3. Переменные окружения

```bash
BIND_ADDRESS=0.0.0.0
HTTP_THREAD_POOL_SIZE=20
RENDER_ENVIRONMENT=production
UPLOADS_DIR=/opt/render/project/src/uploads
JWT_SECRET=your-secret-key-here
JAVA_OPTS=-Xmx512m -Xms256m
```

### 4. Health Check

- **Health Check Path**: `/health`
- **Auto-Deploy**: Включено

## 🐳 Docker (опционально)

Если хотите использовать Docker:

1. **Build Command**: `docker build -t homecloud-server .`
2. **Start Command**: `docker run -p 8080:8080 -p 8081:8081 homecloud-server`

## 📁 Структура проекта

```
java_websocket/
├── src/main/java/org/example/
│   ├── UnifiedServer.java          # Основной сервер
│   └── AdminHttpServer.java        # HTTP админ-панель
├── src/main/resources/
│   └── admin_panel.html            # Веб-интерфейс
├── pom.xml                         # Maven зависимости
├── Dockerfile                      # Docker образ
└── render.yaml                     # Render.com конфигурация
```

## 🔍 Проверка развертывания

### 1. WebSocket Server
- **URL**: `wss://your-app-name.onrender.com:8080`
- **Статус**: Проверьте логи в Render Dashboard

### 2. Admin Panel
- **URL**: `https://your-app-name.onrender.com:8081/admin`
- **Функции**: Статистика, мониторинг, логи

### 3. Health Check
- **URL**: `https://your-app-name.onrender.com:8081/health`
- **Ожидаемый ответ**: JSON с статусом "healthy"

## 🚨 Устранение неполадок

### Ошибка сборки Maven
- Проверьте, что `pom.xml` корректен
- Убедитесь, что все зависимости доступны
- Проверьте логи сборки в Render Dashboard

### Ошибка запуска Java
- Проверьте версию Java (должна быть 17+)
- Убедитесь, что JAR файл создался в `target/`
- Проверьте переменные окружения

### Проблемы с портами
- Render.com автоматически назначает порты
- Используйте `0.0.0.0` для bind address
- Проверьте, что порты 8080 и 8081 открыты

## 📊 Мониторинг

### Render Dashboard
- **Logs**: Просмотр логов в реальном времени
- **Metrics**: CPU, память, сеть
- **Deployments**: История развертываний

### Admin Panel
- **Server Stats**: Активные соединения, запросы
- **Client List**: Подключенные клиенты
- **Server Logs**: Детальные логи сервера

## 🔗 Полезные ссылки

- [Render.com Documentation](https://render.com/docs)
- [Java WebSocket](https://github.com/TooTallNate/Java-WebSocket)
- [Netty Framework](https://netty.io/)
- [JWT Authentication](https://jwt.io/)

## 📞 Поддержка

Если возникли проблемы:

1. Проверьте логи в Render Dashboard
2. Убедитесь, что все файлы закоммичены в Git
3. Проверьте переменные окружения
4. Обратитесь к документации Render.com
