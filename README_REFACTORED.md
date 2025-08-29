# HomeCloud Server - Refactored Version

## 🚀 **Новая архитектура сервера**

### **📁 Структура файлов:**
```
src/main/java/org/example/
├── UnifiedServerRefactored.java    # Главный класс сервера
├── UnifiedServerHandler.java       # Обработчик HTTP/WebSocket
├── AdminPanel.java                 # Админ-панель и веб-интерфейс
├── ServerStatistics.java           # Статистика и метрики сервера
└── utils/
    ├── AdminLogger.java            # Система логирования
    └── ServerConfig.java           # Конфигурация сервера
```

## 🎯 **Как запустить:**

### **1. Сборка:**
```bash
cd relay_server/java_websocket_relay_server/java_websocket
./gradlew shadowJar
```

### **2. Запуск:**
```bash
java -jar build/libs/java_websocket_relay_server-all.jar
```

### **3. Доступ к админ-панели:**
- **URL:** `http://localhost:8080/admin`
- **Логин:** `admin`
- **Пароль:** `admin123`

## 🔧 **Конфигурация через переменные окружения:**

```bash
# Порт сервера (по умолчанию: 8080)
export PORT=8080

# Директория для загрузок (по умолчанию: uploads)
export UPLOADS_DIR=uploads

# JWT секрет (по умолчанию: your-secret-key-change-this-in-production)
export JWT_SECRET=your-secret-key

# Логин админа (по умолчанию: admin)
export ADMIN_USERNAME=admin

# Пароль админа (по умолчанию: admin123)
export ADMIN_PASSWORD=admin123
```

## 📊 **Доступные API endpoints:**

### **Основные:**
- `POST /api/token` - получение JWT токена
- `GET /health` - проверка состояния сервера

### **Админ-панель:**
- `GET /admin` - страница входа
- `POST /admin/login` - аутентификация
- `GET /admin/dashboard` - дашборд

### **API для админа:**
- `GET /api/stats` - статистика сервера
- `GET /api/clients` - список клиентов
- `GET /api/logs` - логи сервера

## 🌟 **Преимущества новой архитектуры:**

1. **Модульность** - код разделен на логические компоненты
2. **Читаемость** - каждый файл отвечает за свою область
3. **Поддержка** - легче вносить изменения и исправления
4. **Расширяемость** - просто добавлять новые функции
5. **Тестируемость** - каждый модуль можно тестировать отдельно

## 🔄 **Миграция со старой версии:**

1. **Остановите старый сервер**
2. **Запустите новый:** `java -jar java_websocket_relay_server-all.jar`
3. **Все функции работают так же!**

## 🚨 **Важно:**

- **Старый файл** `UnifiedServer.java` остается для совместимости
- **Новый файл** `UnifiedServerRefactored.java` - основная версия
- **Все WebSocket соединения** работают без изменений
- **Админ-панель** доступна сразу после запуска

## 📝 **Логирование:**

Все события логируются в консоль и доступны через админ-панель:
- Системные события
- Подключения клиентов
- Админские действия
- Ошибки и исключения

## 🎉 **Готово к использованию!**

Новый сервер полностью функционален и готов к работе! 🚀✨
