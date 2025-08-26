# Используем официальный образ Java 17
FROM openjdk:17-jdk-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем JAR файл
COPY target/*.jar app.jar

# Копируем ресурсы
COPY src/main/resources/ ./resources/

# Создаем директорию для логов
RUN mkdir -p /app/logs

# Создаем директорию для загрузок
RUN mkdir -p /app/uploads

# Устанавливаем переменные окружения для Render.com
ENV BIND_ADDRESS=0.0.0.0
ENV HTTP_THREAD_POOL_SIZE=20
ENV RENDER_ENVIRONMENT=production
ENV UPLOADS_DIR=/app/uploads
ENV JWT_SECRET=your-secret-key-here

# Открываем порты
EXPOSE 8080 8081

# Создаем пользователя для безопасности
RUN useradd -r -s /bin/false appuser
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1

# Запускаем приложение
CMD ["java", "-jar", "app.jar"]