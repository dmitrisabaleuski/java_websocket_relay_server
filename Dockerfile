# Build stage
FROM gradle:8.5.0-jdk21 AS build

WORKDIR /app

# Copy Gradle files first (for better caching)
COPY settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
RUN chmod +x ./gradlew
RUN mkdir -p src/main/java src/main/resources

# Copy Java source code
COPY src ./src

# Build
RUN ./gradlew shadowJar --no-daemon --stacktrace

# Runtime stage
FROM eclipse-temurin:21-jre

WORKDIR /app

# Create uploads directory
RUN mkdir -p /app/uploads

# Copy built JAR
COPY --from=build /app/build/libs/*-all.jar app.jar

EXPOSE 8080

# Smart entrypoint: Works with or without PostgreSQL
RUN echo '#!/bin/bash\n\
set -e\n\
if [ -n "$DATABASE_URL" ]; then\n\
  echo "DATABASE_URL detected: $DATABASE_URL"\n\
  host=$(echo $DATABASE_URL | sed -E "s|.*@([^:]+):.*|\\1|")\n\
  echo "PostgreSQL host: $host"\n\
  if [ "$host" != "localhost" ] && [ "$host" != "127.0.0.1" ]; then\n\
    echo "External PostgreSQL detected, checking connection..."\n\
    # Extract host from connection string\n\
    if command -v pg_isready &> /dev/null; then\n\
      until pg_isready -h "$host"; do\n\
        echo "Waiting for PostgreSQL at $host..."\n\
        sleep 2\n\
      done\n\
      echo "PostgreSQL is ready!"\n\
    fi\n\
  fi\n\
else\n\
  echo "No DATABASE_URL found, using in-memory storage"\n\
fi\n\
echo "Starting HomeCloud server..."\n\
exec java -jar app.jar' > /app/start.sh && chmod +x /app/start.sh

# Install postgresql-client if DATABASE_URL is used
RUN apt-get update && apt-get install -y postgresql-client && rm -rf /var/lib/apt/lists/*

CMD ["/app/start.sh"]