# Build stage
FROM gradle:8.5.0-jdk21 AS build

WORKDIR /app
COPY build.gradle.kts settings.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
RUN chmod +x ./gradlew
COPY src ./src
RUN ./gradlew build --no-daemon

# Runtime stage
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8080

CMD ["java", "-cp", "app.jar", "org.example.UnifiedServer"]