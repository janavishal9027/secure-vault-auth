# Multi-stage build for the Authentication service.
#
#   Stage 1: maven:3.9-eclipse-temurin-21 — runs `mvn package` so the build
#            environment doesn't pollute the runtime image. Java 21 because
#            the pom.xml targets Java 21 features (Spring Boot 3, jakarta.*).
#
#   Stage 2: eclipse-temurin:21-jre — JRE-only image with just the produced
#            jar. Smaller footprint, fewer CVEs than a JDK image.
#
# server.port in application.yml is 3211 and server.servlet.context-path is
# /authentication, so the service responds at  http://<host>:3211/authentication/*
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app

# Build-arg labels for traceability. Set by the pipeline:
#   GIT_COMMIT     full commit SHA (image tag matches)
#   BUILD_NUMBER   Bitbucket auto-incrementing pipeline build number
#   BUILD_DATE     ISO-8601 timestamp at build time
ARG GIT_COMMIT=unknown
ARG BUILD_NUMBER=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.source="https://bitbucket.org/<workspace>/secure-vault-authentication"
LABEL bitbucket.build.number="${BUILD_NUMBER}"
LABEL version="${BUILD_NUMBER}"

COPY --from=build /app/target/*.jar app.jar
EXPOSE 3211
ENTRYPOINT ["java", "-jar", "app.jar"]
