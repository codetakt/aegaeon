FROM maven:3-eclipse-temurin-17 AS build

ARG SUITE_REPO=https://github.com/openid-certification/conformance-suite.git
ARG SUITE_REF=master

RUN apt-get update && \
  apt-get install -y --no-install-recommends git ca-certificates && \
  rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${SUITE_REF}" "${SUITE_REPO}" /src
WORKDIR /src

RUN git rev-parse HEAD > /src/SUITE_COMMIT.txt

RUN mvn -B clean package -DskipTests=true

FROM eclipse-temurin:17

WORKDIR /opt/suite
COPY --from=build /src/target/*.jar /opt/suite/
COPY --from=build /src/SUITE_COMMIT.txt /opt/suite/SUITE_COMMIT.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SUITE_PORT=8080
ENV SUITE_BASE_URL=https://suite.example.invalid
ENV MONGODB_URI=mongodb://mongo:27017/conformance

ENTRYPOINT ["/entrypoint.sh"]
