ARG PROVIDER_PATH=/usr/src/providers

# Build custom identity providers
FROM gradle:7-jdk11-alpine AS providers
ARG PROVIDER_PATH

WORKDIR ${PROVIDER_PATH}
COPY providers/IdentityProvider ./
RUN gradle clean build

# Build Keycloak with IDPs
FROM quay.io/keycloak/keycloak:19.0.3 AS builder
ARG PROVIDER_PATH

ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

COPY --from=providers ${PROVIDER_PATH}/build/libs /opt/keycloak/providers
RUN /opt/keycloak/bin/kc.sh build

# Compose Keycloak Docker image
FROM quay.io/keycloak/keycloak:19.0.3 AS production
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT [ "/opt/keycloak/bin/kc.sh" , "start", "--optimized"]
