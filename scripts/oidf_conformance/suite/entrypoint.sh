#!/usr/bin/env sh

set -eu

SUITE_PORT="${SUITE_PORT:-8080}"
SUITE_BASE_URL="${SUITE_BASE_URL:-https://suite.example.invalid}"
MONGODB_URI="${MONGODB_URI:-mongodb://mongo:27017/conformance}"
SUITE_EXTRA_CA_CERT="${SUITE_EXTRA_CA_CERT:-}"
OIDF_LOCAL_CA_CERT_FILENAME="${OIDF_LOCAL_CA_CERT_FILENAME:-}"

if [ -z "${SUITE_EXTRA_CA_CERT}" ] && [ -n "${OIDF_LOCAL_CA_CERT_FILENAME}" ]; then
	SUITE_EXTRA_CA_CERT="/etc/ssl/localcerts/${OIDF_LOCAL_CA_CERT_FILENAME}"
fi

if [ -n "${SUITE_EXTRA_CA_CERT}" ]; then
	if [ ! -f "${SUITE_EXTRA_CA_CERT}" ]; then
		echo "error: SUITE_EXTRA_CA_CERT not found: ${SUITE_EXTRA_CA_CERT}" >&2
		exit 1
	fi
	keytool -delete -alias oidf-local-ca -cacerts -storepass changeit >/dev/null 2>&1 || true
	keytool -importcert -noprompt -trustcacerts \
		-alias oidf-local-ca \
		-file "${SUITE_EXTRA_CA_CERT}" \
		-cacerts \
		-storepass changeit >/dev/null
fi

JAR=""
if [ -f "/opt/suite/conformance-suite.jar" ]; then
	JAR="/opt/suite/conformance-suite.jar"
elif [ -f "/opt/suite/fapi-test-suite.jar" ]; then
	JAR="/opt/suite/fapi-test-suite.jar"
else
	JAR="$(ls -1 /opt/suite/*.jar 2>/dev/null | head -n 1 || true)"
fi

if [ -z "${JAR}" ]; then
	echo "error: could not locate conformance suite jar under /opt/suite" >&2
	ls -la /opt/suite >&2 || true
	exit 1
fi

exec java \
	-Djdk.tls.maxHandshakeMessageSize=65536 \
	-jar "${JAR}" \
	--server.port="${SUITE_PORT}" \
	--server.forward-headers-strategy=native \
	--spring.profiles.active=dev \
	--spring.data.mongodb.uri="${MONGODB_URI}" \
	--fintechlabs.base_url="${SUITE_BASE_URL}" \
	--fintechlabs.devmode=true \
	--fintechlabs.startredir=true
