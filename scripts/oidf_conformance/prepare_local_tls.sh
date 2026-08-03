#!/usr/bin/env bash

set -euo pipefail

die() {
	echo "error: $*" >&2
	exit 1
}

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		die "missing required command: $1"
	fi
}

need_cmd openssl

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${OIDF_ENV_FILE:-scripts/oidf_conformance/.env.local}"
ENV_PATH="${REPO_ROOT}/${ENV_FILE}"

[ -f "${ENV_PATH}" ] || die "env file not found: ${ENV_PATH}"

# shellcheck disable=SC1090
set -a
source "${ENV_PATH}"
set +a

: "${AEGAEON_DOMAIN:?missing AEGAEON_DOMAIN in ${ENV_PATH}}"
: "${SUITE_DOMAIN:?missing SUITE_DOMAIN in ${ENV_PATH}}"
: "${CERT_PRIMARY_DOMAIN:?missing CERT_PRIMARY_DOMAIN in ${ENV_PATH}}"
: "${OIDF_LOCAL_CA_CERT_FILENAME:?missing OIDF_LOCAL_CA_CERT_FILENAME in ${ENV_PATH}}"
: "${OIDF_LOCAL_CA_KEY_FILENAME:?missing OIDF_LOCAL_CA_KEY_FILENAME in ${ENV_PATH}}"

CERT_DIR="${REPO_ROOT}/scripts/oidf_conformance/certificates"
CA_CERT="${CERT_DIR}/${OIDF_LOCAL_CA_CERT_FILENAME}"
CA_KEY="${CERT_DIR}/${OIDF_LOCAL_CA_KEY_FILENAME}"
LEAF_CERT="${CERT_DIR}/${CERT_PRIMARY_DOMAIN}.crt"
LEAF_KEY="${CERT_DIR}/${CERT_PRIMARY_DOMAIN}.key"

mkdir -p "${CERT_DIR}"

if [ "${OIDF_FORCE_REGENERATE:-0}" = "1" ]; then
	rm -f "${CA_CERT}" "${CA_KEY}" "${LEAF_CERT}" "${LEAF_KEY}" \
		"${CERT_DIR}/${CERT_PRIMARY_DOMAIN}.csr" "${CERT_DIR}/${CERT_PRIMARY_DOMAIN}.ext" "${CERT_DIR}/oidf-local-ca.srl"
fi

if [ ! -f "${CA_KEY}" ] || [ ! -f "${CA_CERT}" ]; then
	umask 077
	openssl genrsa -out "${CA_KEY}" 4096 >/dev/null 2>&1
	openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
		-subj "/CN=Aegaeon OIDF Local CA" \
		-out "${CA_CERT}" >/dev/null 2>&1
	chmod 644 "${CA_CERT}"
fi

if [ ! -f "${LEAF_KEY}" ] || [ ! -f "${LEAF_CERT}" ]; then
	csr_path="${CERT_DIR}/${CERT_PRIMARY_DOMAIN}.csr"
	ext_path="${CERT_DIR}/${CERT_PRIMARY_DOMAIN}.ext"
	umask 077
	openssl genrsa -out "${LEAF_KEY}" 2048 >/dev/null 2>&1
	openssl req -new -key "${LEAF_KEY}" \
		-subj "/CN=${CERT_PRIMARY_DOMAIN}" \
		-out "${csr_path}" >/dev/null 2>&1
	cat >"${ext_path}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=${AEGAEON_DOMAIN}
DNS.2=${SUITE_DOMAIN}
DNS.3=localhost
IP.1=127.0.0.1
IP.2=::1
EOF
	openssl x509 -req -in "${csr_path}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
		-CAcreateserial -out "${LEAF_CERT}" -days 825 -sha256 -extfile "${ext_path}" >/dev/null 2>&1
	chmod 644 "${LEAF_CERT}"
	rm -f "${csr_path}" "${ext_path}"
fi

echo "local CA cert: ${CA_CERT}"
echo "local CA key: ${CA_KEY}"
echo "leaf cert: ${LEAF_CERT}"
echo "leaf key: ${LEAF_KEY}"
