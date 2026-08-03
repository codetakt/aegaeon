#!/usr/bin/env bash

set -euo pipefail

oidf_resolve_ca_cert() {
	local repo_root="$1"
	local explicit="${OIDF_CA_CERT:-}"
	if [ -n "${explicit}" ]; then
		[ -f "${explicit}" ] || {
			echo "error: OIDF_CA_CERT not found: ${explicit}" >&2
			return 1
		}
		printf '%s\n' "${explicit}"
		return 0
	fi

	if [ "${OIDF_LOCAL_CERTS:-0}" = "1" ] && [ -n "${OIDF_LOCAL_CA_CERT_FILENAME:-}" ]; then
		local ca_path="${repo_root}/scripts/oidf_conformance/certificates/${OIDF_LOCAL_CA_CERT_FILENAME}"
		[ -f "${ca_path}" ] || {
			echo "error: local CA cert not found: ${ca_path}" >&2
			return 1
		}
		printf '%s\n' "${ca_path}"
		return 0
	fi

	return 1
}

oidf_init_curl() {
	local repo_root="$1"
	OIDF_CA_CERT_RESOLVED=""
	if oidf_resolved="$(oidf_resolve_ca_cert "${repo_root}")"; then
		OIDF_CA_CERT_RESOLVED="${oidf_resolved}"
		export OIDF_CA_CERT_RESOLVED
	fi
}

oidf_curl() {
	if [ -n "${OIDF_CA_CERT_RESOLVED:-}" ]; then
		curl --cacert "${OIDF_CA_CERT_RESOLVED}" "$@"
	else
		curl "$@"
	fi
}
