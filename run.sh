#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly REQUIREMENTS_FILE="${SCRIPT_DIR}/requirements.txt"
readonly APPLICATION_FILE="${SCRIPT_DIR}/AtilKurt.py"
readonly ENV_FILE="${ATILKURT_ENV_FILE:-${SCRIPT_DIR}/.env}"

if [[ -n "${ATILKURT_VENV_DIR:-}" ]]; then
    if [[ "${ATILKURT_VENV_DIR}" = /* ]]; then
        VENV_DIR="${ATILKURT_VENV_DIR}"
    else
        VENV_DIR="${SCRIPT_DIR}/${ATILKURT_VENV_DIR}"
    fi
else
    VENV_DIR="${SCRIPT_DIR}/.venv"
fi

DISTRO_ID="unknown"
PACKAGE_MANAGER=""
APT_UPDATED=0

log() {
    printf '[AtilKurt] %s\n' "$*"
}

fail() {
    printf '[AtilKurt] Error: %s\n' "$*" >&2
    exit 1
}

detect_linux_distribution() {
    [[ "$(uname -s)" == "Linux" ]] || fail "run.sh supports Linux only."

    local distro_like=""
    if [[ -r /etc/os-release ]]; then
        while IFS='=' read -r key value; do
            value="${value%\"}"
            value="${value#\"}"
            case "${key}" in
                ID) DISTRO_ID="${value}" ;;
                ID_LIKE) distro_like="${value}" ;;
            esac
        done < /etc/os-release
    fi

    case "${DISTRO_ID} ${distro_like}" in
        *debian*|*ubuntu*) PACKAGE_MANAGER="apt-get" ;;
        *fedora*|*rhel*|*centos*|*rocky*|*almalinux*)
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            else
                PACKAGE_MANAGER="yum"
            fi
            ;;
        *arch*|*manjaro*) PACKAGE_MANAGER="pacman" ;;
        *opensuse*|*sles*) PACKAGE_MANAGER="zypper" ;;
        *alpine*) PACKAGE_MANAGER="apk" ;;
    esac

    if [[ -z "${PACKAGE_MANAGER}" ]]; then
        local candidate
        for candidate in apt-get dnf yum pacman zypper apk; do
            if command -v "${candidate}" >/dev/null 2>&1; then
                PACKAGE_MANAGER="${candidate}"
                break
            fi
        done
    fi

    log "Detected Linux distribution: ${DISTRO_ID} (${PACKAGE_MANAGER:-no supported package manager})."
}

run_privileged() {
    if (( EUID == 0 )); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -- "$@"
    else
        fail "System packages are missing and sudo is not available. Run this script as root once."
    fi
}

install_system_packages() {
    (( $# > 0 )) || return 0
    [[ -n "${PACKAGE_MANAGER}" ]] || fail "No supported package manager was detected. Install Python 3.9+ and venv support manually."

    log "Installing missing system support with ${PACKAGE_MANAGER}: $*."
    case "${PACKAGE_MANAGER}" in
        apt-get)
            if (( APT_UPDATED == 0 )); then
                run_privileged apt-get update
                APT_UPDATED=1
            fi
            run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
            ;;
        dnf) run_privileged dnf install -y "$@" ;;
        yum) run_privileged yum install -y "$@" ;;
        pacman) run_privileged pacman -Sy --needed --noconfirm "$@" ;;
        zypper) run_privileged zypper --non-interactive install --no-recommends "$@" ;;
        apk) run_privileged apk add --no-cache "$@" ;;
        *) fail "Unsupported package manager: ${PACKAGE_MANAGER}." ;;
    esac
}

python_meets_minimum_version() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1
}

install_python_runtime() {
    case "${PACKAGE_MANAGER}" in
        apt-get) install_system_packages python3 python3-venv python3-pip ca-certificates ;;
        dnf|yum) install_system_packages python3 python3-pip ca-certificates ;;
        pacman) install_system_packages python python-pip ca-certificates ;;
        zypper) install_system_packages python3 python3-pip ca-certificates ;;
        apk) install_system_packages python3 py3-pip py3-virtualenv ca-certificates ;;
        *) fail "Install Python 3.9+, pip, and venv support, then run this script again." ;;
    esac
}

install_venv_support() {
    case "${PACKAGE_MANAGER}" in
        apt-get) install_system_packages python3-venv ;;
        dnf|yum) install_system_packages python3 python3-pip ;;
        pacman) install_system_packages python python-pip ;;
        zypper) install_system_packages python3 python3-pip ;;
        apk) install_system_packages py3-virtualenv py3-pip ;;
        *) fail "Python venv support is unavailable. Install it and run this script again." ;;
    esac
}

ensure_python_runtime() {
    if python_meets_minimum_version; then
        log "Python runtime is already available: $(python3 --version 2>&1)."
        return
    fi

    install_python_runtime
    python_meets_minimum_version || fail "The installed python3 is older than Python 3.9. Install a supported Python release."
}

ensure_ca_certificates() {
    if python3 - <<'PY' >/dev/null 2>&1
import os
import ssl

paths = ssl.get_default_verify_paths()
raise SystemExit(0 if (paths.cafile and os.path.isfile(paths.cafile)) or (paths.capath and os.path.isdir(paths.capath)) else 1)
PY
    then
        log "A system CA certificate store is already available."
        return
    fi

    install_system_packages ca-certificates
}

ensure_virtual_environment() {
    if [[ -x "${VENV_DIR}/bin/python" ]]; then
        if "${VENV_DIR}/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
            log "Virtual environment is already available: ${VENV_DIR}."
        else
            fail "The existing virtual environment uses Python older than 3.9: ${VENV_DIR}. Remove or replace it manually."
        fi
    else
        log "Creating virtual environment: ${VENV_DIR}."
        if ! python3 -m venv "${VENV_DIR}"; then
            log "Python venv support is missing; installing it before retrying."
            install_venv_support
            python3 -m venv "${VENV_DIR}" || fail "Could not create the virtual environment at ${VENV_DIR}."
        fi
    fi

    if ! "${VENV_DIR}/bin/python" -m pip --version >/dev/null 2>&1; then
        "${VENV_DIR}/bin/python" -m ensurepip --upgrade || fail "pip is unavailable in ${VENV_DIR}."
    fi
}

requirements_are_satisfied() {
    "${VENV_DIR}/bin/python" - "${REQUIREMENTS_FILE}" <<'PY'
import sys
from importlib import metadata
from pathlib import Path

from pip._vendor.packaging.requirements import Requirement

requirements_path = Path(sys.argv[1])
for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    requirement = Requirement(line)
    if requirement.marker and not requirement.marker.evaluate():
        continue
    try:
        installed_version = metadata.version(requirement.name)
    except metadata.PackageNotFoundError:
        raise SystemExit(1)
    if requirement.specifier and not requirement.specifier.contains(installed_version, prereleases=True):
        raise SystemExit(1)
PY
}

ensure_python_dependencies() {
    if requirements_are_satisfied && "${VENV_DIR}/bin/python" -m pip check >/dev/null 2>&1; then
        log "Python dependencies already satisfy requirements; installation skipped."
        return
    fi

    log "Installing missing or incompatible Python dependencies."
    "${VENV_DIR}/bin/python" -m pip install --disable-pip-version-check -r "${REQUIREMENTS_FILE}"
    "${VENV_DIR}/bin/python" -m pip check
}

trim_whitespace() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "${value}"
}

load_environment_file() {
    [[ -f "${ENV_FILE}" ]] || return 0

    local permissions
    permissions="$(stat -c '%a' "${ENV_FILE}" 2>/dev/null || true)"
    if [[ -n "${permissions}" ]] && (( (8#${permissions} & 077) != 0 )); then
        printf '[AtilKurt] Warning: %s is readable by other users; use chmod 600.\n' "${ENV_FILE}" >&2
    fi

    local line key value
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        line="$(trim_whitespace "${line}")"
        [[ -z "${line}" || "${line}" == \#* ]] && continue
        [[ "${line}" == export\ * ]] && line="${line#export }"
        [[ "${line}" == *=* ]] || fail "Malformed line in ${ENV_FILE}. Expected KEY=VALUE."

        key="$(trim_whitespace "${line%%=*}")"
        value="$(trim_whitespace "${line#*=}")"
        case "${key}" in
            ATILKURT_DOMAIN|ATILKURT_USER|ATILKURT_PASS|ATILKURT_DC_IP|ATILKURT_OUTPUT) ;;
            *) continue ;;
        esac

        if [[ ${#value} -ge 2 ]]; then
            if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] ||
               [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
                value="${value:1:${#value}-2}"
            fi
        fi

        if [[ -z "${!key+x}" ]]; then
            printf -v "${key}" '%s' "${value}"
            export "${key?}"
        fi
    done < "${ENV_FILE}"
    log "Loaded supported settings from ${ENV_FILE}."
}

has_option() {
    local short_option="$1"
    local long_option="$2"
    shift 2
    local argument
    for argument in "$@"; do
        if [[ "${argument}" == "${short_option}" || "${argument}" == "${long_option}" ||
              "${argument}" == "${long_option}="* ]]; then
            return 0
        fi
    done
    return 1
}

build_application_arguments() {
    APPLICATION_ARGUMENTS=("$@")

    if ! has_option "-d" "--domain" "$@" && [[ -n "${ATILKURT_DOMAIN:-}" ]]; then
        APPLICATION_ARGUMENTS=("--domain" "${ATILKURT_DOMAIN}" "${APPLICATION_ARGUMENTS[@]}")
    fi
    if ! has_option "-u" "--username" "$@" && [[ -n "${ATILKURT_USER:-}" ]]; then
        APPLICATION_ARGUMENTS=("--username" "${ATILKURT_USER}" "${APPLICATION_ARGUMENTS[@]}")
    fi
    if ! has_option "" "--dc-ip" "$@" && [[ -n "${ATILKURT_DC_IP:-}" ]]; then
        APPLICATION_ARGUMENTS=("--dc-ip" "${ATILKURT_DC_IP}" "${APPLICATION_ARGUMENTS[@]}")
    fi
    if ! has_option "" "--output" "$@" && [[ -n "${ATILKURT_OUTPUT:-}" ]]; then
        APPLICATION_ARGUMENTS=("--output" "${ATILKURT_OUTPUT}" "${APPLICATION_ARGUMENTS[@]}")
    fi
}

is_help_request() {
    local argument
    for argument in "$@"; do
        [[ "${argument}" == "-h" || "${argument}" == "--help" ]] && return 0
    done
    return 1
}

validate_required_application_settings() {
    is_help_request "${APPLICATION_ARGUMENTS[@]}" && return 0
    has_option "-d" "--domain" "${APPLICATION_ARGUMENTS[@]}" || fail "Set ATILKURT_DOMAIN or pass --domain."
    has_option "-u" "--username" "${APPLICATION_ARGUMENTS[@]}" || fail "Set ATILKURT_USER or pass --username."

    if [[ ! -t 0 && -z "${ATILKURT_PASS:-}" ]] && ! has_option "-p" "--password" "${APPLICATION_ARGUMENTS[@]}"; then
        fail "Non-interactive execution requires ATILKURT_PASS."
    fi
}

main() {
    [[ -f "${APPLICATION_FILE}" ]] || fail "Application entry point not found: ${APPLICATION_FILE}."
    [[ -f "${REQUIREMENTS_FILE}" ]] || fail "Requirements file not found: ${REQUIREMENTS_FILE}."

    detect_linux_distribution
    ensure_python_runtime
    ensure_ca_certificates
    ensure_virtual_environment
    ensure_python_dependencies
    load_environment_file
    build_application_arguments "$@"
    validate_required_application_settings

    log "Starting AtilKurt."
    cd -- "${SCRIPT_DIR}"
    exec "${VENV_DIR}/bin/python" "${APPLICATION_FILE}" "${APPLICATION_ARGUMENTS[@]}"
}

main "$@"
