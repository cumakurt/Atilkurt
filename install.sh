#!/usr/bin/env bash
# Prepare a reusable environment and install command wrappers without touching AD.
set -Eeuo pipefail
umask 077

INSTALL_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_VENV="${ATILKURT_VENV_DIR:-${INSTALL_ROOT}/.venv}"
[[ "${INSTALL_VENV}" == /* ]] || INSTALL_VENV="${INSTALL_ROOT}/${INSTALL_VENV}"
INSTALL_BIN="${ATILKURT_BIN_DIR:-}"
INSTALL_PLATFORM="$(uname -s)"
INSTALL_MANAGER=""
INSTALL_PYTHON=""
INSTALL_LOG="$(mktemp "${TMPDIR:-/tmp}/atilkurt-install.XXXXXX")"
trap 'rm -f -- "${INSTALL_LOG}" "${INSTALL_LOG}.brew"' EXIT

log() { printf '[AtilKurt] %s\n' "$*"; }
fail() { printf '[AtilKurt] Error: %s\n' "$*" >&2; exit 1; }
quiet() {
    if ! "$@" >"${INSTALL_LOG}" 2>&1; then
        tail -n 12 "${INSTALL_LOG}" >&2
        fail "The installation step failed. Resolve the error above and run install.sh again."
    fi
}
privileged() {
    if (( EUID == 0 )); then "$@";
    elif command -v sudo >/dev/null 2>&1; then sudo -- "$@";
    else fail "Missing system packages require root or sudo."; fi
}

detect_platform() {
    case "${INSTALL_PLATFORM}" in
        Linux)
            local candidate
            for candidate in apt-get dnf yum pacman zypper apk; do
                if command -v "${candidate}" >/dev/null 2>&1; then INSTALL_MANAGER="${candidate}"; break; fi
            done
            ;;
        Darwin)
            if command -v brew >/dev/null 2>&1; then INSTALL_MANAGER="brew"; fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            if command -v winget >/dev/null 2>&1; then INSTALL_MANAGER="winget"; fi
            ;;
        *) fail "Unsupported operating system: ${INSTALL_PLATFORM}. Use Linux, macOS, WSL, or Git Bash on Windows." ;;
    esac
    log "Platform: ${INSTALL_PLATFORM}."
}

find_python() {
    local candidate windows_root launcher_python
    local candidates=("${INSTALL_VENV}/bin/python" "${INSTALL_VENV}/Scripts/python.exe" "${ATILKURT_PYTHON:-}" python3 python)
    case "${INSTALL_PLATFORM}" in
        MINGW*|MSYS*|CYGWIN*)
            # A new winget installation is usable before its PATH update reaches
            # this shell. Convert Windows paths for Git Bash/Cygwin when needed.
            if command -v py >/dev/null 2>&1; then
                launcher_python="$(py -3 -c 'import sys; print(sys.executable)' 2>/dev/null | tr -d '\r' || true)"
                if [[ -n "${launcher_python}" ]]; then
                    if command -v cygpath >/dev/null 2>&1; then launcher_python="$(cygpath -u "${launcher_python}")"; fi
                    candidates+=("${launcher_python}")
                fi
            fi
            for windows_root in "${LOCALAPPDATA:-}" "${ProgramFiles:-${PROGRAMFILES:-}}"; do
                [[ -n "${windows_root}" ]] || continue
                if command -v cygpath >/dev/null 2>&1; then windows_root="$(cygpath -u "${windows_root}")"; fi
                for candidate in "${windows_root}"/Programs/Python/Python3*/python.exe "${windows_root}"/Python3*/python.exe; do
                    [[ -x "${candidate}" ]] && candidates+=("${candidate}")
                done
            done
            ;;
    esac
    for candidate in "${candidates[@]}"; do
        [[ -n "${candidate}" ]] || continue
        if command -v "${candidate}" >/dev/null 2>&1 &&
           "${candidate}" -c 'import sys, ssl; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
            INSTALL_PYTHON="$(command -v "${candidate}")"
            return 0
        fi
    done
    return 1
}

install_python_support() {
    if (( EUID != 0 )) && [[ "${INSTALL_MANAGER}" != 'brew' && "${INSTALL_MANAGER}" != 'winget' ]]; then
        command -v sudo >/dev/null 2>&1 || fail "Missing system packages require sudo."
        sudo -v || fail "Could not obtain permission to install missing system packages."
    fi
    if [[ "${INSTALL_PLATFORM}" == 'Darwin' && -z "${INSTALL_MANAGER}" ]]; then
        (( EUID != 0 )) || fail "Homebrew cannot be installed as root; run install.sh as your normal macOS user."
        log "Installing Homebrew for missing Python support."
        command -v curl >/dev/null 2>&1 || fail "curl is required to install Homebrew."
        quiet curl --fail --location --connect-timeout 15 --max-time 120 --output "${INSTALL_LOG}.brew" https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh
        quiet env NONINTERACTIVE=1 /bin/bash "${INSTALL_LOG}.brew"
        rm -f -- "${INSTALL_LOG}.brew"
        if [[ -x /opt/homebrew/bin/brew ]]; then INSTALL_MANAGER='/opt/homebrew/bin/brew';
        elif [[ -x /usr/local/bin/brew ]]; then INSTALL_MANAGER='/usr/local/bin/brew';
        else fail "Homebrew installation did not produce a usable brew command."; fi
    fi
    log "Installing missing Python support (${INSTALL_MANAGER:-system package manager})."
    case "${INSTALL_MANAGER}" in
        apt-get)
            quiet privileged apt-get update
            quiet privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates
            ;;
        dnf|yum) quiet privileged "${INSTALL_MANAGER}" install -y python3 python3-pip ca-certificates ;;
        pacman) quiet privileged pacman -S --needed --noconfirm python python-pip ca-certificates ;;
        zypper) quiet privileged zypper --non-interactive install --no-recommends python3 python3-pip ca-certificates ;;
        apk) quiet privileged apk add --no-cache python3 py3-pip py3-virtualenv ca-certificates ;;
        brew|*/brew) quiet "${INSTALL_MANAGER}" install python
            local brew_prefix
            brew_prefix="$("${INSTALL_MANAGER}" --prefix)"
            export PATH="${brew_prefix}/bin:${PATH}" ;;
        winget) quiet winget install --id Python.Python.3.12 --exact --silent --accept-package-agreements --accept-source-agreements ;;
        *) fail "Python 3.9+ is missing. Install it with your OS package manager (Homebrew on macOS), then rerun this script." ;;
    esac
}

ensure_environment() {
    if ! find_python; then
        install_python_support
        find_python || fail "Python is still unavailable in PATH. Open a new terminal and rerun install.sh."
    fi
    if [[ -x "${INSTALL_VENV}/bin/python" ]]; then
        INSTALL_PYTHON="${INSTALL_VENV}/bin/python"
    elif [[ -x "${INSTALL_VENV}/Scripts/python.exe" ]]; then
        INSTALL_PYTHON="${INSTALL_VENV}/Scripts/python.exe"
    else
        [[ ! -e "${INSTALL_VENV}" ]] || fail "An incomplete environment exists at ${INSTALL_VENV}; preserve or repair it before continuing."
        log "Creating Python environment."
        if ! "${INSTALL_PYTHON}" -m venv "${INSTALL_VENV}" >"${INSTALL_LOG}" 2>&1; then
            install_python_support
            quiet "${INSTALL_PYTHON}" -m venv "${INSTALL_VENV}"
        fi
        if [[ -x "${INSTALL_VENV}/bin/python" ]]; then INSTALL_PYTHON="${INSTALL_VENV}/bin/python";
        else INSTALL_PYTHON="${INSTALL_VENV}/Scripts/python.exe"; fi
    fi
    "${INSTALL_PYTHON}" -c 'import sys, ssl; raise SystemExit(sys.version_info < (3, 9))' >/dev/null 2>&1 ||
        fail "The existing environment must use Python 3.9+ with SSL support."
    if ! "${INSTALL_PYTHON}" -m pip --version >/dev/null 2>&1; then
        log "Preparing pip in the existing environment."
        quiet "${INSTALL_PYTHON}" -m ensurepip --upgrade
    fi
}

requirements_satisfied() {
    "${INSTALL_PYTHON}" - "${INSTALL_ROOT}/requirements.txt" <<'PY' >/dev/null 2>&1
import sys
from importlib import metadata
from pathlib import Path
from pip._vendor.packaging.requirements import Requirement
for line in Path(sys.argv[1]).read_text().splitlines():
    if not line.strip() or line.lstrip().startswith('#'):
        continue
    req = Requirement(line)
    if req.marker and not req.marker.evaluate():
        continue
    try:
        version = metadata.version(req.name)
    except metadata.PackageNotFoundError:
        raise SystemExit(1)
    if not req.specifier.contains(version, prereleases=True):
        raise SystemExit(1)
PY
}

ensure_dependencies() {
    if requirements_satisfied && "${INSTALL_PYTHON}" -m pip check >/dev/null 2>&1; then
        log "Existing environment and dependencies are ready."
    else
        log "Installing missing or incompatible application dependencies."
        quiet "${INSTALL_PYTHON}" -m pip install --disable-pip-version-check -r "${INSTALL_ROOT}/requirements.txt"
        quiet "${INSTALL_PYTHON}" -m pip check
    fi
}

ensure_certificate_store() {
    if "${INSTALL_PYTHON}" - <<'PY' >/dev/null 2>&1
import ssl
from pathlib import Path
paths = ssl.get_default_verify_paths()
raise SystemExit(0 if (paths.cafile and Path(paths.cafile).is_file()) or (paths.capath and Path(paths.capath).is_dir()) or ssl.create_default_context().get_ca_certs() else 1)
PY
    then return; fi
    log "Preparing missing CA certificates."
    case "${INSTALL_MANAGER}" in
        apt-get) quiet privileged apt-get install -y --no-install-recommends ca-certificates ;;
        dnf|yum) quiet privileged "${INSTALL_MANAGER}" install -y ca-certificates ;;
        pacman) quiet privileged pacman -S --needed --noconfirm ca-certificates ;;
        zypper) quiet privileged zypper --non-interactive install ca-certificates ;;
        apk) quiet privileged apk add --no-cache ca-certificates ;;
        brew|*/brew) quiet "${INSTALL_MANAGER}" install ca-certificates ;;
        *) fail "The Python certificate store is unavailable. Repair the OS/Python CA store and rerun install.sh." ;;
    esac
}

configure_commands() {
    if [[ -z "${INSTALL_BIN}" ]]; then
        if (( EUID == 0 )); then INSTALL_BIN='/usr/local/bin';
        else INSTALL_BIN="${HOME}/.local/bin"; fi
    fi
    [[ "${INSTALL_BIN}" == /* ]] || fail "ATILKURT_BIN_DIR must be an absolute path."
    mkdir -p -- "${INSTALL_BIN}"
    local wrapper command_name temporary
    wrapper="$("${INSTALL_PYTHON}" - "${INSTALL_PYTHON}" "${INSTALL_ROOT}" <<'PY'
import shlex
import sys
print('#!/usr/bin/env bash')
print('# Managed by AtilKurt install.sh')
print('source ' + shlex.quote(sys.argv[2] + '/run.sh'))
print('load_environment_file')
print('build_application_arguments "$@"')
print('exec ' + shlex.quote(sys.argv[1]) + ' ' + shlex.quote(sys.argv[2] + '/AtilKurt.py') + ' "${APPLICATION_ARGUMENTS[@]}"')
PY
)"
    for command_name in Atilkurt atilkurt AtilKurt; do
        if [[ -e "${INSTALL_BIN}/${command_name}" || -L "${INSTALL_BIN}/${command_name}" ]]; then
            if [[ "$(cat -- "${INSTALL_BIN}/${command_name}" 2>/dev/null || true)" == "${wrapper}" ]]; then continue; fi
            fail "Existing command ${INSTALL_BIN}/${command_name} differs; choose ATILKURT_BIN_DIR instead of overwriting it."
        fi
        temporary="$(mktemp "${INSTALL_BIN}/.atilkurt-command.XXXXXX")"
        printf '%s\n' "${wrapper}" >"${temporary}"
        chmod 755 "${temporary}"
        mv -- "${temporary}" "${INSTALL_BIN}/${command_name}"
    done
}

configure_path() {
    case ":${PATH}:" in *":${INSTALL_BIN}:"*) return ;; esac
    local path_line profile
    local profiles=()
    path_line="$("${INSTALL_PYTHON}" - "${INSTALL_BIN}" <<'PY'
import shlex
import sys
print('export PATH=' + shlex.quote(sys.argv[1]) + ':"$PATH" # AtilKurt command path')
PY
)"
    case "${SHELL:-/bin/bash}" in
        */zsh) profile="${ZDOTDIR:-${HOME}}/.zshrc" ;;
        */bash)
            # Interactive terminals and login shells read different files.
            profiles+=("${HOME}/.bashrc")
            if [[ -f "${HOME}/.bash_profile" ]]; then profile="${HOME}/.bash_profile";
            elif [[ -f "${HOME}/.bash_login" ]]; then profile="${HOME}/.bash_login";
            else profile="${HOME}/.profile"; fi
            ;;
        */fish)
            mkdir -p "${HOME}/.config/fish/conf.d"
            profile="${HOME}/.config/fish/conf.d/atilkurt.fish"
            local fish_line
            fish_line="$("${INSTALL_PYTHON}" - "${INSTALL_BIN}" <<'PY'
import sys
print('fish_add_path ' + "'" + sys.argv[1].replace('\\', '\\\\').replace("'", "\\'") + "'")
PY
            )"
            if [[ -e "${profile}" ]]; then
                [[ "$(cat -- "${profile}")" == "${fish_line}" ]] || fail "Existing fish configuration must be preserved: ${profile}."
            else printf '%s\n' "${fish_line}" >"${profile}"; fi
            log "Command path configured for the next terminal: ${INSTALL_BIN}."
            return ;;
        *) profile="${HOME}/.profile" ;;
    esac
    profiles+=("${profile}")
    for profile in "${profiles[@]}"; do
        if ! [[ -f "${profile}" ]] || ! "${INSTALL_PYTHON}" - "${profile}" "${path_line}" <<'PY' >/dev/null 2>&1
import sys
from pathlib import Path
raise SystemExit(0 if sys.argv[2] in Path(sys.argv[1]).read_text().splitlines() else 1)
PY
        then
            printf '\n%s\n' "${path_line}" >>"${profile}"
        fi
    done
    log "Command path configured for the next terminal: ${INSTALL_BIN}."
}

main() {
    [[ -f "${INSTALL_ROOT}/AtilKurt.py" && -f "${INSTALL_ROOT}/requirements.txt" && -f "${INSTALL_ROOT}/run.sh" ]] || fail "Run install.sh from the application checkout."
    detect_platform
    ensure_environment
    ensure_certificate_store
    ensure_dependencies
    configure_commands
    configure_path
    export PATH="${INSTALL_BIN}:${PATH}"
    log "Ready. Run Atilkurt --domain example.com --username auditor."
    "${INSTALL_BIN}/Atilkurt" --help
}
main "$@"
