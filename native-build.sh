#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${NIKA_TOOLS_DIR:-${SCRIPT_DIR}/.native-tools}"
BIN_DIR="${TOOLS_DIR}/bin"
VENV_DIR="${NIKA_VENV_DIR:-${SCRIPT_DIR}/.venv}"
CONFIG_TEMPLATE="${SCRIPT_DIR}/config/crtConfig.yml"
NATIVE_CONFIG_PATH="${NIKA_NATIVE_CONFIG:-${SCRIPT_DIR}/config/native-crtConfig.yml}"

ASTRAIL_URL="${ASTRAIL_URL:-https://github.com/rootaux/astrail/releases/download/v0.0.5/astrail-cli.zip}"
OPENGREP_VERSION="${OPENGREP_VERSION:-v1.19.0}"
ASSUME_YES="${NIKA_ASSUME_YES:-0}"

OS_NAME=""
ARCH_NAME=""
LINUX_FLAVOR=""
PACKAGE_MANAGER=""
PYTHON_BIN=""
JAVA_HOME_VALUE=""
ASTRAIL_BIN=""
JAVASRC2CPG_BIN=""
OPENGREP_BIN="${BIN_DIR}/opengrep"
SYSTEM_INSTALL_APPROVED="0"
PIP_INSTALL_APPROVED="0"

info() {
    echo -e "${BLUE}==>${NC} $*"
}

success() {
    echo -e "${GREEN}✓${NC} $*"
}

warn() {
    echo -e "${YELLOW}!${NC} $*"
}

fail() {
    echo -e "${RED}✗${NC} $*" >&2
    exit 1
}

confirm() {
    local prompt="$1"
    local reply

    if [[ "${ASSUME_YES}" == "1" ]]; then
        return 0
    fi

    if [[ ! -t 0 ]]; then
        fail "Confirmation required but no interactive terminal is available: ${prompt}. Re-run with NIKA_ASSUME_YES=1 if you want non-interactive execution."
    fi

    while true; do
        read -r -p "${prompt} [y/N]: " reply
        case "${reply}" in
            y|Y|yes|YES)
                return 0
                ;;
            n|N|no|NO|"")
                return 1
                ;;
            *)
                warn "Please answer y or n."
                ;;
        esac
    done
}

have_command() {
    command -v "$1" >/dev/null 2>&1
}

is_executable_file() {
    local file_path="$1"
    [[ -f "${file_path}" && -x "${file_path}" ]]
}

run_as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
        return
    fi

    if have_command sudo; then
        sudo "$@"
        return
    fi

    fail "Need root privileges to run: $*"
}

version_gte() {
    local left="$1"
    local right="$2"
    [[ "$(printf '%s\n%s\n' "${right}" "${left}" | sort -V | tail -n 1)" == "${left}" ]]
}

ensure_python_version() {
    local python_version

    python_version="$("${PYTHON_BIN}" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
    if ! version_gte "${python_version}" "3.10"; then
        fail "Python ${python_version} is not supported. native-build.sh requires Python 3.10 or greater."
    fi

    success "Python version supported: ${python_version}"
}

ensure_jdk_version() {
    local jdk_version

    jdk_version="$(java -XshowSettings:properties -version 2>&1 | awk -F'= ' '/java.specification.version/ {print $2; exit}')"
    [[ -n "${jdk_version}" ]] || fail "Unable to determine installed JDK version"

    if ! version_gte "${jdk_version}" "17"; then
        fail "JDK ${jdk_version} is not supported. native-build.sh requires JDK 17 or greater."
    fi

    success "JDK version supported: ${jdk_version}"
}

detect_package_manager() {
    if [[ "${OS_NAME}" == "macos" ]]; then
        if have_command brew; then
            PACKAGE_MANAGER="brew"
            return
        fi
        fail "Homebrew is required on macOS to install missing dependencies. Install Homebrew and rerun this script."
    fi

    for candidate in apt-get dnf yum pacman zypper apk; do
        if have_command "${candidate}"; then
            PACKAGE_MANAGER="${candidate}"
            return
        fi
    done

    fail "Unsupported Linux package manager. Supported: apt-get, dnf, yum, pacman, zypper, apk."
}

detect_os_arch() {
    local uname_s uname_m
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"

    case "${uname_s}" in
        Darwin)
            OS_NAME="macos"
            ;;
        Linux)
            OS_NAME="linux"
            ;;
        *)
            fail "Unsupported operating system: ${uname_s}"
            ;;
    esac

    case "${uname_m}" in
        x86_64|amd64)
            ARCH_NAME="x86_64"
            ;;
        arm64|aarch64)
            ARCH_NAME="arm64"
            ;;
        *)
            fail "Unsupported architecture: ${uname_m}"
            ;;
    esac

    if [[ "${OS_NAME}" == "linux" ]]; then
        if have_command ldd && ldd --version 2>&1 | grep -qi musl; then
            LINUX_FLAVOR="musl"
        else
            LINUX_FLAVOR="manylinux"
        fi
    fi

    detect_package_manager
}

install_packages() {
    if [[ "${SYSTEM_INSTALL_APPROVED}" != "1" ]]; then
        if ! confirm "This will install missing system packages using ${PACKAGE_MANAGER}. Continue?"; then
            fail "Aborted before installing system packages"
        fi
        SYSTEM_INSTALL_APPROVED="1"
    fi

    case "${PACKAGE_MANAGER}" in
        brew)
            brew install "$@"
            ;;
        apt-get)
            run_as_root apt-get update
            run_as_root apt-get install -y "$@"
            ;;
        dnf)
            run_as_root dnf install -y "$@"
            ;;
        yum)
            run_as_root yum install -y "$@"
            ;;
        pacman)
            run_as_root pacman -Sy --noconfirm "$@"
            ;;
        zypper)
            run_as_root zypper --non-interactive install "$@"
            ;;
        apk)
            run_as_root apk add --no-cache "$@"
            ;;
        *)
            fail "Package manager not configured."
            ;;
    esac
}

ensure_base_tools() {
    local missing=()

    if ! have_command curl; then
        missing+=(curl)
    fi
    if ! have_command unzip; then
        missing+=(unzip)
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        success "Base tools already installed"
        return
    fi

    info "Installing missing base tools: ${missing[*]}"
    case "${PACKAGE_MANAGER}" in
        brew)
            install_packages "${missing[@]}"
            ;;
        apt-get|dnf|yum|pacman|zypper|apk)
            install_packages "${missing[@]}"
            ;;
    esac
}

ensure_python() {
    if have_command python3; then
        PYTHON_BIN="$(command -v python3)"
    else
        info "Installing Python 3"
        case "${PACKAGE_MANAGER}" in
            brew)
                install_packages python
                ;;
            apt-get)
                install_packages python3 python3-venv python3-pip
                ;;
            dnf|yum)
                install_packages python3 python3-pip
                ;;
            pacman)
                install_packages python
                ;;
            zypper)
                install_packages python311 python311-pip
                ;;
            apk)
                install_packages python3 py3-pip
                ;;
        esac
        PYTHON_BIN="$(command -v python3 || true)"
    fi

    [[ -n "${PYTHON_BIN}" ]] || fail "python3 is required but could not be installed."

    if ! "${PYTHON_BIN}" -m venv --help >/dev/null 2>&1; then
        if [[ "${PACKAGE_MANAGER}" == "apt-get" ]]; then
            info "Installing python3-venv"
            install_packages python3-venv
        else
            fail "python3 is installed, but the venv module is unavailable. Install the Python venv package for this system and rerun."
        fi
    fi

    success "Python ready: ${PYTHON_BIN}"
    ensure_python_version
}

install_jdk_macos() {
    local brew_prefix openjdk_bundle

    install_packages openjdk@21
    brew_prefix="$(brew --prefix)"
    openjdk_bundle="${brew_prefix}/opt/openjdk@21/libexec/openjdk.jdk"

    if [[ -d "${openjdk_bundle}" ]]; then
        run_as_root mkdir -p /Library/Java/JavaVirtualMachines
        run_as_root ln -sfn "${openjdk_bundle}" /Library/Java/JavaVirtualMachines/openjdk-21.jdk
    fi
}

install_jdk_linux() {
    case "${PACKAGE_MANAGER}" in
        apt-get)
            install_packages openjdk-21-jdk
            ;;
        dnf|yum)
            install_packages java-21-openjdk-devel
            ;;
        pacman)
            install_packages jdk21-openjdk
            ;;
        zypper)
            install_packages java-21-openjdk-devel
            ;;
        apk)
            install_packages openjdk21-jdk
            ;;
        *)
            fail "No JDK install recipe for package manager: ${PACKAGE_MANAGER}"
            ;;
    esac
}

ensure_jdk() {
    if have_command java && have_command javac; then
        success "JDK already installed"
        ensure_jdk_version
        return
    fi

    info "Installing JDK 21"
    if [[ "${OS_NAME}" == "macos" ]]; then
        install_jdk_macos
    else
        install_jdk_linux
    fi

    have_command java || fail "java was not found after JDK installation"
    have_command javac || fail "javac was not found after JDK installation"
    success "JDK installed"
    ensure_jdk_version
}

resolve_java_home() {
    if [[ "${OS_NAME}" == "macos" ]]; then
        if [[ -x /usr/libexec/java_home ]]; then
            JAVA_HOME_VALUE="$(/usr/libexec/java_home -v 21 2>/dev/null || /usr/libexec/java_home 2>/dev/null || true)"
        fi
    else
        JAVA_HOME_VALUE="$(dirname "$(dirname "$(${PYTHON_BIN} -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$(command -v javac)")")")"
    fi

    if [[ -z "${JAVA_HOME_VALUE}" || ! -d "${JAVA_HOME_VALUE}" ]]; then
        fail "Unable to resolve JAVA_HOME"
    fi

    export JAVA_HOME="${JAVA_HOME_VALUE}"
    export PATH="${JAVA_HOME}/bin:${PATH}"
    success "JAVA_HOME set to ${JAVA_HOME}"
}

download_file() {
    local url="$1"
    local destination="$2"

    curl -k -fsSL --retry 3 --retry-delay 2 "${url}" -o "${destination}"
}

install_astrail() {
    local temp_dir archive

    mkdir -p "${TOOLS_DIR}"
    ASTRAIL_BIN="$(find "${TOOLS_DIR}" -type f -name astrail | head -n 1)"
    JAVASRC2CPG_BIN="$(find "${TOOLS_DIR}" -type f -name javasrc2cpg | head -n 1)"

    if is_executable_file "${ASTRAIL_BIN}" && is_executable_file "${JAVASRC2CPG_BIN}"; then
        success "Astrail already installed"
        return
    fi

    info "Downloading Astrail"
    rm -rf "${TOOLS_DIR}/astrail"

    temp_dir="$(mktemp -d)"
    archive="${temp_dir}/astrail-cli.zip"

    download_file "${ASTRAIL_URL}" "${archive}"
    unzip -q "${archive}" -d "${TOOLS_DIR}"

    ASTRAIL_BIN="$(find "${TOOLS_DIR}" -type f -name astrail | head -n 1)"
    JAVASRC2CPG_BIN="$(find "${TOOLS_DIR}" -type f -name javasrc2cpg | head -n 1)"

    [[ -n "${ASTRAIL_BIN}" ]] || fail "Could not locate astrail executable after extraction"
    [[ -n "${JAVASRC2CPG_BIN}" ]] || fail "Could not locate javasrc2cpg executable after extraction"

    chmod +x "${ASTRAIL_BIN}" "${JAVASRC2CPG_BIN}"
    rm -rf "${temp_dir}"
    success "Astrail installed"
}

opengrep_asset_url() {
    case "${OS_NAME}:${ARCH_NAME}" in
        macos:x86_64)
            echo "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_osx_x86"
            ;;
        macos:arm64)
            echo "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_osx_arm64"
            ;;
        linux:x86_64)
            if [[ "${LINUX_FLAVOR}" == "musl" ]]; then
                echo "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_musllinux_x86"
            else
                echo "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86"
            fi
            ;;
        linux:arm64)
            if [[ "${LINUX_FLAVOR}" == "musl" ]]; then
                echo "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_musllinux_aarch64"
            else
                echo "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_aarch64"
            fi
            ;;
        *)
            fail "Unsupported OpenGrep target: ${OS_NAME}/${ARCH_NAME}"
            ;;
    esac
}

install_opengrep() {
    local opengrep_url

    mkdir -p "${BIN_DIR}"

    if is_executable_file "${OPENGREP_BIN}"; then
        success "OpenGrep already installed"
        return
    fi

    info "Downloading OpenGrep"
    opengrep_url="$(opengrep_asset_url)"
    download_file "${opengrep_url}" "${OPENGREP_BIN}"
    chmod +x "${OPENGREP_BIN}"
    success "OpenGrep installed"
}

create_venv() {
    info "Creating virtual environment"
    rm -rf "${VENV_DIR}"
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
    if [[ "${PIP_INSTALL_APPROVED}" != "1" ]]; then
        if ! confirm "This will install Python packages into ${VENV_DIR}. Continue?"; then
            fail "Aborted before installing Python dependencies"
        fi
        PIP_INSTALL_APPROVED="1"
    fi
    "${VENV_DIR}/bin/python" -m pip install --upgrade pip
    "${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
    success "Virtual environment ready"
}

write_native_config() {
    [[ -f "${CONFIG_TEMPLATE}" ]] || fail "Config template not found: ${CONFIG_TEMPLATE}"

    info "Writing native config"
    mkdir -p "$(dirname "${NATIVE_CONFIG_PATH}")"

    "${PYTHON_BIN}" - "${CONFIG_TEMPLATE}" "${NATIVE_CONFIG_PATH}" "${ASTRAIL_BIN}" "${JAVASRC2CPG_BIN}" "${OPENGREP_BIN}" <<'PY'
import pathlib
import sys

template = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
astrail_path = sys.argv[3]
javasrc2cpg_path = sys.argv[4]
opengrep_path = sys.argv[5]

lines = template.read_text(encoding="utf-8").splitlines()
output_lines = []

in_tools = False
in_astrail = False
in_opengrep = False
seen_astrailpath = False
seen_javasrc2cpg = False
seen_opengrep_path = False

for line in lines:
    stripped = line.strip()

    if stripped and not line.startswith(" "):
        in_tools = stripped == "tools:"
        in_astrail = False
        in_opengrep = False
        output_lines.append(line)
        continue

    if in_tools and line.startswith("  ") and not line.startswith("    "):
        in_astrail = stripped == "astrail:"
        in_opengrep = stripped == "opengrep:"
        output_lines.append(line)
        continue

    if in_astrail and stripped.startswith("astrailpath:"):
        output_lines.append(f"    astrailpath: '{astrail_path}'")
        seen_astrailpath = True
        continue

    if in_astrail and stripped.startswith("javasrc2cpg:"):
        output_lines.append(f"    javasrc2cpg: '{javasrc2cpg_path}'")
        seen_javasrc2cpg = True
        continue

    if in_opengrep and stripped.startswith("path:"):
        output_lines.append(f"    path: '{opengrep_path}'")
        seen_opengrep_path = True
        continue

    output_lines.append(line)

if not seen_astrailpath or not seen_javasrc2cpg or not seen_opengrep_path:
    missing = []
    if not seen_astrailpath:
        missing.append("tools.astrail.astrailpath")
    if not seen_javasrc2cpg:
        missing.append("tools.astrail.javasrc2cpg")
    if not seen_opengrep_path:
        missing.append("tools.opengrep.path")
    raise SystemExit(f"Failed to update config keys: {', '.join(missing)}")

target.write_text("\n".join(output_lines) + "\n", encoding="utf-8")
PY

    success "Native config written to ${NATIVE_CONFIG_PATH}"
}

write_env_file() {
    local env_file

    env_file="${SCRIPT_DIR}/.native-env"
    cat > "${env_file}" <<EOF
export JAVA_HOME='${JAVA_HOME}'
export PATH='${BIN_DIR}:${JAVA_HOME}/bin:'"\$PATH"
EOF
    success "Environment helper written to ${env_file}"
}

print_summary() {
    cat <<EOF

Native bootstrap complete.

Tools directory : ${TOOLS_DIR}
Virtual env     : ${VENV_DIR}
Native config   : ${NATIVE_CONFIG_PATH}
JAVA_HOME       : ${JAVA_HOME}

Next steps:
1. source "${VENV_DIR}/bin/activate"
2. source "${SCRIPT_DIR}/.native-env"
3. python main.py --config "${NATIVE_CONFIG_PATH}" --path /absolute/path/to/source --output report.html
EOF
}

main() {
    info "Preparing native Nika environment"
    detect_os_arch
    ensure_base_tools
    ensure_python
    ensure_jdk
    resolve_java_home
    install_astrail
    install_opengrep
    create_venv
    write_native_config
    write_env_file
    print_summary
}

main "$@"