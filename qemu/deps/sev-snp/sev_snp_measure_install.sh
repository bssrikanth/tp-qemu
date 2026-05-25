#!/bin/bash
# Host-side installer for virtee/sev-snp-measure
# (https://github.com/virtee/sev-snp-measure).

set -u

check_status() {
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
}

usage() {
    echo "Usage: $0 [--repo URL] [--branch BRANCH | --tag TAG]"
    echo "          [--install-dir DIR] [--bin-dir DIR]"
    echo "  --repo        : Git repository URL"
    echo "                  (default: https://github.com/virtee/sev-snp-measure.git)"
    echo "  --branch      : Branch to checkout (default: main)"
    echo "  --tag         : Tag to checkout (mutually exclusive with --branch)"
    echo "  --install-dir : Where to clone the source tree"
    echo "                  (default: /usr/local/share/sev-snp-measure)"
    echo "  --bin-dir     : Where to drop the 'sev-snp-measure' wrapper"
    echo "                  (default: /usr/local/bin)"
    exit 1
}

REPO_URL="https://github.com/virtee/sev-snp-measure.git"
BRANCH="main"
TAG=""
INSTALL_DIR="/usr/local/share/sev-snp-measure"
BIN_DIR="/usr/local/bin"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)
            REPO_URL="$2"
            shift 2
            ;;
        --branch)
            [ -n "$TAG" ] && { echo "Error: --branch and --tag are mutually exclusive"; usage; }
            BRANCH="$2"
            shift 2
            ;;
        --tag)
            [ -n "$BRANCH" ] && [ "$BRANCH" != "main" ] && { echo "Error: --branch and --tag are mutually exclusive"; usage; }
            TAG="$2"
            BRANCH=""
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --bin-dir)
            BIN_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    sudo -n true 2>/dev/null
    check_status "root or passwordless sudo required to write under ${BIN_DIR}/${INSTALL_DIR}"
    SUDO="sudo -n"
else
    SUDO=""
fi

echo "Validating repository: $REPO_URL..."
git ls-remote "$REPO_URL" >/dev/null 2>&1
check_status "Invalid or inaccessible repository: $REPO_URL"

if [ -n "$TAG" ]; then
    echo "Validating tag: $TAG..."
    git ls-remote --exit-code --tags "$REPO_URL" "refs/tags/$TAG" >/dev/null
    check_status "Tag '$TAG' does not exist in repository"
elif [ -n "$BRANCH" ]; then
    echo "Validating branch: $BRANCH..."
    git ls-remote --exit-code --heads "$REPO_URL" "refs/heads/$BRANCH" >/dev/null
    check_status "Branch '$BRANCH' does not exist in repository"
fi

echo "Installing build prerequisites..."
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect operating system."
    exit 1
fi

case "$OS" in
    ubuntu|debian)
        $SUDO apt update
        check_status "Failed to update package lists"
        $SUDO apt install -y git python3 python3-pip
        check_status "Failed to install python3 / pip / git"
        ;;
    rhel|centos|fedora|rocky|almalinux)
        $SUDO yum install -y git python3 python3-pip
        check_status "Failed to install python3 / pip / git"
        ;;
    sles|suse|opensuse-leap|opensuse-tumbleweed)
        $SUDO zypper -n install -y git python3 python3-pip
        check_status "Failed to install python3 / pip / git"
        ;;
    *)
        echo "Warning: unsupported OS '$OS'; assuming git + python3 + pip3 are already installed."
        ;;
esac

command -v git >/dev/null 2>&1
check_status "git is required but not on PATH"
command -v python3 >/dev/null 2>&1
check_status "python3 is required but not on PATH"
command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1
check_status "pip3 is required but not on PATH"

PIP=$(command -v pip3 || command -v pip)

# Clone or update the source tree at $INSTALL_DIR. Idempotent so the
# autoinstall path stays cheap on subsequent runs.
$SUDO mkdir -p "$(dirname "$INSTALL_DIR")"
check_status "Failed to create parent of $INSTALL_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing checkout at $INSTALL_DIR..."
    $SUDO git -C "$INSTALL_DIR" fetch --all --tags
    check_status "Failed to fetch updates in $INSTALL_DIR"
    if [ -n "$TAG" ]; then
        $SUDO git -C "$INSTALL_DIR" checkout "tags/$TAG"
        check_status "Failed to checkout tag $TAG"
    else
        $SUDO git -C "$INSTALL_DIR" checkout "$BRANCH"
        check_status "Failed to checkout branch $BRANCH"
        $SUDO git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
        check_status "Failed to fast-forward $BRANCH"
    fi
else
    echo "Cloning $REPO_URL into $INSTALL_DIR..."
    [ -e "$INSTALL_DIR" ] && $SUDO rm -rf "$INSTALL_DIR"
    $SUDO git clone "$REPO_URL" "$INSTALL_DIR"
    check_status "Failed to clone $REPO_URL"
    if [ -n "$TAG" ]; then
        $SUDO git -C "$INSTALL_DIR" checkout "tags/$TAG"
        check_status "Failed to checkout tag $TAG"
    elif [ "$BRANCH" != "main" ]; then
        $SUDO git -C "$INSTALL_DIR" checkout "$BRANCH"
        check_status "Failed to checkout branch $BRANCH"
    fi
fi

echo "Installing Python runtime dependencies..."
REQS="$INSTALL_DIR/requirements.txt"
if [ -f "$REQS" ]; then
    PIP_ERR=$(mktemp)
    if ! $SUDO "$PIP" install -r "$REQS" 2>"$PIP_ERR"; then
        if grep -qE "externally-managed-environment|RECORD file not found|Cannot uninstall.*installed by debian" "$PIP_ERR"; then
            echo "Pip failure recoverable with --break-system-packages; retrying..."
            PIP_ERR2=$(mktemp)
            if ! $SUDO "$PIP" install --break-system-packages -r "$REQS" 2>"$PIP_ERR2"; then
                cat "$PIP_ERR2" >&2
                echo
                echo "ERROR: pip install failed even with --break-system-packages."
                if grep -qE "Cannot uninstall .* RECORD file not found" "$PIP_ERR2"; then
                    offender=$(grep -oE "Cannot uninstall [A-Za-z0-9_.-]+ [0-9][0-9A-Za-z.+!-]*" "$PIP_ERR2" | head -1)
                    pkg=$(echo "$offender" | awk '{print $3}')
                    echo "Cause: a distro-managed Python package is blocking the install ($offender)."
                    echo "Action required: remove the conflicting OS package and re-run this installer."
                fi
                rm -f "$PIP_ERR" "$PIP_ERR2"
                exit 1
            fi
            rm -f "$PIP_ERR2"
        else
            cat "$PIP_ERR" >&2
            rm -f "$PIP_ERR"
            echo "Error: pip install failed"
            exit 1
        fi
    fi
    rm -f "$PIP_ERR"
else
    echo "Warning: $REQS not found; skipping pip install."
fi

WRAPPER="$BIN_DIR/sev-snp-measure"
echo "Installing wrapper at $WRAPPER..."
$SUDO mkdir -p "$BIN_DIR"
check_status "Failed to create $BIN_DIR"
$SUDO tee "$WRAPPER" >/dev/null <<EOF
#!/bin/sh
# Auto-generated by qemu/deps/sev-snp/sev_snp_measure_install.sh
# Source: $REPO_URL ($([ -n "$TAG" ] && echo "tag=$TAG" || echo "branch=$BRANCH"))
exec python3 "$INSTALL_DIR/sev-snp-measure.py" "\$@"
EOF
check_status "Failed to write $WRAPPER"
$SUDO chmod 755 "$WRAPPER"
check_status "Failed to chmod $WRAPPER"

echo "Verifying installation..."
"$WRAPPER" --version
check_status "sev-snp-measure verification failed"

echo "sev-snp-measure installed successfully at $WRAPPER (source: $INSTALL_DIR)."
exit 0
