#!/bin/bash
#
# Development Dependencies Setup Script
#
# This script installs and configures the required development dependencies
# for building and testing the sandbox project, including:
#   - Go (version 1.24.0 or later)
#   - QEMU (qemu-system-x86_64 and related tools)
#   - golangci-lint (for code linting)
#
# Usage: ./setup-dev-dependencies.sh [OPTIONS]
#
# Options:
#   --go-version VERSION       Go version to install (default: 1.24.4)
#   --skip-go                  Skip Go installation
#   --skip-qemu                Skip QEMU installation
#   --skip-golangci-lint       Skip golangci-lint installation
#   --go-install-method METHOD Go installation method: 'official' or 'apt' (default: official)
#   -h, --help                 Show this help message
#

set -euo pipefail

# Default configuration
GO_VERSION="${GO_VERSION:-1.24.4}"
GO_INSTALL_METHOD="${GO_INSTALL_METHOD:-official}"
GOLANGCI_LINT_VERSION="${GOLANGCI_LINT_VERSION:-latest}"
SKIP_GO=0
SKIP_QEMU=0
SKIP_GOLANGCI_LINT=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

show_help() {
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# //g' | sed 's/^#//g'
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --go-version)
            GO_VERSION="$2"
            shift 2
            ;;
        --skip-go)
            SKIP_GO=1
            shift
            ;;
        --skip-qemu)
            SKIP_QEMU=1
            shift
            ;;
        --skip-golangci-lint)
            SKIP_GOLANGCI_LINT=1
            shift
            ;;
        --go-install-method)
            GO_INSTALL_METHOD="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            ;;
    esac
done

log_info "Development Dependencies Setup"
log_info "==============================="
log_info ""

# Detect OS and architecture
detect_system() {
    log_info "Detecting system..."
    
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    
    case "$OS" in
        Linux*)
            OS="linux"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="$ID"
                DISTRO_VERSION="$VERSION_ID"
            else
                DISTRO="unknown"
                DISTRO_VERSION="unknown"
            fi
            ;;
        Darwin*)
            OS="darwin"
            DISTRO="macos"
            DISTRO_VERSION="$(sw_vers -productVersion)"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            GO_ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            GO_ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "OS: $OS ($DISTRO $DISTRO_VERSION)"
    log_info "Architecture: $ARCH"
    log_info ""
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Go installation
check_go() {
    if command_exists go; then
        INSTALLED_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go is already installed: $INSTALLED_GO_VERSION"
        
        # Compare versions
        if [ "$(printf '%s\n' "$GO_VERSION" "$INSTALLED_GO_VERSION" | sort -V | head -n1)" = "$GO_VERSION" ] && [ "$INSTALLED_GO_VERSION" != "$GO_VERSION" ]; then
            log_success "Installed Go version ($INSTALLED_GO_VERSION) meets minimum requirement ($GO_VERSION)"
            return 0
        elif [ "$INSTALLED_GO_VERSION" = "$GO_VERSION" ]; then
            log_success "Installed Go version matches target version ($GO_VERSION)"
            return 0
        else
            log_warn "Installed Go version ($INSTALLED_GO_VERSION) is older than target ($GO_VERSION)"
            return 1
        fi
    else
        log_info "Go is not installed"
        return 1
    fi
}

# Install Go from official tarball
install_go_official() {
    log_info "Installing Go $GO_VERSION from official source..."
    
    local GO_TARBALL="go${GO_VERSION}.${OS}-${GO_ARCH}.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TARBALL}"
    local TEMP_DIR=$(mktemp -d)
    
    log_info "Downloading Go from $GO_URL..."
    if command_exists wget; then
        wget -q --show-progress -O "$TEMP_DIR/$GO_TARBALL" "$GO_URL" || {
            log_error "Failed to download Go"
            rm -rf "$TEMP_DIR"
            exit 1
        }
    elif command_exists curl; then
        curl -L -o "$TEMP_DIR/$GO_TARBALL" "$GO_URL" || {
            log_error "Failed to download Go"
            rm -rf "$TEMP_DIR"
            exit 1
        }
    else
        log_error "Neither wget nor curl is available. Please install one of them."
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    log_info "Extracting Go..."
    
    # Determine installation directory
    if [ "$EUID" -eq 0 ]; then
        # Running as root, install to /usr/local
        INSTALL_DIR="/usr/local"
        log_info "Installing to $INSTALL_DIR (system-wide)..."
        rm -rf "$INSTALL_DIR/go"
        tar -C "$INSTALL_DIR" -xzf "$TEMP_DIR/$GO_TARBALL"
        GO_BIN="$INSTALL_DIR/go/bin"
    else
        # Running as regular user, install to ~/.local
        INSTALL_DIR="$HOME/.local"
        log_info "Installing to $INSTALL_DIR (user-local)..."
        mkdir -p "$INSTALL_DIR"
        rm -rf "$INSTALL_DIR/go"
        tar -C "$INSTALL_DIR" -xzf "$TEMP_DIR/$GO_TARBALL"
        GO_BIN="$INSTALL_DIR/go/bin"
    fi
    
    rm -rf "$TEMP_DIR"
    
    # Add to PATH if not already there
    log_info "Setting up environment..."
    if [[ ":$PATH:" != *":$GO_BIN:"* ]]; then
        export PATH="$GO_BIN:$PATH"
        
        # Add to shell profile
        local SHELL_PROFILE=""
        if [ -f "$HOME/.bashrc" ]; then
            SHELL_PROFILE="$HOME/.bashrc"
        elif [ -f "$HOME/.bash_profile" ]; then
            SHELL_PROFILE="$HOME/.bash_profile"
        elif [ -f "$HOME/.zshrc" ]; then
            SHELL_PROFILE="$HOME/.zshrc"
        fi
        
        if [ -n "$SHELL_PROFILE" ]; then
            if ! grep -q "export PATH.*$GO_BIN" "$SHELL_PROFILE" 2>/dev/null; then
                log_info "Adding Go to PATH in $SHELL_PROFILE..."
                echo "" >> "$SHELL_PROFILE"
                echo "# Go installation" >> "$SHELL_PROFILE"
                echo "export PATH=\"$GO_BIN:\$PATH\"" >> "$SHELL_PROFILE"
                log_warn "Added Go to PATH in $SHELL_PROFILE. You may need to restart your shell or run: source $SHELL_PROFILE"
            fi
        fi
    fi
    
    # Verify installation
    if command_exists go; then
        INSTALLED_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_success "Go $INSTALLED_VERSION installed successfully!"
        log_info "Go binary: $(which go)"
    else
        log_error "Go installation verification failed"
        exit 1
    fi
}

# Install Go via package manager
install_go_apt() {
    log_info "Installing Go via APT package manager..."
    
    # For newer Go versions, we may need to add PPA
    if ! apt-cache show golang-go | grep -q "Version: 1.2[0-9]" 2>/dev/null; then
        log_warn "System Go package may be outdated. Consider using --go-install-method=official"
    fi
    
    sudo apt-get update
    sudo apt-get install -y golang-go
    
    # Verify installation
    if command_exists go; then
        INSTALLED_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_success "Go $INSTALLED_VERSION installed successfully!"
    else
        log_error "Go installation verification failed"
        exit 1
    fi
}

# Install QEMU
install_qemu() {
    log_info "Installing QEMU..."
    
    case "$DISTRO" in
        ubuntu|debian)
            log_info "Installing QEMU via APT..."
            sudo apt-get update
            sudo apt-get install -y \
                qemu-system-x86 \
                qemu-system-arm \
                qemu-utils \
                libvirt-daemon-system \
                libvirt-clients
            ;;
        fedora|rhel|centos)
            log_info "Installing QEMU via DNF/YUM..."
            if command_exists dnf; then
                sudo dnf install -y \
                    qemu-system-x86 \
                    qemu-system-arm \
                    qemu-img
            else
                sudo yum install -y \
                    qemu-system-x86 \
                    qemu-system-arm \
                    qemu-img
            fi
            ;;
        arch|manjaro)
            log_info "Installing QEMU via Pacman..."
            sudo pacman -Sy --noconfirm qemu-full
            ;;
        macos)
            log_info "Installing QEMU via Homebrew..."
            if ! command_exists brew; then
                log_error "Homebrew is not installed. Please install Homebrew first: https://brew.sh/"
                exit 1
            fi
            brew install qemu
            ;;
        *)
            log_error "Unsupported distribution: $DISTRO"
            log_error "Please install QEMU manually"
            exit 1
            ;;
    esac
    
    # Verify installation
    if command_exists qemu-system-x86_64; then
        QEMU_VERSION=$(qemu-system-x86_64 --version | head -n1)
        log_success "QEMU installed successfully: $QEMU_VERSION"
        log_info "QEMU binary: $(which qemu-system-x86_64)"
    else
        log_error "QEMU installation verification failed"
        exit 1
    fi
}

# Check QEMU installation
check_qemu() {
    if command_exists qemu-system-x86_64; then
        QEMU_VERSION=$(qemu-system-x86_64 --version | head -n1)
        log_success "QEMU is already installed: $QEMU_VERSION"
        return 0
    else
        log_info "QEMU is not installed"
        return 1
    fi
}

# Check golangci-lint installation
check_golangci_lint() {
    if command_exists golangci-lint; then
        GOLANGCI_LINT_VERSION=$(golangci-lint --version 2>/dev/null | head -n1 | awk '{print $4}')
        log_success "golangci-lint is already installed: $GOLANGCI_LINT_VERSION"
        return 0
    else
        log_info "golangci-lint is not installed"
        return 1
    fi
}

# Install golangci-lint
install_golangci_lint() {
    log_info "Installing golangci-lint..."
    
    if ! command_exists go; then
        log_error "Go is not installed. Please install Go first."
        exit 1
    fi
    
    # Use the official installation script
    local TEMP_DIR=$(mktemp -d)
    local INSTALL_SCRIPT="$TEMP_DIR/install.sh"
    
    log_info "Downloading golangci-lint installation script..."
    if command_exists curl; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh -o "$INSTALL_SCRIPT" || {
            log_error "Failed to download golangci-lint installation script"
            rm -rf "$TEMP_DIR"
            exit 1
        }
    elif command_exists wget; then
        wget -q -O "$INSTALL_SCRIPT" https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh || {
            log_error "Failed to download golangci-lint installation script"
            rm -rf "$TEMP_DIR"
            exit 1
        }
    else
        log_error "Neither curl nor wget is available. Please install one of them."
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    chmod +x "$INSTALL_SCRIPT"
    
    # Determine installation directory
    local GOPATH=$(go env GOPATH)
    if [ -z "$GOPATH" ]; then
        GOPATH="$HOME/go"
    fi
    local BIN_DIR="$GOPATH/bin"
    
    mkdir -p "$BIN_DIR"
    
    log_info "Installing golangci-lint to $BIN_DIR..."
    sh "$INSTALL_SCRIPT" -b "$BIN_DIR" "$GOLANGCI_LINT_VERSION" || {
        log_error "Failed to install golangci-lint"
        rm -rf "$TEMP_DIR"
        exit 1
    }
    
    rm -rf "$TEMP_DIR"
    
    # Add GOPATH/bin to PATH if not already there
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        export PATH="$BIN_DIR:$PATH"
        
        # Add to shell profile
        local SHELL_PROFILE=""
        if [ -f "$HOME/.bashrc" ]; then
            SHELL_PROFILE="$HOME/.bashrc"
        elif [ -f "$HOME/.bash_profile" ]; then
            SHELL_PROFILE="$HOME/.bash_profile"
        elif [ -f "$HOME/.zshrc" ]; then
            SHELL_PROFILE="$HOME/.zshrc"
        fi
        
        if [ -n "$SHELL_PROFILE" ]; then
            if ! grep -q "export PATH.*$BIN_DIR" "$SHELL_PROFILE" 2>/dev/null; then
                log_info "Adding $BIN_DIR to PATH in $SHELL_PROFILE..."
                echo "" >> "$SHELL_PROFILE"
                echo "# Go binaries" >> "$SHELL_PROFILE"
                echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_PROFILE"
            fi
        fi
    fi
    
    # Verify installation
    if command_exists golangci-lint; then
        INSTALLED_VERSION=$(golangci-lint --version 2>/dev/null | head -n1 | awk '{print $4}')
        log_success "golangci-lint $INSTALLED_VERSION installed successfully!"
        log_info "golangci-lint binary: $(which golangci-lint)"
    else
        log_error "golangci-lint installation verification failed"
        exit 1
    fi
}

# Main installation flow
main() {
    detect_system
    
    # Install Go
    if [ $SKIP_GO -eq 0 ]; then
        log_info "Checking Go installation..."
        if ! check_go; then
            case "$GO_INSTALL_METHOD" in
                official)
                    install_go_official
                    ;;
                apt)
                    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
                        install_go_apt
                    else
                        log_error "APT installation method is only supported on Debian/Ubuntu"
                        log_error "Use --go-install-method=official for this system"
                        exit 1
                    fi
                    ;;
                *)
                    log_error "Unknown Go installation method: $GO_INSTALL_METHOD"
                    log_error "Valid options: official, apt"
                    exit 1
                    ;;
            esac
        fi
        log_info ""
    else
        log_warn "Skipping Go installation (--skip-go)"
        log_info ""
    fi
    
    # Install QEMU
    if [ $SKIP_QEMU -eq 0 ]; then
        log_info "Checking QEMU installation..."
        if ! check_qemu; then
            install_qemu
        fi
        log_info ""
    else
        log_warn "Skipping QEMU installation (--skip-qemu)"
        log_info ""
    fi
    
    # Install golangci-lint
    if [ $SKIP_GOLANGCI_LINT -eq 0 ]; then
        log_info "Checking golangci-lint installation..."
        if ! check_golangci_lint; then
            install_golangci_lint
        fi
        log_info ""
    else
        log_warn "Skipping golangci-lint installation (--skip-golangci-lint)"
        log_info ""
    fi
    
    # Summary
    log_success "================================"
    log_success "Setup completed successfully!"
    log_success "================================"
    log_info ""
    log_info "Installed tools:"
    
    if [ $SKIP_GO -eq 0 ] && command_exists go; then
        log_info "  Go:              $(go version | awk '{print $3}') ($(which go))"
    fi
    
    if [ $SKIP_QEMU -eq 0 ] && command_exists qemu-system-x86_64; then
        log_info "  QEMU:            $(qemu-system-x86_64 --version | head -n1 | awk '{print $4}') ($(which qemu-system-x86_64))"
    fi
    
    if [ $SKIP_GOLANGCI_LINT -eq 0 ] && command_exists golangci-lint; then
        log_info "  golangci-lint:   $(golangci-lint --version 2>/dev/null | head -n1 | awk '{print $4}') ($(which golangci-lint))"
    fi
    
    log_info ""
    log_info "Next steps:"
    log_info "  1. If Go was installed for the first time, you may need to restart your shell"
    log_info "  2. Run 'make build' to build the project"
    log_info "  3. Run 'make verify' to run tests and linting"
    log_info "  4. See README.md for more information"
    log_info ""
}

# Run main function
main
