#!/bin/bash
#
# Foundry Sandbox Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
#
# Or with options:
#   curl -fsSL ... | bash -s -- --no-build
#

set -e

# Configuration
INSTALL_DIR="${FOUNDRY_SANDBOX_HOME:-$HOME/.foundry-sandbox}"
REPO_URL="https://github.com/foundry-works/foundry-sandbox.git"
BRANCH="main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Options
BUILD_IMAGE=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)
            BUILD_IMAGE=false
            shift
            ;;
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --branch)
            BRANCH="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}"
echo "  ___                 _              ___              _ _"
echo " | __|__ _  _ _ _  __| |_ _ _  _    / __| __ _ _ _  __| | |__  _____ __"
echo " | _/ _ \\ || | ' \\/ _\` | '_| || |   \\__ \\/ _\` | ' \\/ _\` | '_ \\/ _ \\ \\ /"
echo " |_|\\___/\\_,_|_||_\\__,_|_|  \\_, |   |___/\\__,_|_||_\\__,_|_.__/\\___/_\\_\\"
echo "                            |__/"
echo -e "${NC}"
echo "Installer"
echo ""

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

check_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "${RED}Error: $1 is required but not installed.${NC}"
        echo "  Install $1 and try again."
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} $1"
}

check_command git
check_command docker
check_command tmux

# Check Docker daemon
if ! docker info &>/dev/null; then
    echo -e "${RED}Error: Docker daemon is not running.${NC}"
    echo "  Start Docker and try again."
    exit 1
fi
echo -e "  ${GREEN}✓${NC} docker daemon"

echo ""

# Detect shell
detect_shell_rc() {
    local shell_name
    shell_name=$(basename "$SHELL")

    case "$shell_name" in
        zsh)
            echo "$HOME/.zshrc"
            ;;
        bash)
            if [[ -f "$HOME/.bashrc" ]]; then
                echo "$HOME/.bashrc"
            elif [[ -f "$HOME/.bash_profile" ]]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.bashrc"
            fi
            ;;
        *)
            echo "$HOME/.bashrc"
            ;;
    esac
}

SHELL_RC=$(detect_shell_rc)

# Clone or update repository
if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}Found existing installation at $INSTALL_DIR${NC}"
    echo -n "Update to latest version? [Y/n] "
    read -r response
    if [[ "$response" =~ ^[Nn] ]]; then
        echo "Keeping existing installation."
    else
        echo "Updating..."
        cd "$INSTALL_DIR"
        git fetch origin
        git checkout "$BRANCH"
        git pull origin "$BRANCH"
        echo -e "${GREEN}Updated to latest version.${NC}"
    fi
else
    echo -e "${BLUE}Installing to $INSTALL_DIR...${NC}"
    git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    echo -e "${GREEN}Cloned repository.${NC}"
fi

echo ""

# Add alias to shell rc
ALIAS_LINE="alias cast='$INSTALL_DIR/sandbox.sh'"
COMPLETION_LINE="source '$INSTALL_DIR/completion.bash'"

add_to_shell_rc() {
    local line="$1"
    local description="$2"

    if grep -qF "$line" "$SHELL_RC" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $description (already configured)"
    else
        echo "" >> "$SHELL_RC"
        echo "# Foundry Sandbox" >> "$SHELL_RC"
        echo "$line" >> "$SHELL_RC"
        echo -e "  ${GREEN}✓${NC} $description (added to $SHELL_RC)"
    fi
}

echo -e "${BLUE}Configuring shell...${NC}"
add_to_shell_rc "$ALIAS_LINE" "cast alias"
add_to_shell_rc "$COMPLETION_LINE" "tab completion"

echo ""

# Build Docker image
if [[ "$BUILD_IMAGE" == true ]]; then
    echo -e "${BLUE}Building Docker image...${NC}"
    echo "  This may take a few minutes on first run."
    echo ""

    cd "$INSTALL_DIR"
    if ./sandbox.sh build; then
        echo ""
        echo -e "${GREEN}Docker image built successfully.${NC}"
    else
        echo ""
        echo -e "${YELLOW}Warning: Docker build failed.${NC}"
        echo "  You can retry later with: cast build"
    fi
else
    echo -e "${YELLOW}Skipping Docker build (--no-build).${NC}"
    echo "  Run 'cast build' when ready."
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "To get started:"
echo ""
echo "  1. Reload your shell:"
echo -e "     ${BLUE}source $SHELL_RC${NC}"
echo ""
echo "  2. Create your first sandbox:"
echo -e "     ${BLUE}cast new owner/repo${NC}"
echo ""
echo "  3. See all commands:"
echo -e "     ${BLUE}cast help${NC}"
echo ""
echo "Documentation: https://github.com/foundry-works/foundry-sandbox"
echo ""
