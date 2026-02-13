#!/bin/bash
#
# Foundry Sandbox Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
#
# Or with options:
#   curl -fsSL ... | bash -s -- --no-build
#   curl -fsSL ... | bash -s -- --no-cache   # Force rebuild without cache
#   ./install.sh --repo /path/to/foundry-sandbox   # Install from local path (offline)
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
NO_CACHE=""
WITHOUT_OPENCODE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)
            BUILD_IMAGE=false
            shift
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --without-opencode)
            WITHOUT_OPENCODE="--without-opencode"
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
        --repo)
            REPO_URL="$2"
            shift 2
            ;;
        --repo=*)
            REPO_URL="${1#*=}"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

REPO_LOCAL=false
if [[ "$REPO_URL" == ~* ]]; then
    REPO_URL="${REPO_URL/#\~/$HOME}"
fi
if [[ "$REPO_URL" == file://* ]]; then
    REPO_URL="${REPO_URL#file://}"
fi
if [ -e "$REPO_URL" ]; then
    REPO_LOCAL=true
fi

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

check_git() {
    if command -v git &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} git"
        return 0
    fi
    echo -e "  ${RED}✗${NC} git (not found)"
    echo ""
    echo -e "${RED}Error: git is required but not installed.${NC}"
    echo ""
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  Install with: xcode-select --install"
        echo "  Or: brew install git"
    else
        echo "  Install with: sudo apt-get install git"
        echo "  Or: sudo dnf install git"
    fi
    exit 1
}

check_docker() {
    if command -v docker &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} docker"
        return 0
    fi
    echo -e "  ${RED}✗${NC} docker (not found)"
    echo ""
    echo -e "${RED}Error: Docker is required but not installed.${NC}"
    echo ""
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "  Install Docker Desktop: https://docs.docker.com/desktop/install/mac-install/"
        echo "  Or with Homebrew: brew install --cask docker"
    else
        echo "  Install Docker Engine: https://docs.docker.com/engine/install/"
    fi
    exit 1
}

install_tmux() {
    if command -v tmux &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} tmux"
        return 0
    fi

    echo -e "  Installing tmux..."
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &>/dev/null; then
            brew install tmux
        else
            echo -e "  ${RED}✗${NC} tmux (Homebrew required)"
            echo -e "${RED}Error: Install Homebrew first, then run installer again.${NC}"
            exit 1
        fi
    elif command -v apt-get &>/dev/null; then
        sudo apt-get update &>/dev/null && sudo apt-get install -y tmux &>/dev/null
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y tmux &>/dev/null
    elif command -v yum &>/dev/null; then
        sudo yum install -y tmux &>/dev/null
    else
        echo -e "  ${RED}✗${NC} tmux (unknown package manager)"
        echo -e "${RED}Error: Install tmux manually and run installer again.${NC}"
        exit 1
    fi

    if command -v tmux &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} tmux installed"
    else
        echo -e "  ${RED}✗${NC} tmux (installation failed)"
        exit 1
    fi
}

install_gum() {
    if command -v gum &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} gum"
        return 0
    fi

    echo -e "  Installing gum..."
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v brew &>/dev/null; then
            brew install gum
        else
            echo -e "  ${YELLOW}⚠${NC} gum (skipped - no brew)"
            return 0
        fi
    elif command -v apt-get &>/dev/null; then
        # Add Charm repo for Debian/Ubuntu
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg 2>/dev/null
        echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list >/dev/null
        sudo apt-get update &>/dev/null && sudo apt-get install -y gum &>/dev/null
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        # Download binary directly - more reliable than COPR
        local arch=$(uname -m)
        # Gum uses x86_64/arm64 in filenames, not amd64
        local tmp_dir=$(mktemp -d)
        # Get latest version tag
        local version=$(curl -fsSL "https://api.github.com/repos/charmbracelet/gum/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        version="${version:-0.17.0}"
        local url="https://github.com/charmbracelet/gum/releases/download/v${version}/gum_${version}_Linux_${arch}.tar.gz"
        if curl -fsSL "$url" -o "$tmp_dir/gum.tar.gz" 2>/dev/null; then
            tar -xzf "$tmp_dir/gum.tar.gz" -C "$tmp_dir" 2>/dev/null
            # Binary is in a subdirectory named gum_VERSION_Linux_ARCH/
            local gum_bin=$(find "$tmp_dir" -name gum -type f 2>/dev/null | head -1)
            if [ -n "$gum_bin" ]; then
                mkdir -p "$HOME/.local/bin"
                sudo install -m 755 "$gum_bin" /usr/local/bin/gum 2>/dev/null || \
                    install -m 755 "$gum_bin" "$HOME/.local/bin/gum" 2>/dev/null
            fi
        fi
        rm -rf "$tmp_dir"
    else
        echo -e "  ${YELLOW}⚠${NC} gum (skipped - unknown package manager)"
        return 0
    fi

    if command -v gum &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} gum installed"
    else
        echo -e "  ${YELLOW}⚠${NC} gum (install failed - optional)"
    fi
}

check_git
check_docker
install_tmux
install_gum

# Check Docker daemon (with timeout to avoid hanging)
echo -ne "  Checking docker daemon..."
timeout_docker_check() {
    # Try gtimeout (macOS with coreutils), then timeout (Linux), then fallback
    if command -v gtimeout &>/dev/null; then
        gtimeout 15 docker info &>/dev/null
    elif command -v timeout &>/dev/null; then
        timeout 15 docker info &>/dev/null
    else
        # Fallback: run directly (may hang if daemon is truly stuck)
        docker info &>/dev/null
    fi
}
if ! timeout_docker_check; then
    echo -e "\r  ${RED}✗${NC} docker daemon                    "
    echo ""
    echo -e "${RED}Error: Docker daemon is not responding.${NC}"
    echo ""
    echo "  Possible causes:"
    echo "    - Docker Desktop is still starting up (wait for it to fully load)"
    echo "    - Docker Desktop is not running (start it from Applications)"
    echo "    - Docker daemon is unresponsive (try restarting Docker Desktop)"
    echo ""
    echo "  To verify, run: docker info"
    echo ""
    exit 1
fi
echo -e "\r  ${GREEN}✓${NC} docker daemon                    "

echo ""

# Check API keys
echo -e "${BLUE}Checking API keys...${NC}"

# Determine script directory for local install, or use temp for curl install
if [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ -f "$(dirname "${BASH_SOURCE[0]}")/lib/api_keys.sh" ]]; then
    source "$(dirname "${BASH_SOURCE[0]}")/lib/api_keys.sh"
elif [[ -d "$INSTALL_DIR" ]] && [[ -f "$INSTALL_DIR/lib/api_keys.sh" ]]; then
    source "$INSTALL_DIR/lib/api_keys.sh"
else
    # Inline minimal check for curl-piped install (before repo is cloned)
    # Keys are expected to be set in the environment
    _check_api_keys_inline() {
        local has_ai_key=false
        local has_search_key=false

        # Check Claude authentication (OAuth token or API key)
        for key in CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY; do
            if [ -n "${!key:-}" ]; then
                has_ai_key=true
                break
            fi
        done
        # Check search provider keys
        if [ -n "${TAVILY_API_KEY:-}" ]; then
            has_search_key=true
        elif [ -n "${PERPLEXITY_API_KEY:-}" ]; then
            has_search_key=true
        fi

        # All keys present
        if [ "$has_ai_key" = "true" ] && [ "$has_search_key" = "true" ]; then
            echo -e "  ${GREEN}✓${NC} API keys configured"
            return 0
        fi

        # AI key present but no search key - warn but continue
        if [ "$has_ai_key" = "true" ]; then
            echo -e "  ${GREEN}✓${NC} AI provider keys configured"
            echo -e "${YELLOW}Warning: No search provider API keys found.${NC}"
            echo "Deep research features (foundry-mcp) will be unavailable."
            echo ""
            echo "Expected at least one of:"
            echo "  - TAVILY_API_KEY"
            echo "  - PERPLEXITY_API_KEY"
            echo ""
            return 0
        fi

        # No AI key - prompt to continue
        echo -e "${YELLOW}Warning: Claude authentication not found.${NC}"
        echo ""
        echo "Expected one of:"
        echo "  - CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)"
        echo "  - ANTHROPIC_API_KEY"
        echo ""
        if [ "$has_search_key" = "false" ]; then
            echo -e "${YELLOW}Warning: No search provider API keys found.${NC}"
            echo "Deep research features (foundry-mcp) will be unavailable."
            echo ""
            echo "Expected at least one of:"
            echo "  - TAVILY_API_KEY"
            echo "  - PERPLEXITY_API_KEY"
            echo ""
        fi
        echo "Set the required environment variables before running:"
        echo "  export CLAUDE_CODE_OAUTH_TOKEN=\"your-token\""
        echo "  export TAVILY_API_KEY=\"your-key\""
        echo ""
        echo "See .env.example for all supported keys."
        echo ""
        read -p "Continue without API keys? [y/N]: " response
        case "$response" in
            [yY]|[yY][eE][sS])
                echo -e "${YELLOW}Continuing without API keys...${NC}"
                return 0
                ;;
            *)
                echo -e "${RED}Installation cancelled.${NC}"
                return 1
                ;;
        esac
    }
    _check_api_keys_inline || exit 1
fi

# If we loaded api_keys.sh, use its functions
if type check_api_keys_with_prompt &>/dev/null; then
    check_api_keys_with_prompt "Installation" || exit 1
fi

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

sync_local_repo() {
    local src="$1"
    local dst="$2"

    if command -v rsync &>/dev/null; then
        rsync -a --delete --exclude '.git/' "$src"/ "$dst"/
    else
        echo -e "${YELLOW}Warning: rsync not found; using tar to copy (stale files may remain).${NC}"
        (cd "$src" && tar -cf - --exclude=.git .) | (cd "$dst" && tar -xf -)
    fi
}

# Install or update by syncing files (no .git in install dir)
install_from_source() {
    local source_dir="$1"
    mkdir -p "$INSTALL_DIR"
    sync_local_repo "$source_dir" "$INSTALL_DIR"

    # Touch stub files to force Docker Desktop file sync to notice changes
    # This is needed because Docker Desktop may cache bind mount contents
    find "$INSTALL_DIR/unified-proxy" -name 'stub-*.json' -exec touch {} \; 2>/dev/null || true
}

if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}Found existing installation at $INSTALL_DIR${NC}"
    echo -n "Update to latest version? [Y/n] "
    read -r response
    if [[ "$response" =~ ^[Nn] ]]; then
        echo "Keeping existing installation."
    else
        echo "Updating..."
        if [ "$REPO_LOCAL" = "true" ]; then
            echo "Syncing from local repo..."
            install_from_source "$REPO_URL"
        else
            TEMP_DIR=$(mktemp -d)
            trap "rm -rf '$TEMP_DIR'" EXIT
            echo "Fetching latest version..."
            git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TEMP_DIR" >/dev/null 2>&1
            install_from_source "$TEMP_DIR"
            rm -rf "$TEMP_DIR"
            trap - EXIT
        fi
        echo -e "${GREEN}Updated to latest version.${NC}"
    fi
else
    echo -e "${BLUE}Installing to $INSTALL_DIR...${NC}"
    if [ "$REPO_LOCAL" = "true" ]; then
        install_from_source "$REPO_URL"
    else
        TEMP_DIR=$(mktemp -d)
        trap "rm -rf '$TEMP_DIR'" EXIT
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TEMP_DIR" >/dev/null 2>&1
        install_from_source "$TEMP_DIR"
        rm -rf "$TEMP_DIR"
        trap - EXIT
    fi
    echo -e "${GREEN}Installed.${NC}"
fi

echo ""

# Migrate from old bash-based installation
# Remove legacy aliases and stale references from the shell-script era

# Patterns to remove from rc files (extended regex)
LEGACY_PATTERNS=(
    'alias cast=.*sandbox\.sh'
    "source.*Documents/GitHub/foundry-sandbox/completion\.bash"
)

migrate_legacy_rc() {
    local rc_file="$1"
    local found=false

    [ -f "$rc_file" ] || return 1

    for pattern in "${LEGACY_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$rc_file" 2>/dev/null; then
            echo -e "  ${YELLOW}⚠${NC} Removing legacy line from $rc_file: $pattern"
            # Use | as sed delimiter to avoid conflicts with / in paths
            sed -i.bak "\|$pattern|d" "$rc_file"
            rm -f "${rc_file}.bak"
            found=true
        fi
    done

    # Remove the _sb() completion function block if present
    if grep -q '^_sb()' "$rc_file" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} Removing legacy _sb() function from $rc_file"
        sed -i.bak '/^_sb()/,/^}/d' "$rc_file"
        rm -f "${rc_file}.bak"
        found=true
    fi

    [ "$found" = "true" ]
}

MIGRATED=false
# Scan standard rc files plus common custom rc files sourced from them
for rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc" "$HOME/.custom_zshrc" "$HOME/.aliases"; do
    if migrate_legacy_rc "$rc"; then
        MIGRATED=true
    fi
done
if [ "$MIGRATED" = "true" ]; then
    echo -e "  ${GREEN}✓${NC} Legacy references removed (cast is now installed via pip)"
fi

# Install Python package (provides `cast` entry point via pyproject.toml)
echo -e "${BLUE}Installing Python package...${NC}"
pip install -e "$INSTALL_DIR" >/dev/null 2>&1 && \
    echo -e "  ${GREEN}✓${NC} cast CLI installed ($(which cast 2>/dev/null || echo 'restart shell to use'))" || \
    echo -e "  ${RED}✗${NC} pip install failed — run manually: pip install -e $INSTALL_DIR"

COMPLETION_LINE="source '$INSTALL_DIR/completion.bash'"

add_to_shell_rc() {
    local line="$1"
    local description="$2"

    # Clean up orphaned "# Foundry Sandbox" comment lines (empty blocks from prior installs)
    if [ -f "$SHELL_RC" ]; then
        sed -i.bak '/^# Foundry Sandbox$/{ N; /^# Foundry Sandbox\n$/d; /^# Foundry Sandbox\n# Foundry Sandbox$/d; }' "$SHELL_RC"
        rm -f "${SHELL_RC}.bak"
    fi

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
add_to_shell_rc "$COMPLETION_LINE" "tab completion"

echo ""

# Build Docker image
if [[ "$BUILD_IMAGE" == true ]]; then
    echo -e "${BLUE}Building Docker image...${NC}"
    echo "  This may take a few minutes on first run."
    echo ""

    cd "$INSTALL_DIR"
    if cast build $NO_CACHE $WITHOUT_OPENCODE; then
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
if [ "$MIGRATED" = "true" ]; then
    echo "  1. Clear the stale alias from your current shell and reload:"
    echo -e "     ${BLUE}unalias cast 2>/dev/null; source $SHELL_RC${NC}"
else
    echo "  1. Reload your shell:"
    echo -e "     ${BLUE}source $SHELL_RC${NC}"
fi
echo ""
echo "  2. Create your first sandbox:"
echo -e "     ${BLUE}cast new owner/repo${NC}"
echo ""
echo "  3. See all commands:"
echo -e "     ${BLUE}cast help${NC}"
echo ""
echo "Documentation: https://github.com/foundry-works/foundry-sandbox"
echo ""
