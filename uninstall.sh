#!/bin/bash
#
# Foundry Sandbox Uninstaller
#
# Usage:
#   ~/.foundry-sandbox/uninstall.sh
#
# Or:
#   curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/uninstall.sh | bash
#

set -e

# Configuration
INSTALL_DIR="${FOUNDRY_SANDBOX_HOME:-$HOME/.foundry-sandbox}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Foundry Sandbox Uninstaller${NC}"
echo ""

# Check if installed
if [[ ! -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}Foundry Sandbox is not installed at $INSTALL_DIR${NC}"
    exit 0
fi

# Confirm
echo "This will:"
echo "  - Remove $INSTALL_DIR"
echo "  - Remove alias and completion from shell rc files"
echo "  - Optionally remove Docker image and sandbox data"
echo ""
echo -n "Continue? [y/N] "
read -r response
if [[ ! "$response" =~ ^[Yy] ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""

# Remove from shell rc files
remove_from_rc() {
    local rc_file="$1"
    if [[ -f "$rc_file" ]]; then
        # Remove lines containing foundry-sandbox or cast alias
        if grep -q "foundry-sandbox\|alias cast=" "$rc_file" 2>/dev/null; then
            # Create backup
            cp "$rc_file" "$rc_file.bak"
            # Remove the lines
            grep -v "foundry-sandbox\|alias cast=\|# Foundry Sandbox" "$rc_file.bak" > "$rc_file" || true
            echo -e "  ${GREEN}✓${NC} Cleaned $rc_file"
        fi
    fi
}

echo -e "${BLUE}Removing shell configuration...${NC}"
remove_from_rc "$HOME/.bashrc"
remove_from_rc "$HOME/.bash_profile"
remove_from_rc "$HOME/.zshrc"

echo ""

# Ask about Docker image
echo -n "Remove Docker image (foundry-sandbox:latest)? [y/N] "
read -r response
if [[ "$response" =~ ^[Yy] ]]; then
    if docker image rm foundry-sandbox:latest 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Removed Docker image"
    else
        echo -e "  ${YELLOW}!${NC} Docker image not found or could not be removed"
    fi
fi

echo ""

# Ask about sandbox data
SANDBOX_HOME="${SANDBOX_HOME:-$HOME/.sandboxes}"
if [[ -d "$SANDBOX_HOME" ]]; then
    echo -e "${YELLOW}Warning:${NC} Sandbox data exists at $SANDBOX_HOME"
    echo "This contains your git worktrees and may have uncommitted work."
    echo ""
    echo -n "Remove sandbox data? [y/N] "
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        rm -rf "$SANDBOX_HOME"
        echo -e "  ${GREEN}✓${NC} Removed sandbox data"
    else
        echo -e "  ${YELLOW}!${NC} Keeping sandbox data"
    fi
fi

echo ""

# Remove installation directory
echo -e "${BLUE}Removing installation...${NC}"
rm -rf "$INSTALL_DIR"
echo -e "  ${GREEN}✓${NC} Removed $INSTALL_DIR"

echo ""
echo -e "${GREEN}Uninstall complete.${NC}"
echo ""
echo "Reload your shell or run: source ~/.bashrc (or ~/.zshrc)"
echo ""
