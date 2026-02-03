#!/bin/bash

cmd_upgrade() {
    local use_local=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local)
                use_local=true
                shift
                ;;
            --help|-h)
                echo "Usage: cast upgrade [--local]"
                echo ""
                echo "Upgrade Foundry Sandbox to the latest version."
                echo ""
                echo "Options:"
                echo "  --local    Upgrade from local repo (for development)"
                return 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Usage: cast upgrade [--local]"
                exit 1
                ;;
        esac
    done

    if [ "$use_local" = "true" ]; then
        # Use local install.sh for development/testing
        if [ -f "$SCRIPT_DIR/install.sh" ]; then
            echo "Running local installer..."
            bash "$SCRIPT_DIR/install.sh" --repo "$SCRIPT_DIR"
        else
            die "Local install.sh not found at $SCRIPT_DIR/install.sh"
        fi
    else
        # Fetch and run from GitHub
        echo "Fetching latest installer from GitHub..."
        curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
    fi
}
