#!/bin/bash
# Module: 13-package-install
# Description: Package installation (pip and npm) in credential isolation mode

run_tests() {
    header "30. PACKAGE INSTALLATION"

    echo ""
    echo "Testing pip and npm package installation..."
    echo "(Credential isolation mode should allow user-mode installs to ~/.local/)"

    # Test 1: PIP_USER=1 is set
    info "Testing PIP_USER environment variable..."
    if [[ "${PIP_USER:-}" = "1" ]]; then
        test_pass "PIP_USER=1 is set"
    else
        test_fail "PIP_USER is not set to 1 (got: '${PIP_USER:-}')"
    fi

    # Test 2: pip install --user succeeds
    info "Testing pip install --user (explicit)..."
    PIP_USER_OUTPUT=$(pip install --user six 2>&1)
    PIP_USER_EXIT=$?
    if [[ $PIP_USER_EXIT -eq 0 ]]; then
        test_pass "pip install --user six succeeded"
    else
        info "pip output: $(echo "$PIP_USER_OUTPUT" | tail -3)"
        test_fail "pip install --user six failed (exit: $PIP_USER_EXIT)"
    fi

    # Test 3: pip install (no --user) succeeds when PIP_USER=1 is set
    info "Testing pip install without --user (relies on PIP_USER=1)..."
    PIP_NOUSER_OUTPUT=$(pip install cowsay 2>&1)
    PIP_NOUSER_EXIT=$?
    if [[ $PIP_NOUSER_EXIT -eq 0 ]]; then
        test_pass "pip install cowsay succeeded (PIP_USER=1 effective)"
    else
        info "pip output: $(echo "$PIP_NOUSER_OUTPUT" | tail -3)"
        test_fail "pip install cowsay failed (exit: $PIP_NOUSER_EXIT)"
    fi

    # Test 4: Installed pip package is importable
    info "Testing installed pip package is importable..."
    IMPORT_OUTPUT=$(python3 -c "import six; print(six.__version__)" 2>&1)
    IMPORT_EXIT=$?
    if [[ $IMPORT_EXIT -eq 0 ]]; then
        test_pass "Installed package importable (six v${IMPORT_OUTPUT})"
    else
        info "Import output: $IMPORT_OUTPUT"
        test_fail "Cannot import installed package 'six'"
    fi

    # Test 5: ~/.local/bin is in PATH
    info "Testing ~/.local/bin is in PATH..."
    if echo "$PATH" | grep -q "$HOME/.local/bin"; then
        test_pass "~/.local/bin is in PATH"
    else
        info "PATH: $PATH"
        test_fail "~/.local/bin is not in PATH"
    fi

    # Test 6: npm install -g succeeds (installs to ~/.local/ via npm prefix)
    info "Testing npm install -g..."
    NPM_G_OUTPUT=$(npm install -g semver 2>&1)
    NPM_G_EXIT=$?
    if [[ $NPM_G_EXIT -eq 0 ]]; then
        test_pass "npm install -g semver succeeded"
    else
        info "npm output: $(echo "$NPM_G_OUTPUT" | tail -3)"
        test_fail "npm install -g semver failed (exit: $NPM_G_EXIT)"
    fi

    # Test 7: Globally installed npm binary is executable
    info "Testing globally installed npm binary is executable..."
    if command -v semver >/dev/null 2>&1; then
        test_pass "semver binary found in PATH"
    else
        # Check if it's in ~/.local/bin even if not in PATH for current shell
        if [[ -x "$HOME/.local/bin/semver" ]]; then
            test_pass "semver binary found at ~/.local/bin/semver"
        else
            test_fail "semver binary not found after npm install -g"
        fi
    fi

    # Test 8: npm install (local, in /tmp test dir) succeeds
    info "Testing npm install (local)..."
    NPM_TEST_DIR=$(mktemp -d)
    pushd "$NPM_TEST_DIR" > /dev/null 2>&1
    NPM_LOCAL_OUTPUT=$(npm init -y 2>&1 && npm install is-even 2>&1)
    NPM_LOCAL_EXIT=$?
    popd > /dev/null 2>&1
    if [[ $NPM_LOCAL_EXIT -eq 0 ]] && [[ -d "$NPM_TEST_DIR/node_modules/is-even" ]]; then
        test_pass "npm install (local) succeeded"
    else
        info "npm output: $(echo "$NPM_LOCAL_OUTPUT" | tail -3)"
        test_fail "npm install (local) failed (exit: $NPM_LOCAL_EXIT)"
    fi
    rm -rf "$NPM_TEST_DIR"

    # Test 9: sudo apt-get install is denied (regression test)
    info "Testing sudo apt-get install is denied..."
    APT_OUTPUT=$(sudo apt-get install -y sl 2>&1)
    APT_EXIT=$?
    if [[ $APT_EXIT -ne 0 ]]; then
        test_pass "sudo apt-get install denied (exit: $APT_EXIT)"
    else
        test_fail "sudo apt-get install succeeded (should be blocked by sudoers)"
    fi

    # Test 10: System pip install (to /usr/local/) fails (read-only root)
    info "Testing system pip install is denied (read-only root)..."
    SYSPIP_OUTPUT=$(PIP_USER=0 pip install --no-user --target=/usr/local/lib/python3/dist-packages six 2>&1)
    SYSPIP_EXIT=$?
    if [[ $SYSPIP_EXIT -ne 0 ]]; then
        test_pass "System pip install denied (read-only root FS)"
    else
        test_fail "System pip install succeeded (root FS should be read-only)"
    fi
}
