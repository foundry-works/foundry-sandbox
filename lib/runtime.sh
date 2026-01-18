#!/bin/bash

run_cmd() {
    if [ "$SANDBOX_VERBOSE" = "1" ]; then
        echo "+ $*"
    fi
    "$@"
}

run_cmd_quiet() {
    if [ "$SANDBOX_VERBOSE" = "1" ]; then
        echo "+ $*"
    fi
    "$@" >/dev/null 2>&1
}
