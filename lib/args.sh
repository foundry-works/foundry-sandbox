#!/bin/bash

parse_new_args() {
    NEW_REPO_URL=""
    NEW_BRANCH=""
    NEW_FROM_BRANCH=""
    NEW_MOUNTS=()
    NEW_COPIES=()
    NEW_NETWORK_MODE="${SANDBOX_NETWORK_MODE:-limited}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --mount|-v)
                shift
                [ -n "$1" ] && NEW_MOUNTS+=("$1")
                ;;
            --copy|-c)
                shift
                [ -n "$1" ] && NEW_COPIES+=("$1")
                ;;
            --network|-n)
                shift
                if [ -n "$1" ]; then
                    NEW_NETWORK_MODE="$1"
                    validate_network_mode "$NEW_NETWORK_MODE"
                fi
                ;;
            *)
                if [ -z "$NEW_REPO_URL" ]; then
                    NEW_REPO_URL="$1"
                elif [ -z "$NEW_BRANCH" ]; then
                    NEW_BRANCH="$1"
                elif [ -z "$NEW_FROM_BRANCH" ]; then
                    NEW_FROM_BRANCH="$1"
                fi
                ;;
        esac
        shift
    done
}

parse_destroy_args() {
    DESTROY_NAME=""
    DESTROY_KEEP_WORKTREE=false
    DESTROY_FORCE=false
    DESTROY_ASSUME_YES="${SANDBOX_ASSUME_YES}"

    while [ $# -gt 0 ]; do
        case "$1" in
            --keep-worktree) DESTROY_KEEP_WORKTREE=true ;;
            -f|--force) DESTROY_FORCE=true ;;
            -y|--yes) DESTROY_ASSUME_YES="1" ;;
            *) [ -z "$DESTROY_NAME" ] && DESTROY_NAME="$1" ;;
        esac
        shift
    done
}

parse_build_args() {
    BUILD_NO_CACHE=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-cache) BUILD_NO_CACHE="--no-cache" ;;
        esac
        shift
    done
}
