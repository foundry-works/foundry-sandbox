#!/bin/bash

parse_new_args() {
    NEW_REPO_URL=""
    NEW_BRANCH=""
    NEW_FROM_BRANCH=""
    NEW_MOUNTS=()
    NEW_COPIES=()
    NEW_NETWORK_MODE="${SANDBOX_NETWORK_MODE:-limited}"
    NEW_SYNC_SSH="${SANDBOX_SYNC_SSH:-0}"
    NEW_SSH_MODE="${SANDBOX_SSH_MODE:-always}"
    NEW_SKIP_KEY_CHECK=false
    NEW_WORKING_DIR=""
    NEW_SPARSE_CHECKOUT=false
    NEW_PIP_REQUIREMENTS=""
    NEW_ISOLATE_CREDENTIALS=false

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
            --network=*|-n=*)
                NEW_NETWORK_MODE="${1#*=}"
                if [ -n "$NEW_NETWORK_MODE" ]; then
                    validate_network_mode "$NEW_NETWORK_MODE"
                fi
                ;;
            --with-ssh)
                NEW_SYNC_SSH="1"
                NEW_SSH_MODE="always"
                ;;
            --no-ssh|--without-ssh)
                die "Flag removed: SSH is disabled by default. Use --with-ssh to enable."
                ;;
            --with-ssh-always)
                die "Flag removed: use --with-ssh."
                ;;
            --with-api-keys|--no-api-keys)
                die "Flag removed: API keys are now passed via environment variables. See .env.example."
                ;;
            --skip-key-check)
                NEW_SKIP_KEY_CHECK=true
                ;;
            --wd)
                shift
                [ -n "$1" ] && NEW_WORKING_DIR="$1"
                ;;
            --wd=*)
                NEW_WORKING_DIR="${1#*=}"
                ;;
            --sparse)
                NEW_SPARSE_CHECKOUT=true
                ;;
            --isolate-credentials|--isolate)
                NEW_ISOLATE_CREDENTIALS=true
                ;;
            --pip-requirements|-r)
                shift
                if [ -n "$1" ] && [[ "$1" != -* ]]; then
                    NEW_PIP_REQUIREMENTS="$1"
                else
                    NEW_PIP_REQUIREMENTS="auto"
                    continue
                fi
                ;;
            --pip-requirements=*|-r=*)
                NEW_PIP_REQUIREMENTS="${1#*=}"
                [ -z "$NEW_PIP_REQUIREMENTS" ] && NEW_PIP_REQUIREMENTS="auto"
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

    if [ "$NEW_SYNC_SSH" = "1" ]; then
        validate_ssh_mode "$NEW_SSH_MODE"
    fi
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
