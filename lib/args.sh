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
    NEW_ISOLATE_CREDENTIALS=true
    NEW_ALLOW_DANGEROUS_MOUNT=false
    NEW_ALLOW_PR=false
    NEW_ENABLE_OPENCODE=false
    NEW_ENABLE_ZAI=false
    NEW_USE_LAST=false
    NEW_USE_PRESET=""
    NEW_SAVE_AS=""
    NEW_WITH_IDE=""
    NEW_IDE_ONLY=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --last)
                NEW_USE_LAST=true
                ;;
            --preset)
                shift
                [ -n "$1" ] && NEW_USE_PRESET="$1"
                ;;
            --preset=*)
                NEW_USE_PRESET="${1#*=}"
                ;;
            --save-as)
                shift
                [ -n "$1" ] && NEW_SAVE_AS="$1"
                ;;
            --save-as=*)
                NEW_SAVE_AS="${1#*=}"
                ;;
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
            --from-branch)
                shift
                [ -n "$1" ] && NEW_FROM_BRANCH="$1"
                ;;
            --from-branch=*)
                NEW_FROM_BRANCH="${1#*=}"
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
            --no-isolate-credentials|--no-isolate)
                NEW_ISOLATE_CREDENTIALS=false
                ;;
            --allow-dangerous-mount)
                NEW_ALLOW_DANGEROUS_MOUNT=true
                ;;
            --allow-pr|--with-pr)
                NEW_ALLOW_PR=true
                ;;
            --from)
                shift
                [ -n "$1" ] && NEW_FROM_BRANCH="$1"
                ;;
            --from=*)
                NEW_FROM_BRANCH="${1#*=}"
                ;;
            --with-opencode)
                NEW_ENABLE_OPENCODE=true
                ;;
            --with-zai)
                NEW_ENABLE_ZAI=true
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
            --with-ide)
                shift
                if [ -n "$1" ] && [[ "$1" != -* ]]; then
                    NEW_WITH_IDE="$1"
                else
                    NEW_WITH_IDE="auto"
                    continue
                fi
                ;;
            --with-ide=*)
                NEW_WITH_IDE="${1#*=}"
                [ -z "$NEW_WITH_IDE" ] && NEW_WITH_IDE="auto"
                ;;
            --ide-only)
                NEW_IDE_ONLY=true
                shift
                if [ -n "$1" ] && [[ "$1" != -* ]]; then
                    NEW_WITH_IDE="$1"
                else
                    NEW_WITH_IDE="auto"
                    continue
                fi
                ;;
            --ide-only=*)
                NEW_IDE_ONLY=true
                NEW_WITH_IDE="${1#*=}"
                [ -z "$NEW_WITH_IDE" ] && NEW_WITH_IDE="auto"
                ;;
            --no-ide)
                NEW_WITH_IDE="none"
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

parse_attach_args() {
    ATTACH_NAME=""
    ATTACH_USE_LAST=false
    ATTACH_WITH_IDE=""
    ATTACH_IDE_ONLY=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --last)
                ATTACH_USE_LAST=true
                ;;
            --with-ide)
                shift
                if [ -n "$1" ] && [[ "$1" != -* ]]; then
                    ATTACH_WITH_IDE="$1"
                else
                    ATTACH_WITH_IDE="auto"
                    continue
                fi
                ;;
            --with-ide=*)
                ATTACH_WITH_IDE="${1#*=}"
                [ -z "$ATTACH_WITH_IDE" ] && ATTACH_WITH_IDE="auto"
                ;;
            --ide-only)
                ATTACH_IDE_ONLY=true
                shift
                if [ -n "$1" ] && [[ "$1" != -* ]]; then
                    ATTACH_WITH_IDE="$1"
                else
                    ATTACH_WITH_IDE="auto"
                    continue
                fi
                ;;
            --ide-only=*)
                ATTACH_IDE_ONLY=true
                ATTACH_WITH_IDE="${1#*=}"
                [ -z "$ATTACH_WITH_IDE" ] && ATTACH_WITH_IDE="auto"
                ;;
            --no-ide)
                ATTACH_WITH_IDE="none"
                ;;
            *)
                [ -z "$ATTACH_NAME" ] && ATTACH_NAME="$1"
                ;;
        esac
        shift
    done
}
