#!/bin/bash

cmd_config() {
    local json_output=false
    if [ "$1" = "--json" ]; then
        json_output=true
    fi

    if [ "$json_output" = true ]; then
        local home
        home=$(json_escape "$SANDBOX_HOME")
        local repos
        repos=$(json_escape "$REPOS_DIR")
        local worktrees
        worktrees=$(json_escape "$WORKTREES_DIR")
        local configs
        configs=$(json_escape "$CLAUDE_CONFIGS_DIR")
        local script
        script=$(json_escape "$SCRIPT_DIR")
        local docker_image
        docker_image=$(json_escape "$DOCKER_IMAGE")
        local docker_uid
        docker_uid=$(json_escape "$DOCKER_UID")
        local docker_gid
        docker_gid=$(json_escape "$DOCKER_GID")
        local ssh_mode
        ssh_mode=$(json_escape "$SANDBOX_SSH_MODE")

        printf '{"sandbox_home":"%s","repos_dir":"%s","worktrees_dir":"%s",' "$home" "$repos" "$worktrees"
        printf '"claude_configs_dir":"%s","script_dir":"%s","docker_image":"%s",' "$configs" "$script" "$docker_image"
        printf '"docker_uid":"%s","docker_gid":"%s",' "$docker_uid" "$docker_gid"
        printf '"network_mode":"%s","sync_ssh":%s,"ssh_mode":"%s","sync_api_keys":%s,' "$SANDBOX_NETWORK_MODE" "$SANDBOX_SYNC_SSH" "$ssh_mode" "$SANDBOX_SYNC_API_KEYS"
        printf '"debug":%s,"verbose":%s,"assume_yes":%s}' "$SANDBOX_DEBUG" "$SANDBOX_VERBOSE" "$SANDBOX_ASSUME_YES"
        return
    fi

    format_header "Sandbox config"
    format_kv "SANDBOX_HOME" "$SANDBOX_HOME"
    format_kv "REPOS_DIR" "$REPOS_DIR"
    format_kv "WORKTREES_DIR" "$WORKTREES_DIR"
    format_kv "CLAUDE_CONFIGS_DIR" "$CLAUDE_CONFIGS_DIR"
    format_kv "SCRIPT_DIR" "$SCRIPT_DIR"
    format_kv "DOCKER_IMAGE" "$DOCKER_IMAGE"
    format_kv "DOCKER_UID" "$DOCKER_UID"
    format_kv "DOCKER_GID" "$DOCKER_GID"
    format_kv "SANDBOX_DEBUG" "$SANDBOX_DEBUG"
    format_kv "SANDBOX_VERBOSE" "$SANDBOX_VERBOSE"
    format_kv "SANDBOX_ASSUME_YES" "$SANDBOX_ASSUME_YES"
    format_kv "SANDBOX_NETWORK_MODE" "$SANDBOX_NETWORK_MODE"
    format_kv "SANDBOX_SYNC_SSH" "$SANDBOX_SYNC_SSH"
    format_kv "SANDBOX_SSH_MODE" "$SANDBOX_SSH_MODE"
    format_kv "SANDBOX_SYNC_API_KEYS" "$SANDBOX_SYNC_API_KEYS"

    format_section_break
    format_header "Checks"
    if command -v git >/dev/null 2>&1; then
        format_kv "git" "ok"
    else
        format_kv "git" "missing"
    fi
    if command -v docker >/dev/null 2>&1; then
        format_kv "docker" "ok"
    else
        format_kv "docker" "missing"
    fi
    if docker info >/dev/null 2>&1; then
        format_kv "docker daemon" "ok"
    else
        format_kv "docker daemon" "not running"
    fi
}
